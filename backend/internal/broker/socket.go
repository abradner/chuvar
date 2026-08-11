package broker

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

// maxRequestLine bounds a single request line — generous for any real git
// commit object, but bounded so a confused or malicious same-uid caller
// can't hand the connection an unbounded stream and grow this process's
// memory without limit. Same posture as scope.MaxLength: a cheap ceiling
// against amplification, not a realistic operational limit.
const maxRequestLine = 16 << 20 // 16MiB

// connDeadline bounds how long one connection may take end to end — a
// same-uid caller that connects and then never writes (accidentally or
// otherwise) must not be able to hold a listener goroutine open forever.
const connDeadline = 10 * time.Second

// Handler answers one request. broker.go's Broker.Handle is the real
// implementation; tests substitute their own.
type Handler func(ctx context.Context, req Request) Result

// Listen creates (or replaces a stale) Unix socket at socketPath, with the
// directory+socket permission hygiene the #77 spike found to be the one
// thing socket-path permissions can actually guarantee: they gate
// *cross-user* access (a different OS user, or a misconfigured
// world-writable socket) and nothing finer — same-uid processes connect
// freely regardless of which one they are, which is exactly why the token
// check in Broker.Handle is the actual authorization primitive, not this.
//
// The directory is created 0700 (not just the socket file 0600) because a
// Unix socket's connect() also requires search (x) permission on every
// parent directory component — a 0700 directory is what makes "only this
// uid can even reach the socket path" true end to end, not just true of
// the leaf file's own mode bits.
func Listen(socketPath string) (*net.UnixListener, error) {
	dir := filepath.Dir(socketPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("broker: creating socket directory %s: %w", dir, err)
	}
	// MkdirAll doesn't change the mode of a directory that already existed
	// with looser permissions — chmod explicitly so a pre-existing,
	// wrongly-permissioned directory doesn't silently defeat the hygiene
	// this function exists to provide.
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("broker: chmod socket directory %s: %w", dir, err)
	}

	// A stale socket file from a previous, uncleanly-terminated run makes
	// bind() fail with "address already in use" even though nothing is
	// listening — remove it first. Only ever removes a socket, never a
	// regular file: if something else occupies this path, refusing is
	// safer than deleting a file this process doesn't understand.
	if info, err := os.Lstat(socketPath); err == nil {
		if info.Mode()&os.ModeSocket == 0 {
			return nil, fmt.Errorf("broker: %s exists and is not a socket; refusing to remove it", socketPath)
		}
		if err := os.Remove(socketPath); err != nil {
			return nil, fmt.Errorf("broker: removing stale socket %s: %w", socketPath, err)
		}
	}

	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: socketPath, Net: "unix"})
	if err != nil {
		return nil, fmt.Errorf("broker: listening on %s: %w", socketPath, err)
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		ln.Close() //nolint:errcheck // the chmod error is the one worth reporting
		return nil, fmt.Errorf("broker: chmod socket %s: %w", socketPath, err)
	}
	return ln, nil
}

// Serve accepts connections until ctx is cancelled, handling each with
// handle, and does not return until every already-accepted connection has
// finished being handled.
//
// That draining matters specifically because of what cmd/brokerd does
// immediately after Serve returns: destroy the signing key
// (keyring.SigningKey.Destroy, deferred in main). The #74 custody spike
// found that a lingering reference into a destroyed memguard buffer is not
// a catchable error — it is an unrecoverable SIGSEGV that kills the whole
// process. If Serve returned as soon as the listener closed, a signing
// goroutine still mid-Sign when a shutdown signal arrived could still be
// touching the key at the exact moment Destroy unmaps it. Waiting for the
// in-flight WaitGroup here is what makes "stop accepting, finish what's
// in flight, then it's safe to destroy the key" true, rather than merely
// intended.
func Serve(ctx context.Context, ln *net.UnixListener, handle Handler) {
	go func() {
		<-ctx.Done()
		ln.Close() //nolint:errcheck // Accept below observes this as its exit signal
	}()

	var wg sync.WaitGroup
	for {
		conn, err := ln.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				break // expected: Close() above unblocked Accept
			}
			slog.Error("broker: accept failed", "error", err)
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			handleConn(ctx, conn, handle)
		}()
	}
	wg.Wait()
}

// handleConn services exactly one request per accepted connection, then
// closes it. Not a persistent session: the #77 spike's socket-authorization
// recommendation is explicit that the token must be "presented on every
// socket connection (not cached broker-side as already authenticated
// once)... consumed on the same read that authorizes the same signing
// request it accompanies — eliminating any deliberate delay between 'check'
// and 'use.'" A one-request-per-connection protocol is what makes that
// true structurally, rather than a policy this handler has to remember to
// enforce on a connection that could otherwise carry many requests.
func handleConn(ctx context.Context, conn *net.UnixConn, handle Handler) {
	defer conn.Close()

	if !peerUIDMatches(conn) {
		// See Listen's doc comment: directory+socket permissions already
		// gate cross-user access at connect() time, so reaching this
		// branch at all means either a same-uid caller somehow spoofing
		// SO_PEERCRED (not possible via any socket API — see the #77
		// spike) or a misconfiguration of the socket's own permissions.
		// Either way: close without responding. A caller that isn't
		// entitled to talk to this socket at all doesn't get a typed
		// protocol error to learn from, it gets nothing.
		slog.Error("broker: rejected connection: SO_PEERCRED uid does not match this process's own uid")
		return
	}

	if err := conn.SetDeadline(time.Now().Add(connDeadline)); err != nil {
		slog.Warn("broker: setting connection deadline failed", "error", err)
	}

	// bufio.Scanner, not bufio.Reader.ReadString: ReadString has no bound on
	// how much it will buffer while searching for the delimiter — a caller
	// that sends gigabytes with no '\n' would be read into memory in full
	// before maxRequestLine was ever checked, which would defeat the whole
	// point of the limit (caught in review: an earlier version of this
	// function did exactly that). Scanner.Buffer caps the *scanning*
	// buffer itself, so it stops growing and reports ErrTooLong at the
	// limit rather than after it.
	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 0, 4096), maxRequestLine)
	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			if errors.Is(err, bufio.ErrTooLong) {
				writeResult(conn, Result{Code: ScopeDenied, Message: "request too large"})
				return
			}
			slog.Debug("broker: reading request line failed", "error", err)
		}
		return // EOF with nothing read, or a transient read error: no response either way
	}
	line := scanner.Bytes()

	var req Request
	if err := json.Unmarshal(line, &req); err != nil {
		writeResult(conn, Result{Code: ScopeDenied, Message: "malformed request: " + err.Error()})
		return
	}

	writeResult(conn, handle(ctx, req))
}

func writeResult(conn *net.UnixConn, res Result) {
	enc, err := json.Marshal(res)
	if err != nil {
		// Marshal failing on this package's own Result type would be a
		// programming error (an unmarshalable field type), not a runtime
		// condition a caller could hit — log loudly rather than silently
		// dropping the response.
		slog.Error("broker: marshaling response failed", "error", err)
		return
	}
	enc = append(enc, '\n')
	if _, err := conn.Write(enc); err != nil {
		slog.Debug("broker: writing response failed", "error", err)
	}
}

// peerUIDMatches reads SO_PEERCRED synchronously, at accept time, with no
// intervening I/O — the #77 spike's finding 2 is that SO_PEERCRED is
// latched at connect() and safe to trust at exactly this moment, and finding
// 6 is that ANY later re-check of a /proc/<pid>-derived fact is checking
// live, attacker-influenceable state instead. This function is called
// exactly once, immediately on accept, before this connection's request is
// even read — never cached, never re-checked later in the connection's
// lifetime.
//
// This is the cheap, kernel-enforced half of the spike's two-control
// recommendation (uid gate + per-grant token); Broker.Handle's token check
// against Cache.Lookup is the other, load-bearing half — see Listen's doc
// comment for why the uid check alone is "free defense-in-depth" against a
// different OS user, not the actual authorization boundary on a
// single-OS-user deployment.
func peerUIDMatches(conn *net.UnixConn) bool {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		slog.Error("broker: obtaining raw connection for SO_PEERCRED check failed", "error", err)
		return false
	}

	var ucred *unix.Ucred
	var sockErr error
	ctlErr := rawConn.Control(func(fd uintptr) {
		ucred, sockErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if ctlErr != nil {
		slog.Error("broker: SyscallConn.Control failed", "error", ctlErr)
		return false
	}
	if sockErr != nil {
		slog.Error("broker: SO_PEERCRED lookup failed", "error", sockErr)
		return false
	}

	return ucred.Uid == uint32(os.Getuid())
}
