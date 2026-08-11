package broker

import (
	"bytes"
	"context"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"testing"
	"time"
)

func TestListen_DirectoryAndSocketPermissions(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "nested", "brokerd.sock")

	ln, err := Listen(socketPath)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	sockInfo, err := os.Stat(socketPath)
	if err != nil {
		t.Fatalf("stat socket: %v", err)
	}
	if perm := sockInfo.Mode().Perm(); perm != 0o600 {
		t.Errorf("socket mode = %04o, want 0600", perm)
	}

	dirInfo, err := os.Stat(filepath.Dir(socketPath))
	if err != nil {
		t.Fatalf("stat socket directory: %v", err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0o700 {
		t.Errorf("socket directory mode = %04o, want 0700", perm)
	}
}

func TestListen_StaleSocketIsReplaced(t *testing.T) {
	dir := t.TempDir()
	socketPath := filepath.Join(dir, "brokerd.sock")

	ln1, err := Listen(socketPath)
	if err != nil {
		t.Fatalf("first Listen: %v", err)
	}
	ln1.Close() // simulates an unclean shutdown: the socket file is left behind

	ln2, err := Listen(socketPath)
	if err != nil {
		t.Fatalf("second Listen (should replace the stale socket file): %v", err)
	}
	defer ln2.Close()
}

func TestListen_RefusesNonSocketAtPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "not-a-socket")
	if err := os.WriteFile(path, []byte("regular file"), 0o600); err != nil {
		t.Fatalf("writing fixture file: %v", err)
	}

	if _, err := Listen(path); err == nil {
		t.Fatal("Listen() over an existing regular file: want error, got nil")
	}
	// The file must survive — Listen must never delete something it didn't
	// create and doesn't understand.
	if _, err := os.Stat(path); err != nil {
		t.Errorf("regular file was removed by a failed Listen(): %v", err)
	}
}

// TestServe_MalformedJSONRejected exercises handleConn's json.Unmarshal
// error branch directly over a real socket, independent of any Broker —
// confirming the socket layer itself refuses garbage input with a typed
// response rather than hanging or crashing the connection goroutine.
func TestServe_MalformedJSONRejected(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "brokerd.sock")
	ln, err := Listen(socketPath)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	handlerCalled := false
	go Serve(ctx, ln, func(ctx context.Context, req Request) Result {
		handlerCalled = true
		return Result{Code: OK}
	})

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("{not valid json\n")); err != nil {
		t.Fatalf("write: %v", err)
	}

	var res Result
	if err := json.NewDecoder(conn).Decode(&res); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if res.Code != ScopeDenied {
		t.Fatalf("response to malformed JSON = %+v, want SCOPE_DENIED", res)
	}
	if handlerCalled {
		t.Error("Handler was invoked for a request that never parsed")
	}
}

// TestServe_OversizedRequestRejected exercises maxRequestLine's boundary —
// a same-uid caller (confused or otherwise) handing the connection an
// unbounded stream must not be able to grow this process's memory without
// limit.
func TestServe_OversizedRequestRejected(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "brokerd.sock")
	ln, err := Listen(socketPath)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Serve(ctx, ln, func(ctx context.Context, req Request) Result {
		return Result{Code: OK}
	})

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	// One line, no newline, larger than maxRequestLine — bufio.Reader's
	// ReadString keeps buffering until it sees '\n' or the peer closes, so
	// this writes past the limit and then closes to force ReadString to
	// return what it has.
	oversized := make([]byte, maxRequestLine+1024)
	for i := range oversized {
		oversized[i] = 'a'
	}
	if _, err := conn.Write(oversized); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn.(*net.UnixConn).CloseWrite() //nolint:errcheck

	var res Result
	if err := json.NewDecoder(conn).Decode(&res); err != nil {
		t.Fatalf("decoding response: %v", err)
	}
	if res.Code != ScopeDenied || res.Message != "request too large" {
		t.Fatalf("response to an oversized request = %+v, want SCOPE_DENIED \"request too large\"", res)
	}
}

// TestServe_WaitsForInFlightHandlersBeforeReturning is the regression test
// for Serve's doc comment: cmd/brokerd destroys the signing key immediately
// after Serve returns, so Serve returning early — while a handler goroutine
// might still be mid-Sign — would be a real, if narrow, use-after-destroy
// race against guarded memory (see keyring's package doc on why that's an
// unrecoverable SIGSEGV, not a catchable error). This confirms the drain
// actually happens rather than merely being documented.
func TestServe_WaitsForInFlightHandlersBeforeReturning(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "brokerd.sock")
	ln, err := Listen(socketPath)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}

	release := make(chan struct{})
	handlerEntered := make(chan struct{})
	handler := func(ctx context.Context, req Request) Result {
		close(handlerEntered)
		<-release // held open until the test says otherwise
		return Result{Code: OK}
	}

	ctx, cancel := context.WithCancel(context.Background())
	serveReturned := make(chan struct{})
	go func() {
		Serve(ctx, ln, handler)
		close(serveReturned)
	}()

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	req, _ := json.Marshal(Request{Op: "preflight", Token: "x", Scope: "git.sign"})
	if _, err := conn.Write(append(req, '\n')); err != nil {
		t.Fatalf("write: %v", err)
	}

	select {
	case <-handlerEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("handler was never invoked")
	}

	cancel() // request shutdown while the handler is still blocked

	select {
	case <-serveReturned:
		t.Fatal("Serve returned while a handler was still in flight — the drain did not happen")
	case <-time.After(200 * time.Millisecond):
		// Expected: still waiting on the in-flight handler.
	}

	close(release) // let the handler finish

	select {
	case <-serveReturned:
		// Expected: Serve returns promptly once the handler completes.
	case <-time.After(2 * time.Second):
		t.Fatal("Serve did not return after the in-flight handler completed")
	}
}

// TestHandleConn_HandlerContextHasConnectionDeadline is the regression test
// for round-2 review's finding: conn.SetDeadline only bounds the socket
// I/O, not the ctx handed to the Handler (and, in the real broker, threaded
// into pool.Exec for the audit-log write). A stalled DB could previously
// hold a handler goroutine open indefinitely, well past the advertised 10s
// connDeadline. This asserts the derived-context wiring directly — that the
// context handleConn passes to Handler carries a deadline, and that the
// deadline is connDeadline out from this connection's own accept time —
// rather than sleeping past the full window, which would make the test
// slow and only prove the same thing indirectly.
func TestHandleConn_HandlerContextHasConnectionDeadline(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "brokerd.sock")
	ln, err := Listen(socketPath)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}

	var gotDeadline time.Time
	var hasDeadline bool
	handlerCalled := make(chan struct{})
	handler := func(ctx context.Context, req Request) Result {
		gotDeadline, hasDeadline = ctx.Deadline()
		close(handlerCalled)
		return Result{Code: OK}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Serve(ctx, ln, handler)

	before := time.Now()
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	req, _ := json.Marshal(Request{Op: "preflight", Token: "x", Scope: "git.sign"})
	if _, err := conn.Write(append(req, '\n')); err != nil {
		t.Fatalf("write: %v", err)
	}

	select {
	case <-handlerCalled:
	case <-time.After(2 * time.Second):
		t.Fatal("handler was never invoked")
	}
	after := time.Now()

	if !hasDeadline {
		t.Fatal("handler's context has no deadline — the daemon-lifetime ctx was passed through " +
			"unmodified, so a stalled audit write (e.g. an unreachable DB) can hold this goroutine " +
			"open indefinitely")
	}
	// The deadline must fall within [before+connDeadline, after+connDeadline]:
	// derived from *this connection's* own accept time via connDeadline —
	// the same window conn.SetDeadline itself uses — not some unrelated or
	// daemon-lifetime window.
	if gotDeadline.Before(before.Add(connDeadline)) || gotDeadline.After(after.Add(connDeadline)) {
		t.Errorf("handler context deadline = %v, want within [%v, %v]",
			gotDeadline, before.Add(connDeadline), after.Add(connDeadline))
	}
}

// TestPeerUIDMatches_SameUserAccepted is the positive case for the #77
// spike's uid gate: a same-uid connection (every test in this package, and
// every real chuvar deployment per the spike's host facts) is accepted.
func TestPeerUIDMatches_SameUserAccepted(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "brokerd.sock")
	ln, err := Listen(socketPath)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	var got *net.UnixConn
	accepted := make(chan struct{})
	go func() {
		c, err := ln.AcceptUnix()
		if err == nil {
			got = c
		}
		close(accepted)
	}()

	client, err := net.Dial("unix", socketPath)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer client.Close()
	<-accepted
	if got == nil {
		t.Fatal("accept failed")
	}
	defer got.Close()

	if !peerUIDMatches(got) {
		t.Error("peerUIDMatches() = false for a same-process (same-uid) connection, want true")
	}
}

// TestHandleConn_CrossUserConnectionNeverReachesSocketPath is the #77
// spike's finding 4, reproduced live: with the socket at its real default
// permissions (0600 inside a 0700 directory), a connection attempt from a
// genuinely different OS user fails at connect() itself — it never reaches
// accept()/SO_PEERCRED at all. Uses `sudo -n -u nobody` the same way the
// spike did. Skipped if this environment can't support that (no
// passwordless sudo, no `nobody` user, no `nc`).
func TestHandleConn_CrossUserConnectionNeverReachesSocketPath(t *testing.T) {
	requireCrossUserTestSupport(t)

	socketPath := filepath.Join(t.TempDir(), "brokerd.sock")
	ln, err := Listen(socketPath)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	accepted := make(chan bool, 1)
	go func() {
		ln.SetDeadline(time.Now().Add(3 * time.Second)) //nolint:errcheck
		_, err := ln.AcceptUnix()
		accepted <- (err == nil)
	}()

	// -w1: give nc a bounded timeout so a hang here can't wedge the test
	// suite if the permission model somehow doesn't block this.
	cmd := exec.Command("sudo", "-n", "-u", "nobody", "nc", "-U", "-w", "1", socketPath)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("connecting as a different OS user succeeded (should have failed at connect()); output: %s", out)
	}

	select {
	case wasAccepted := <-accepted:
		if wasAccepted {
			t.Fatal("AcceptUnix() returned a connection from a different OS user — directory/socket permissions did not block it")
		}
	case <-time.After(4 * time.Second):
		// Accept never fired at all — exactly the expected outcome
		// (nothing to accept, because connect() itself was refused).
	}
}

// TestHandleConn_SOPeercredRejectsDifferentUID isolates the *second*,
// kernel-enforced control from the first: with socket-path permission
// hygiene deliberately disabled (mode 0777, standing in for a
// misconfigured deployment or a future socket location this test doesn't
// control), a cross-user connection reaches accept() — and
// peerUIDMatches/handleConn must still refuse it via SO_PEERCRED, getting
// no response at all rather than a typed protocol error. This is what
// proves the uid gate is a real, independent control and not merely
// redundant with the directory permissions the other test already covers.
func TestHandleConn_SOPeercredRejectsDifferentUID(t *testing.T) {
	requireCrossUserTestSupport(t)

	// Deliberately not t.TempDir(): that nests a per-test directory inside a
	// per-package temp root, and chmod-ing only the socket's immediate
	// parent (below) would leave that outer root's default (restrictive)
	// permissions still blocking `nobody` from traversing to it — which
	// would make this test fail for the wrong reason (still blocked by
	// path permissions, the *other* control) rather than actually reaching
	// SO_PEERCRED. A single directory created directly under /tmp (already
	// world-traversable) means chmod-ing this one directory is enough.
	dir, err := os.MkdirTemp("", "chuvar-broker-socket-test-")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socketPath := filepath.Join(dir, "brokerd.sock")
	ln, err := Listen(socketPath)
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer ln.Close()

	// Deliberately loosen permissions for this one test — see doc comment.
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatalf("chmod dir: %v", err)
	}
	if err := os.Chmod(socketPath, 0o777); err != nil {
		t.Fatalf("chmod socket: %v", err)
	}

	handlerCalled := make(chan struct{}, 1)
	handler := func(ctx context.Context, req Request) Result {
		handlerCalled <- struct{}{}
		return Result{Code: OK}
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go Serve(ctx, ln, handler)

	req, _ := json.Marshal(Request{Op: "preflight", Token: "x", Scope: "git.sign"})
	cmd := exec.Command("sudo", "-n", "-u", "nobody", "nc", "-U", "-w", "2", socketPath)
	cmd.Stdin = bytes.NewReader(append(req, '\n'))
	out, _ := cmd.CombinedOutput() // connect succeeds now (permissions loosened); response is what we're checking

	if len(out) != 0 {
		t.Fatalf("received a response over a cross-uid connection that SO_PEERCRED should have silently rejected: %q", out)
	}
	select {
	case <-handlerCalled:
		t.Fatal("Handle was invoked for a connection SO_PEERCRED should have rejected before ever reading a request")
	case <-time.After(500 * time.Millisecond):
		// Expected: rejected before the handler ever ran.
	}
}

// requireCrossUserTestSupport skips a test when this environment can't
// actually exercise a different-OS-user connection: no passwordless sudo,
// no `nobody` user, or no `nc` binary. These tests are deliberately real
// (spawn a real different-uid process), not simulated, matching how the
// #77 spike itself verified these properties — see that spike's own "Setup
// / read-only compliance" section.
func requireCrossUserTestSupport(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("nc"); err != nil {
		t.Skip("nc not found on PATH")
	}
	if _, err := exec.LookPath("sudo"); err != nil {
		t.Skip("sudo not found on PATH")
	}
	if _, err := user.Lookup("nobody"); err != nil {
		t.Skip("no \"nobody\" user on this host")
	}
	if err := exec.Command("sudo", "-n", "true").Run(); err != nil {
		t.Skip("passwordless sudo is not available in this environment")
	}
}
