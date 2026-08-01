package main

import (
	"context"
	"testing"

	"github.com/abradner/chuvar/backend/internal/sseclient"
)

// These exercise handlePromptKey's digit/backspace/cancel paths only — Enter
// (which fires the actual approve HTTP call via runAction) needs a real
// server and isn't covered here; see internal/api's requireTOTP tests for
// coverage of the server-side gate this prompt exists to satisfy.

func TestHandlePromptKey_DigitsAccumulate(t *testing.T) {
	m := &model{prompt: &promptState{it: item{kind: kindRequest, req: &sseclient.GrantRequest{ID: "r1"}}}}
	events := make(chan appEvent, 1)

	handlePromptKey(context.Background(), &sseclient.Client{}, m, key{r: '1'}, events)
	handlePromptKey(context.Background(), &sseclient.Client{}, m, key{r: '2'}, events)
	handlePromptKey(context.Background(), &sseclient.Client{}, m, key{r: '3'}, events)

	if m.prompt == nil || m.prompt.code != "123" {
		t.Fatalf("prompt.code = %+v, want \"123\"", m.prompt)
	}
}

func TestHandlePromptKey_StopsAtSixDigits(t *testing.T) {
	m := &model{prompt: &promptState{it: item{kind: kindRequest, req: &sseclient.GrantRequest{ID: "r1"}}, code: "123456"}}
	events := make(chan appEvent, 1)

	handlePromptKey(context.Background(), &sseclient.Client{}, m, key{r: '7'}, events)

	if m.prompt.code != "123456" {
		t.Errorf("prompt.code = %q, want unchanged \"123456\" (a 7th digit must not be accepted)", m.prompt.code)
	}
}

func TestHandlePromptKey_BackspaceRemovesLastDigit(t *testing.T) {
	m := &model{prompt: &promptState{it: item{kind: kindRequest, req: &sseclient.GrantRequest{ID: "r1"}}, code: "12"}}
	events := make(chan appEvent, 1)

	handlePromptKey(context.Background(), &sseclient.Client{}, m, key{special: keyBackspace}, events)

	if m.prompt.code != "1" {
		t.Errorf("prompt.code = %q, want \"1\"", m.prompt.code)
	}
}

func TestHandlePromptKey_BackspaceOnEmptyCodeIsNoop(t *testing.T) {
	m := &model{prompt: &promptState{it: item{kind: kindRequest, req: &sseclient.GrantRequest{ID: "r1"}}}}
	events := make(chan appEvent, 1)

	handlePromptKey(context.Background(), &sseclient.Client{}, m, key{special: keyBackspace}, events)

	if m.prompt == nil || m.prompt.code != "" {
		t.Fatalf("prompt = %+v, want an unchanged, still-open prompt with an empty code", m.prompt)
	}
}

func TestHandlePromptKey_NonDigitCancelsPrompt(t *testing.T) {
	m := &model{prompt: &promptState{it: item{kind: kindRequest, req: &sseclient.GrantRequest{ID: "r1"}}, code: "12"}}
	events := make(chan appEvent, 1)

	quit := handlePromptKey(context.Background(), &sseclient.Client{}, m, key{r: 'q'}, events)

	if quit {
		t.Error("handlePromptKey() with a cancelling key = quit true, want false (cancel the prompt, not the program)")
	}
	if m.prompt != nil {
		t.Error("prompt still open after a non-digit, non-control key — want it cancelled")
	}
}

func TestHandlePromptKey_CtrlCQuitsEvenMidPrompt(t *testing.T) {
	m := &model{prompt: &promptState{it: item{kind: kindRequest, req: &sseclient.GrantRequest{ID: "r1"}}, code: "12"}}
	events := make(chan appEvent, 1)

	quit := handlePromptKey(context.Background(), &sseclient.Client{}, m, key{special: keyCtrlC}, events)

	if !quit {
		t.Error("handlePromptKey() with Ctrl-C mid-prompt = quit false, want true")
	}
}

func TestModel_RemoveClearsPromptForResolvedItem(t *testing.T) {
	m := newModel()
	m.upsert(item{kind: kindRequest, req: &sseclient.GrantRequest{ID: "r1"}})
	m.prompt = &promptState{it: item{kind: kindRequest, req: &sseclient.GrantRequest{ID: "r1"}}, code: "12"}

	m.remove("r1")

	if m.prompt != nil {
		t.Error("prompt for r1 still set after r1 was removed (resolved elsewhere) — want it cleared")
	}
}
