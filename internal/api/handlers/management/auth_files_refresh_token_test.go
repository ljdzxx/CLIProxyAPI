package management

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v6/sdk/cliproxy/executor"
)

type refreshTokenTestExecutor struct {
	mu        sync.Mutex
	refreshed []string
}

func (e *refreshTokenTestExecutor) Identifier() string { return "codex" }

func (e *refreshTokenTestExecutor) Execute(context.Context, *coreauth.Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}

func (e *refreshTokenTestExecutor) ExecuteStream(context.Context, *coreauth.Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	return nil, nil
}

func (e *refreshTokenTestExecutor) Refresh(_ context.Context, auth *coreauth.Auth) (*coreauth.Auth, error) {
	e.mu.Lock()
	e.refreshed = append(e.refreshed, auth.ID)
	e.mu.Unlock()

	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}
	auth.Metadata["access_token"] = "new-" + auth.ID
	auth.Metadata["last_refresh"] = time.Now().UTC().Format(time.RFC3339)
	return auth, nil
}

func (e *refreshTokenTestExecutor) CountTokens(context.Context, *coreauth.Auth, cliproxyexecutor.Request, cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}

func (e *refreshTokenTestExecutor) HttpRequest(context.Context, *coreauth.Auth, *http.Request) (*http.Response, error) {
	return nil, nil
}

func (e *refreshTokenTestExecutor) count() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.refreshed)
}

func TestRunRefreshAllAuthFileTokensSkipsLockedCodexAuth(t *testing.T) {
	manager := coreauth.NewManager(nil, nil, nil)
	exec := &refreshTokenTestExecutor{}
	manager.RegisterExecutor(exec)

	locked := &coreauth.Auth{
		ID:       "locked",
		Provider: "codex",
		FileName: "locked.json",
		Metadata: map[string]any{
			"refresh_token":        "locked-refresh",
			"refresh_token_locked": true,
		},
	}
	unlocked := &coreauth.Auth{
		ID:       "unlocked",
		Provider: "codex",
		FileName: "unlocked.json",
		Metadata: map[string]any{
			"refresh_token": "unlocked-refresh",
		},
	}

	if _, err := manager.Register(context.Background(), locked); err != nil {
		t.Fatalf("register locked auth: %v", err)
	}
	if _, err := manager.Register(context.Background(), unlocked); err != nil {
		t.Fatalf("register unlocked auth: %v", err)
	}

	h := &Handler{
		authManager: manager,
		refreshJobs: make(map[string]*authRefreshJob),
	}
	job := &authRefreshJob{
		ID:        "job-1",
		Status:    "running",
		StartedAt: time.Now(),
	}
	if !h.beginRefreshAllJob(job) {
		t.Fatal("begin refresh job failed")
	}

	h.runRefreshAllAuthFileTokens(context.Background(), job.ID, manager.List())

	snapshot := h.authRefreshJobSnapshot(job.ID)
	if snapshot == nil {
		t.Fatal("missing job snapshot")
	}
	if snapshot.Total != 2 || snapshot.Refreshed != 1 || snapshot.Skipped != 1 || snapshot.Failed != 0 {
		t.Fatalf("unexpected job counts: total=%d refreshed=%d skipped=%d failed=%d", snapshot.Total, snapshot.Refreshed, snapshot.Skipped, snapshot.Failed)
	}
	if got := exec.count(); got != 1 {
		t.Fatalf("refresh calls = %d, want 1", got)
	}
}
