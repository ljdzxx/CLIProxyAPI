package auth

import (
	"context"
	"net/http"
	"sync/atomic"
	"testing"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

type rateLimitTestExecutor struct {
	calls atomic.Int32
}

func (e *rateLimitTestExecutor) Identifier() string { return "test-rate" }

func (e *rateLimitTestExecutor) Execute(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	e.calls.Add(1)
	return cliproxyexecutor.Response{}, nil
}

func (e *rateLimitTestExecutor) ExecuteStream(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	e.calls.Add(1)
	return &cliproxyexecutor.StreamResult{}, nil
}

func (e *rateLimitTestExecutor) Refresh(ctx context.Context, auth *Auth) (*Auth, error) {
	return auth, nil
}

func (e *rateLimitTestExecutor) CountTokens(ctx context.Context, auth *Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	e.calls.Add(1)
	return cliproxyexecutor.Response{}, nil
}

func (e *rateLimitTestExecutor) HttpRequest(ctx context.Context, auth *Auth, req *http.Request) (*http.Response, error) {
	e.calls.Add(1)
	return nil, nil
}

func TestManagerExecuteAuthRateLimitPreReservesBeforeUpstream(t *testing.T) {
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	executor := &rateLimitTestExecutor{}
	manager.RegisterExecutor(executor)
	if _, err := manager.Register(context.Background(), &Auth{
		ID:       "limited",
		Provider: "test-rate",
		Metadata: map[string]any{
			"rate_limit_max_requests":   1,
			"rate_limit_window_seconds": 3600,
		},
	}); err != nil {
		t.Fatalf("register auth: %v", err)
	}

	if _, err := manager.Execute(context.Background(), []string{"test-rate"}, cliproxyexecutor.Request{}, cliproxyexecutor.Options{}); err != nil {
		t.Fatalf("first execute failed: %v", err)
	}
	if _, err := manager.Execute(context.Background(), []string{"test-rate"}, cliproxyexecutor.Request{}, cliproxyexecutor.Options{}); err == nil {
		t.Fatalf("second execute succeeded, want local rate limit error")
	} else if statusErr, ok := err.(interface{ StatusCode() int }); !ok || statusErr.StatusCode() != http.StatusTooManyRequests {
		t.Fatalf("second execute err = %T %v, want 429 status error", err, err)
	}

	if got := executor.calls.Load(); got != 1 {
		t.Fatalf("executor calls = %d, want 1", got)
	}
}

func TestManagerExecuteAuthRateLimitFallsThroughToOtherAuth(t *testing.T) {
	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	executor := &rateLimitTestExecutor{}
	manager.RegisterExecutor(executor)
	for _, auth := range []*Auth{
		{
			ID:       "limited",
			Provider: "test-rate",
			Metadata: map[string]any{
				"rate_limit_max_requests":   1,
				"rate_limit_window_seconds": 3600,
			},
		},
		{ID: "unlimited", Provider: "test-rate"},
	} {
		if _, err := manager.Register(context.Background(), auth); err != nil {
			t.Fatalf("register auth %s: %v", auth.ID, err)
		}
	}

	for i := 0; i < 2; i++ {
		if _, err := manager.Execute(context.Background(), []string{"test-rate"}, cliproxyexecutor.Request{}, cliproxyexecutor.Options{}); err != nil {
			t.Fatalf("execute %d failed: %v", i+1, err)
		}
	}

	if got := executor.calls.Load(); got != 2 {
		t.Fatalf("executor calls = %d, want 2", got)
	}
}
