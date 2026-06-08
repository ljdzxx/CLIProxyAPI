package management

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestApplyCodexAuthPresetSyncsMetadataAndRuntimeFields(t *testing.T) {
	h := NewHandlerWithoutConfigFilePath(&config.Config{}, nil)
	auth := &coreauth.Auth{
		ID:       "codex-test.json",
		Provider: "codex",
		Metadata: map[string]any{
			"email":      "user@example.com",
			"account_id": "acct_123",
		},
	}

	preset := map[string]json.RawMessage{
		"proxy_url":                 json.RawMessage(`"http://proxy.local:8080"`),
		"priority":                  json.RawMessage(`8`),
		"headers":                   json.RawMessage(`{"X-Test":"one","User-Agent":"codex-test"}`),
		"excluded_models":           json.RawMessage(`["gpt-5.4","GPT-5.4","o4-mini"]`),
		"rate_limit_max_requests":   json.RawMessage(`12`),
		"rate_limit_window_seconds": json.RawMessage(`60`),
	}

	if err := h.applyCodexAuthPreset(auth, preset); err != nil {
		t.Fatalf("applyCodexAuthPreset returned error: %v", err)
	}

	if auth.ProxyURL != "http://proxy.local:8080" {
		t.Fatalf("ProxyURL = %q, want http://proxy.local:8080", auth.ProxyURL)
	}
	if got, _ := auth.Metadata["proxy_url"].(string); got != "http://proxy.local:8080" {
		t.Fatalf("metadata.proxy_url = %q, want http://proxy.local:8080", got)
	}
	if got := auth.Attributes["priority"]; got != "8" {
		t.Fatalf("attributes.priority = %q, want 8", got)
	}
	if got := auth.Attributes["header:X-Test"]; got != "one" {
		t.Fatalf("attributes.header:X-Test = %q, want one", got)
	}
	if got := auth.Attributes["header:User-Agent"]; got != "codex-test" {
		t.Fatalf("attributes.header:User-Agent = %q, want codex-test", got)
	}
	if got := auth.Attributes["excluded_models"]; got != "gpt-5.4,o4-mini" {
		t.Fatalf("attributes.excluded_models = %q, want gpt-5.4,o4-mini", got)
	}
	if got := auth.Attributes["excluded_models_hash"]; got == "" {
		t.Fatalf("expected excluded_models_hash to be set")
	}
	if got, ok := authFileIntValue(auth.Metadata["rate_limit_max_requests"]); !ok || got != 12 {
		t.Fatalf("metadata.rate_limit_max_requests = %#v, want 12", auth.Metadata["rate_limit_max_requests"])
	}
	if got, ok := authFileIntValue(auth.Metadata["rate_limit_window_seconds"]); !ok || got != 60 {
		t.Fatalf("metadata.rate_limit_window_seconds = %#v, want 60", auth.Metadata["rate_limit_window_seconds"])
	}
}

func TestParseCodexAuthPresetNormalizesAliases(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h := NewHandlerWithoutConfigFilePath(&config.Config{}, nil)
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodPost, "/v0/management/codex-auth-url", strings.NewReader(`{
		"proxy-url": "direct",
		"excluded-models": ["gpt-5.4"],
		"request_limit_max_requests": 1,
		"request_limit_window_seconds": 30
	}`))
	ctx.Request.Header.Set("Content-Type", "application/json")

	preset, ok := h.parseCodexAuthPreset(ctx)
	if !ok {
		t.Fatalf("expected parse to succeed, response body: %s", rec.Body.String())
	}
	for _, key := range []string{"proxy_url", "excluded_models", "rate_limit_max_requests", "rate_limit_window_seconds"} {
		if _, exists := preset[key]; !exists {
			t.Fatalf("expected normalized key %q in preset %#v", key, preset)
		}
	}
}

func TestParseCodexAuthPresetRejectsInvalidFields(t *testing.T) {
	gin.SetMode(gin.TestMode)
	tests := []struct {
		name string
		body string
	}{
		{
			name: "unsupported field",
			body: `{"access_token":"secret"}`,
		},
		{
			name: "non string header value",
			body: `{"headers":{"X-Test":1}}`,
		},
		{
			name: "negative rate limit",
			body: `{"rate_limit_max_requests":-1}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := NewHandlerWithoutConfigFilePath(&config.Config{}, nil)
			rec := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(rec)
			ctx.Request = httptest.NewRequest(http.MethodPost, "/v0/management/codex-auth-url", strings.NewReader(tc.body))
			ctx.Request.Header.Set("Content-Type", "application/json")

			if _, ok := h.parseCodexAuthPreset(ctx); ok {
				t.Fatalf("expected parse to fail")
			}
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("status = %d, want %d with body %s", rec.Code, http.StatusBadRequest, rec.Body.String())
			}
		})
	}
}
