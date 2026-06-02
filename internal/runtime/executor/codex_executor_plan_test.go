package executor

import (
	"encoding/base64"
	"testing"

	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestSyncCodexPlanTypeFromIDTokenUpdatesAttributesAndMetadata(t *testing.T) {
	auth := &cliproxyauth.Auth{
		Provider:   "codex",
		Attributes: map[string]string{"plan_type": "free"},
		Metadata:   map[string]any{},
	}
	idToken := codexTestJWT(`{"https://api.openai.com/auth":{"chatgpt_plan_type":"pro"}}`)

	syncCodexPlanTypeFromIDToken(auth, idToken)

	if got := auth.Attributes["plan_type"]; got != "pro" {
		t.Fatalf("attributes plan_type = %q, want pro", got)
	}
	if got, _ := auth.Metadata["plan_type"].(string); got != "pro" {
		t.Fatalf("metadata plan_type = %q, want pro", got)
	}
}

func TestSyncCodexPlanTypeFromIDTokenIgnoresMissingPlan(t *testing.T) {
	auth := &cliproxyauth.Auth{
		Provider:   "codex",
		Attributes: map[string]string{"plan_type": "free"},
	}
	idToken := codexTestJWT(`{"https://api.openai.com/auth":{}}`)

	syncCodexPlanTypeFromIDToken(auth, idToken)

	if got := auth.Attributes["plan_type"]; got != "free" {
		t.Fatalf("attributes plan_type = %q, want free", got)
	}
	if auth.Metadata != nil {
		if got, _ := auth.Metadata["plan_type"].(string); got != "" {
			t.Fatalf("metadata plan_type = %q, want empty", got)
		}
	}
}

func codexTestJWT(payload string) string {
	enc := base64.RawURLEncoding
	return enc.EncodeToString([]byte(`{"alg":"none"}`)) + "." + enc.EncodeToString([]byte(payload)) + ".sig"
}
