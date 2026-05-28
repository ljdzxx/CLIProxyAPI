package auth

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	authRateLimitMaxRequestsKey     = "rate_limit_max_requests"
	authRateLimitWindowSecondsKey   = "rate_limit_window_seconds"
	authRateLimitMaxRequestsAlias   = "request_limit_max_requests"
	authRateLimitWindowSecondsAlias = "request_limit_window_seconds"
)

type authRateLimitConfig struct {
	maxRequests int
	window      time.Duration
}

type authRateLimitWindow struct {
	start       time.Time
	resetAt     time.Time
	used        int
	maxRequests int
	window      time.Duration
}

type authRateLimitError struct {
	model   string
	resetAt time.Time
}

func authRateLimitConfigForAuth(auth *Auth) (authRateLimitConfig, bool) {
	if auth == nil {
		return authRateLimitConfig{}, false
	}
	maxRequests, okMax := authRateLimitInt(auth, authRateLimitMaxRequestsKey, authRateLimitMaxRequestsAlias)
	windowSeconds, okWindow := authRateLimitInt(auth, authRateLimitWindowSecondsKey, authRateLimitWindowSecondsAlias)
	if !okMax || !okWindow || maxRequests <= 0 || windowSeconds <= 0 {
		return authRateLimitConfig{}, false
	}
	return authRateLimitConfig{
		maxRequests: maxRequests,
		window:      time.Duration(windowSeconds) * time.Second,
	}, true
}

func authRateLimitInt(auth *Auth, keys ...string) (int, bool) {
	for _, key := range keys {
		if auth.Metadata != nil {
			if value, ok := parseAuthRateLimitInt(auth.Metadata[key]); ok {
				return value, true
			}
		}
		if auth.Attributes != nil {
			if value, ok := parseAuthRateLimitInt(auth.Attributes[key]); ok {
				return value, true
			}
		}
	}
	return 0, false
}

func parseAuthRateLimitInt(value any) (int, bool) {
	switch typed := value.(type) {
	case int:
		return typed, true
	case int64:
		return int(typed), true
	case float64:
		return int(typed), true
	case json.Number:
		if i, err := typed.Int64(); err == nil {
			return int(i), true
		}
	case string:
		if i, err := strconv.Atoi(strings.TrimSpace(typed)); err == nil {
			return i, true
		}
	}
	return 0, false
}

func (m *Manager) authRateLimitAvailable(auth *Auth, now time.Time) (bool, time.Time) {
	if m == nil || auth == nil {
		return true, time.Time{}
	}
	cfg, enabled := authRateLimitConfigForAuth(auth)
	if !enabled {
		return true, time.Time{}
	}
	if now.IsZero() {
		now = time.Now()
	}
	m.rateLimitMu.Lock()
	defer m.rateLimitMu.Unlock()
	state := m.rateLimits[auth.ID]
	if state.resetAt.IsZero() || !state.resetAt.After(now) || state.maxRequests != cfg.maxRequests || state.window != cfg.window {
		return true, time.Time{}
	}
	if state.used < cfg.maxRequests {
		return true, time.Time{}
	}
	return false, state.resetAt
}

func (m *Manager) reserveAuthRateLimit(auth *Auth, now time.Time) (bool, time.Time) {
	if m == nil || auth == nil {
		return true, time.Time{}
	}
	cfg, enabled := authRateLimitConfigForAuth(auth)
	if !enabled {
		return true, time.Time{}
	}
	if now.IsZero() {
		now = time.Now()
	}
	m.rateLimitMu.Lock()
	defer m.rateLimitMu.Unlock()
	if m.rateLimits == nil {
		m.rateLimits = make(map[string]authRateLimitWindow)
	}
	state := m.rateLimits[auth.ID]
	if state.resetAt.IsZero() || !state.resetAt.After(now) || state.maxRequests != cfg.maxRequests || state.window != cfg.window {
		m.rateLimits[auth.ID] = authRateLimitWindow{
			start:       now,
			resetAt:     now.Add(cfg.window),
			used:        1,
			maxRequests: cfg.maxRequests,
			window:      cfg.window,
		}
		return true, time.Time{}
	}
	if state.used >= cfg.maxRequests {
		return false, state.resetAt
	}
	state.used++
	m.rateLimits[auth.ID] = state
	return true, time.Time{}
}

func earlierRateLimitReset(current, candidate time.Time) time.Time {
	if candidate.IsZero() {
		return current
	}
	if current.IsZero() || candidate.Before(current) {
		return candidate
	}
	return current
}

func (m *Manager) reserveAuthForSelection(auth *Auth, tried map[string]struct{}, earliestReset *time.Time) bool {
	ok, resetAt := m.reserveAuthRateLimit(auth, time.Now())
	if ok {
		return true
	}
	if auth != nil && tried != nil {
		tried[auth.ID] = struct{}{}
	}
	if earliestReset != nil {
		*earliestReset = earlierRateLimitReset(*earliestReset, resetAt)
	}
	return false
}

func newAuthRateLimitError(model string, resetAt time.Time) *authRateLimitError {
	return &authRateLimitError{model: model, resetAt: resetAt}
}

func (e *authRateLimitError) resetIn() time.Duration {
	if e == nil || e.resetAt.IsZero() {
		return 0
	}
	resetIn := time.Until(e.resetAt)
	if resetIn < 0 {
		return 0
	}
	return resetIn
}

func (e *authRateLimitError) Error() string {
	modelName := e.model
	if modelName == "" {
		modelName = "requested model"
	}
	resetIn := e.resetIn()
	resetSeconds := int(math.Ceil(resetIn.Seconds()))
	if resetSeconds < 0 {
		resetSeconds = 0
	}
	displayDuration := resetIn
	if displayDuration > 0 && displayDuration < time.Second {
		displayDuration = time.Second
	} else {
		displayDuration = displayDuration.Round(time.Second)
	}
	message := fmt.Sprintf("All credentials for model %s reached local request limits", modelName)
	payload := map[string]any{
		"error": map[string]any{
			"code":          "auth_rate_limited",
			"message":       message,
			"model":         e.model,
			"reset_time":    displayDuration.String(),
			"reset_seconds": resetSeconds,
		},
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return fmt.Sprintf(`{"error":{"code":"auth_rate_limited","message":"%s"}}`, message)
	}
	return string(data)
}

func (e *authRateLimitError) StatusCode() int {
	return http.StatusTooManyRequests
}

func (e *authRateLimitError) Headers() http.Header {
	headers := make(http.Header)
	headers.Set("Content-Type", "application/json")
	resetSeconds := int(math.Ceil(e.resetIn().Seconds()))
	if resetSeconds < 0 {
		resetSeconds = 0
	}
	headers.Set("Retry-After", strconv.Itoa(resetSeconds))
	return headers
}
