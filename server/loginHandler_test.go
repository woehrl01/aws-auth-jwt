package main

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	log "github.com/sirupsen/logrus"
)

func TestLoginHandler_ServeHTTP(t *testing.T) {
	private, public, _ := getPrivateKeysGenerated()
	keys, _ := getKeyMaterialFromKeys(private, public)
	
	var buf bytes.Buffer
	log.SetOutput(&buf)

	h := &loginHandler{
		vaultUpstream: &mockUpstream{},
		validator:     &mockValidator{},
		keyMaterial:   &keys.private,
	}

	t.Run("Test with valid input", func(t *testing.T) {
		h.vaultUpstream = &mockUpstream{
			response: &logical.Response{
				Auth: &logical.Auth{
					InternalData: map[string]interface{}{
						"canonical_arn":  "arn:aws:iam::123456789012:role/role-name",
						"account_id":     "123456789012",
						"client_user_id": "AIDAJQABLZS4A3QDU576Q",
					},
				},
			},
		}

		req := httptest.NewRequest(http.MethodPut, "/login", strings.NewReader(`{"user": "john.doe"}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Result().StatusCode != http.StatusOK {
			t.Errorf("Unexpected status code: %d", w.Result().StatusCode)
		}
	})

	t.Run("Test with invalid input (invalid method)", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/login", nil)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Result().StatusCode != http.StatusNotFound {
			t.Errorf("Unexpected status code: %d", w.Result().StatusCode)
		}
	})

	t.Run("Test with invalid input (invalid content type)", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/login", strings.NewReader(`{"user": "jane.doe"}`))
		req.Header.Set("Content-Type", "text/plain")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Result().StatusCode != http.StatusNotFound {
			t.Errorf("Unexpected status code: %d", w.Result().StatusCode)
		}
	})

	t.Run("Test with invalid input (invalid JSON)", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/login", strings.NewReader(`invalid JSON`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Result().StatusCode != http.StatusBadRequest {
			t.Errorf("Unexpected status code: %d", w.Result().StatusCode)
		}
	})
	t.Run("Test with invalid input (denied by validator)", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPut, "/login", strings.NewReader(`{"user": "jane.doe"}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Result().StatusCode != http.StatusUnauthorized {
			t.Errorf("Unexpected status code: %d", w.Result().StatusCode)
		}
	})

	t.Run("Test with invalid input (failed upstream login)", func(t *testing.T) {
		h.vaultUpstream = &mockUpstream{
			response: &logical.Response{
				Data: map[string]interface{}{
					"error": "invalid credentials",
				},
			},
		}
		req := httptest.NewRequest(http.MethodPut, "/login", strings.NewReader(`{"user": "john.doe"}`))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Result().StatusCode != http.StatusUnauthorized {
			t.Errorf("Unexpected status code: %d", w.Result().StatusCode)
		}
	})
}

type mockUpstream struct {
	response *logical.Response
}

func (m *mockUpstream) executeUpstreamLogin(ctx context.Context, requestData map[string]interface{}) *logical.Response {
	return m.response
}

type mockValidator struct{}

func (m *mockValidator) HasAccess(requestData map[string]interface{}, upstreamResponse *logical.Response) ValidatorResult {
	if requestData["user"] == "jane.doe" {
		return Deny()
	} else {
		return Allow(map[string]interface{}{"foo": "bar"})
	}
}
