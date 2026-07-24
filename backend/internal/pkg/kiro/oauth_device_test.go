//go:build unit

package kiro

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRegisterIDCDeviceClientUsesKiroRSDeviceGrant(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/client/register" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		var payload struct {
			ClientName   string   `json:"clientName"`
			GrantTypes   []string `json:"grantTypes"`
			RedirectURIs []string `json:"redirectUris"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		if payload.ClientName != "kiro-rs" {
			t.Fatalf("unexpected client name: %s", payload.ClientName)
		}
		if len(payload.GrantTypes) != 2 ||
			payload.GrantTypes[0] != idcDeviceGrantType ||
			payload.GrantTypes[1] != "refresh_token" {
			t.Fatalf("unexpected grant types: %#v", payload.GrantTypes)
		}
		if payload.RedirectURIs != nil {
			t.Fatalf("device registration must not send redirectUris: %#v", payload.RedirectURIs)
		}
		_, _ = w.Write([]byte(`{"clientId":"client-id","clientSecret":"client-secret"}`))
	}))
	defer server.Close()
	setOIDCTestEndpoint(t, server.URL)

	registration, err := RegisterIDCDeviceClient(
		context.Background(),
		"",
		BuilderIDStartURL,
		"us-east-1",
	)
	if err != nil {
		t.Fatalf("register device client: %v", err)
	}
	if registration.ClientID != "client-id" || registration.ClientSecret != "client-secret" {
		t.Fatalf("unexpected registration: %#v", registration)
	}
}

func TestStartIDCDeviceAuthorization(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/device_authorization" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		var payload map[string]string
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		if payload["clientId"] != "client-id" ||
			payload["clientSecret"] != "client-secret" ||
			payload["startUrl"] != BuilderIDStartURL {
			t.Fatalf("unexpected payload: %#v", payload)
		}
		_, _ = w.Write([]byte(`{
			"deviceCode":"device-code",
			"userCode":"ABCD-EFGH",
			"verificationUri":"https://example.test/verify",
			"verificationUriComplete":"https://example.test/verify?user_code=ABCD-EFGH",
			"expiresIn":600,
			"interval":5
		}`))
	}))
	defer server.Close()
	setOIDCTestEndpoint(t, server.URL)

	result, err := StartIDCDeviceAuthorization(
		context.Background(),
		"",
		"client-id",
		"client-secret",
		BuilderIDStartURL,
		"us-east-1",
	)
	if err != nil {
		t.Fatalf("start device authorization: %v", err)
	}
	if result.DeviceCode != "device-code" || result.UserCode != "ABCD-EFGH" || result.Interval != 5 {
		t.Fatalf("unexpected authorization: %#v", result)
	}
}

func TestPollIDCDeviceTokenHandlesPendingAndSuccess(t *testing.T) {
	tokenRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/token":
			tokenRequests++
			var payload map[string]string
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode payload: %v", err)
			}
			if payload["grantType"] != idcDeviceGrantType || payload["deviceCode"] != "device-code" {
				t.Fatalf("unexpected token payload: %#v", payload)
			}
			if tokenRequests == 1 {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error":"authorization_pending"}`))
				return
			}
			_, _ = w.Write([]byte(`{
				"accessToken":"access-token",
				"refreshToken":"refresh-token",
				"expiresIn":3600
			}`))
		case "/userinfo":
			_, _ = w.Write([]byte(`{"email":"user@example.com"}`))
		default:
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
	}))
	defer server.Close()
	setOIDCTestEndpoint(t, server.URL)

	pending, err := PollIDCDeviceToken(
		context.Background(),
		"",
		"client-id",
		"client-secret",
		"device-code",
		"us-east-1",
		BuilderIDStartURL,
	)
	if err != nil {
		t.Fatalf("poll pending token: %v", err)
	}
	if pending.Status != IDCDeviceTokenPending || pending.Token != nil {
		t.Fatalf("unexpected pending result: %#v", pending)
	}

	success, err := PollIDCDeviceToken(
		context.Background(),
		"",
		"client-id",
		"client-secret",
		"device-code",
		"us-east-1",
		BuilderIDStartURL,
	)
	if err != nil {
		t.Fatalf("poll successful token: %v", err)
	}
	if success.Status != IDCDeviceTokenSuccess ||
		success.Token == nil ||
		success.Token.AccessToken != "access-token" ||
		success.Token.Provider != ProviderBuilderId ||
		success.Token.Email != "user@example.com" {
		t.Fatalf("unexpected successful result: %#v", success)
	}
}

func setOIDCTestEndpoint(t *testing.T, endpoint string) {
	t.Helper()
	previous := oidcEndpointOverride
	oidcEndpointOverride = endpoint
	t.Cleanup(func() {
		oidcEndpointOverride = previous
	})
}
