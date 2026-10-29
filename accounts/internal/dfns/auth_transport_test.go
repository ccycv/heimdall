// SPDX-License-Identifier: ice License 1.0

package dfns

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type authTestTransport func(*http.Request) (*http.Response, error)

func (f authTestTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestAuthTransportRouting(t *testing.T) {
	for _, tc := range []struct {
		path   string
		action string
		direct bool
	}{
		{initLoginUrl, "", true},
		{completeDelegatedRegistrationUrl, "", true},
		{initUserSignatureUrl, "", true},
		{"/wallets/wallet/transactions", "signed-action", true},
		{"/wallets/wallet/transactions", "", false},
		{delegatedLoginUrl, "", false},
		{initDelegatedRegistrationUrl, "", false},
	} {
		t.Run(tc.path+tc.action, func(t *testing.T) {
			directCalls, sdkCalls := 0, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				directCalls++
				if r.URL.Path != tc.path || r.Header.Get(userActionDfnsHeader) != tc.action {
					t.Error("request path or signed action was changed")
				}
				w.WriteHeader(http.StatusUnauthorized)
			}))
			defer server.Close()
			client := &dfnsClient{cfg: &config{DFNS: dfnsCfg{BaseURL: server.URL}}}
			sdk := &http.Client{Transport: authTestTransport(func(r *http.Request) (*http.Response, error) {
				sdkCalls++
				return &http.Response{StatusCode: 401, Body: io.NopCloser(strings.NewReader("{}")), Header: http.Header{}}, nil
			})}
			headers := http.Header{}
			if tc.action != "" {
				headers.Set(userActionDfnsHeader, tc.action)
			}
			_, _, err := client.doClientCall(context.Background(), sdk, "POST", tc.path, headers, []byte("{}"))
			if err != nil {
				t.Fatal(err)
			}
			if tc.direct && (directCalls != 1 || sdkCalls != 0) {
				t.Fatal("expected direct request without SDK signing")
			}
			if !tc.direct && (sdkCalls != 1 || directCalls != 0) {
				t.Fatal("SDK signing behavior was not preserved")
			}
		})
	}
}

func TestRegistrationAndLoginOmitLegacyHeader(t *testing.T) {
	for _, registration := range []bool{true, false} {
		name := "login"
		if registration {
			name = "registration"
		}
		t.Run(name, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.Header.Get(userActionDfnsHeader) != "" {
					t.Error("obsolete user-action header present")
				}
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Error(err)
				}
				if registration {
					if r.URL.Path != completeDelegatedRegistrationUrl || r.Header.Get(authDfnsHeader) != "Bearer test-only" {
						t.Error("registration authentication/path changed")
					}
					if wallets, ok := body["wallets"].([]any); !ok || len(wallets) != 2 {
						t.Error("wallet creation payload changed")
					}
					if _, ok := body["firstFactorCredential"]; !ok {
						t.Error("credential payload dropped")
					}
				} else if r.URL.Path != initLoginUrl || body["username"] != "test-only" || body["orgId"] != "org-test" {
					t.Error("login payload/path changed")
				}
				w.WriteHeader(401)
				_, _ = w.Write([]byte(`{"error":{"status":401,"message":"diagnostic"}}`))
			}))
			defer server.Close()
			client := &dfnsClient{cfg: &config{DFNS: dfnsCfg{BaseURL: server.URL, OrganizationID: "org-test"}}, userClients: map[string]*http.Client{"": server.Client()}}
			ctx := context.WithValue(context.Background(), AuthHeaderCtxValue, "Bearer test-only")
			var err error
			if registration {
				_, err = client.CompleteRegistrationWithWallets(ctx, &Credentials{FirstFactorCredential: map[string]any{"credentialKind": "Fido2"}})
			} else {
				_, err = client.GetLoginChallenge(ctx, "test-only")
			}
			if err == nil || calls != 1 {
				t.Fatal("expected one request and propagated provider rejection")
			}
		})
	}
}
