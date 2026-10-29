// SPDX-License-Identifier: ice License 1.0

package accounts

import (
	"reflect"
	"strings"
	"testing"

	"github.com/ice-blockchain/heimdall/accounts/internal/dfns"
)

func registrationTestWallet(id, key, network, name string) dfns.Wallet {
	return dfns.Wallet{"id": id, "name": name, "network": network, "signingKey": map[string]any{"publicKey": key}}
}

func TestPreserveRegistrationIdentity(t *testing.T) {
	oldKey, newKey := strings.Repeat("11", 32), strings.Repeat("22", 32)
	oldWallet := registrationTestWallet("original", oldKey, "Ion", "main")
	newWallet := registrationTestWallet("extra", newKey, "Ion", "main")
	bscWallet := registrationTestWallet("bsc-existing", "bsc-key", "Bsc", "main-bsc")
	duplicate := "existing-duplicate"
	existing := &user{ID: "user-existing", IdentityKeyName: "existing", MasterPubKey: oldKey,
		Email: []string{"existing@example.invalid"}, Clients: []string{"original-device"}, Verified: true,
		DuplicateOf: &duplicate}
	before := *existing
	for _, reversed := range []bool{false, true} {
		wallets := []dfns.Wallet{newWallet, oldWallet, bscWallet}
		if reversed {
			wallets[0], wallets[1] = wallets[1], wallets[0]
		}
		response := map[string]any{"wallets": []any{map[string]any(newWallet), map[string]any(bscWallet)}, "authentication": "unchanged-token"}
		if err := preserveRegistrationIdentity(existing, "user-existing", "EXISTING", wallets, response); err != nil {
			t.Fatal(err)
		}
		id, key := dfns.ExtractMainWallet(response)
		if id != "original" || key != oldKey {
			t.Fatal("registration selected replacement identity")
		}
		if !reflect.DeepEqual(existing, &before) {
			t.Fatal("existing account data changed")
		}
		if response["authentication"] != "unchanged-token" {
			t.Fatal("authentication changed")
		}
		if !reflect.DeepEqual(response["wallets"].([]any)[1], map[string]any(bscWallet)) {
			t.Fatal("unrelated wallet changed")
		}
	}
}

func TestPreserveRegistrationIdentityFailsClosed(t *testing.T) {
	oldKey, newKey := strings.Repeat("11", 32), strings.Repeat("22", 32)
	original := registrationTestWallet("original", oldKey, "Ion", "main")
	newWallet := registrationTestWallet("extra", newKey, "Ion", "main")
	for _, tc := range []struct {
		name, id, username, key string
		wallets                 []dfns.Wallet
	}{
		{"different-user", "other", "existing", oldKey, []dfns.Wallet{original}},
		{"different-login", "user-existing", "other", oldKey, []dfns.Wallet{original}},
		{"invalid-original-key", "user-existing", "existing", "invalid", []dfns.Wallet{original}},
		{"missing-owned-original", "user-existing", "existing", oldKey, []dfns.Wallet{newWallet}},
		{"wrong-network", "user-existing", "existing", oldKey, []dfns.Wallet{registrationTestWallet("other", oldKey, "Bsc", "main")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			existing := &user{ID: "user-existing", IdentityKeyName: "existing", MasterPubKey: tc.key}
			response := map[string]any{"wallets": []any{map[string]any(newWallet)}}
			if err := preserveRegistrationIdentity(existing, tc.id, tc.username, tc.wallets, response); err == nil {
				t.Fatal("unsafe reconciliation accepted")
			}
			if id, _ := dfns.ExtractMainWallet(response); id != "extra" {
				t.Fatal("failed reconciliation mutated response")
			}
			if existing.MasterPubKey != tc.key {
				t.Fatal("failed reconciliation mutated identity")
			}
		})
	}
}

func TestIdentityWalletSelectsOriginalRegardlessOfOrder(t *testing.T) {
	key := strings.Repeat("11", 32)
	oldWallet := registrationTestWallet("original", key, "Ion", "main")
	extra := registrationTestWallet("extra", strings.Repeat("22", 32), "Ion", "main")
	for _, wallets := range [][]dfns.Wallet{{oldWallet, extra}, {extra, oldWallet}} {
		if got := identityWallet(wallets, key); got == nil || got["id"] != "original" {
			t.Fatal("selected replacement main wallet")
		}
	}
	if identityWallet([]dfns.Wallet{extra}, key) != nil {
		t.Fatal("silently substituted new wallet")
	}
}
