// SPDX-License-Identifier: ice License 1.0

package accounts

import (
	"crypto/ed25519"
	"encoding/hex"
	"strings"

	"github.com/pkg/errors"

	"github.com/ice-blockchain/heimdall/accounts/internal/dfns"
)

func identityWallet(wallets []dfns.Wallet, masterKey string) dfns.Wallet {
	for _, wallet := range wallets {
		if id, key := dfns.CheckMainWallet(wallet); id != "" && key == masterKey {
			return wallet
		}
	}
	return nil
}

// Only reconcile a provider-authenticated user with their own existing wallet.
// Never write a new wallet key into an established social identity.
func preserveRegistrationIdentity(existing *user, userID, username string, wallets []dfns.Wallet, response map[string]any) error {
	if existing.ID != userID || !strings.EqualFold(existing.IdentityKeyName, username) {
		return errors.Wrap(ErrInvalidIdentityKey, "registration identity does not match existing account")
	}
	key, err := hex.DecodeString(existing.MasterPubKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return errors.Wrap(ErrInvalidIdentityKey, "existing registration identity is not a valid public key")
	}
	original := identityWallet(wallets, existing.MasterPubKey)
	if original == nil {
		return errors.Wrap(ErrInvalidIdentityKey, "original identity wallet is absent from provider-owned wallets; use identity recovery")
	}
	createdID, _ := dfns.ExtractMainWallet(response)
	returned, ok := response["wallets"].([]any)
	if !ok || createdID == "" {
		return errors.Wrap(ErrInvalidIdentityKey, "registration response has no main wallet")
	}
	updated := append([]any(nil), returned...)
	for index, entry := range returned {
		wallet, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		if id, _ := dfns.CheckMainWallet(wallet); id == createdID {
			updated[index] = map[string]any(original)
			response["wallets"] = updated
			return nil
		}
	}
	return errors.Wrap(ErrInvalidIdentityKey, "cannot reconcile registration main wallet")
}
