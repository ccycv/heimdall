// SPDX-License-Identifier: ice License 1.0

package accounts

import (
	"context"
	"net/url"
	"os"
	"strings"
	"testing"
	stdlibtime "time"

	"github.com/ice-blockchain/heimdall/accounts/internal/dfns"
	"github.com/ice-blockchain/wintr/connectors/storage/v2"
	"github.com/ice-blockchain/wintr/time"
	"github.com/jackc/pgx/v5"
)

type identityTestWalletClient struct {
	dfns.DfnsClient
	wallets []dfns.Wallet
}

func (c identityTestWalletClient) ListWallets(_ context.Context, _ string) ([]dfns.Wallet, error) {
	return c.wallets, nil
}

func TestEstablishedRegistrationReadOnlyPostgres(t *testing.T) {
	dsn := os.Getenv("IDENTITY_PRESERVATION_TEST_DSN")
	if dsn == "" {
		t.Skip("set IDENTITY_PRESERVATION_TEST_DSN to an isolated local identity_test database")
	}
	u, err := url.Parse(dsn)
	if err != nil || u.Hostname() != "127.0.0.1" || u.Path != "/identity_test" {
		t.Fatal("only the isolated local identity_test database is allowed")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*stdlibtime.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	_, err = conn.Exec(ctx, `CREATE TABLE IF NOT EXISTS users (
 created_at timestamp, updated_at timestamp, id text PRIMARY KEY, identity_key_name text,
 master_pubkey text, duplicate_of text, clients text[], email text[], phone_number text[],
 totp_authenticator_secret text[], ion_connect_relays text[], active_2fa_email boolean[],
 active_2fa_phone_number boolean[], active_2fa_totp_authenticator boolean[], verified boolean);
 CREATE TABLE IF NOT EXISTS ion_connect_relays (url text, relay_type text);`)
	if err != nil {
		t.Fatal(err)
	}
	oldKey, newKey := strings.Repeat("11", 32), strings.Repeat("22", 32)
	_, err = conn.Exec(ctx, `INSERT INTO users (id,identity_key_name,master_pubkey,created_at,updated_at,clients,email,ion_connect_relays,verified)
 VALUES ('user-existing','existing',$1,'2025-01-01','2025-01-02',ARRAY['original-device'],ARRAY['original@example.invalid'],ARRAY[]::text[],true)
 ON CONFLICT (id) DO NOTHING`, oldKey)
	if err != nil {
		t.Fatal(err)
	}
	var before string
	if err = conn.QueryRow(ctx, "SELECT row_to_json(u)::text FROM users u WHERE id='user-existing'").Scan(&before); err != nil {
		t.Fatal(err)
	}
	query := u.Query()
	query.Set("default_transaction_read_only", "on")
	u.RawQuery = query.Encode()
	db := storage.MustConnectWithCfg(ctx, &storage.Cfg{PrimaryURL: u.String(), ReplicaURLs: []string{u.String()}, SkipSettingsVerification: true}, nil)
	defer db.Close()
	var ro struct {
		Value string `db:"default_transaction_read_only"`
	}
	state, err := storage.Get[struct {
		Value string `db:"default_transaction_read_only"`
	}](ctx, db, "SHOW default_transaction_read_only")
	if err != nil {
		t.Fatal(err)
	}
	ro = *state
	if ro.Value != "on" {
		t.Fatal("test connection is not read-only")
	}
	original := registrationTestWallet("original", oldKey, "Ion", "main")
	extra := registrationTestWallet("extra", newKey, "Ion", "main")
	a := &accounts{db: db, delegatedRPClient: identityTestWalletClient{wallets: []dfns.Wallet{extra, original}}}
	for attempt := 0; attempt < 2; attempt++ {
		response := map[string]any{"user": map[string]any{"id": "user-existing", "username": "existing"}, "wallets": []any{map[string]any(extra)}}
		preserved, err := a.upsertUserFromRegistration(ctx, time.Now(), response, newKey, "replacement-visitor", "replacement-device", "different@example.invalid")
		if err != nil {
			t.Fatal(err)
		}
		if preserved.MasterPubKey != oldKey || !preserved.Verified || preserved.Clients[0] != "original-device" {
			t.Fatal("existing identity changed")
		}
		if id, key := dfns.ExtractMainWallet(response); id != "original" || key != oldKey {
			t.Fatal("returned identity is not the original wallet")
		}
	}
	var after string
	if err = conn.QueryRow(ctx, "SELECT row_to_json(u)::text FROM users u WHERE id='user-existing'").Scan(&after); err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatal("established user row was modified")
	}
	wallet, err := a.FetchMainWallet(ctx, oldKey)
	if err != nil || wallet["id"] != "original" {
		t.Fatalf("main wallet reconciliation failed: %v", err)
	}
}
