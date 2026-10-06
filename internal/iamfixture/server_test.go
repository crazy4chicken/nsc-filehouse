package iamfixture_test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	iam "github.com/crazy4chicken/nsc-teamusers/sdk/go"

	"github.com/crazy4chicken/nsc-filehouse/internal/iamfixture"
)

// TestPermissionsEndpointServesSDKSnapshot pins the fixture to the snapshot
// shape the SDK accepts. The SDK fails closed on any other shape, and the
// integration suite is gated by FILEHOUSE_TEST_PG, so a drift here would deny
// every request the suite exercises while the rest of the unit suite stays
// green.
func TestPermissionsEndpointServesSDKSnapshot(t *testing.T) {
	server, err := iamfixture.NewServer(iamfixture.Options{})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	server.SetGrants("u1", 7,
		iamfixture.Grant{Key: "filehouse:read:any"},
		iamfixture.Grant{Key: "!filehouse:delete:any"},
	)

	client := iam.NewPermissionsClient(server.URL(), iam.WithServiceToken("service-token"))
	entry, err := client.Get(context.Background(), "u1", 7)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if entry.UserID != "u1" || entry.PermVer != 7 {
		t.Fatalf("entry = %+v, want user u1 at perm_ver 7", entry)
	}
	keys := make([]string, 0, len(entry.Grants))
	for _, grant := range entry.Grants {
		keys = append(keys, grant.Key)
	}
	if strings.Join(keys, ",") != "filehouse:read:any,!filehouse:delete:any" {
		t.Fatalf("grants = %v, want the seeded keys in order", keys)
	}
}

// TestPermissionsEndpointRejectsLegacyVersion covers the other half of the
// contract: a caller that asks for the legacy snapshot is rejected instead of
// being served grants the SDK would flatten and trust.
func TestPermissionsEndpointRejectsLegacyVersion(t *testing.T) {
	server, err := iamfixture.NewServer(iamfixture.Options{})
	if err != nil {
		t.Fatalf("NewServer: %v", err)
	}
	t.Cleanup(func() { _ = server.Close() })
	server.SetGrants("u1", 1, iamfixture.Grant{Key: "filehouse:read:any"})

	request, err := http.NewRequest(http.MethodGet, server.URL()+"/authz/permissions/u1", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	request.Header.Set("Authorization", "Bearer service-token")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatalf("Do: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.StatusCode, http.StatusBadRequest)
	}
}
