package v1

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Integration tests run against the live netcup API and are skipped unless
// both NETCUP_API_KEY and NETCUP_TEST_DOMAIN are set:
//
//	NETCUP_API_KEY=... NETCUP_TEST_DOMAIN=example.com go test ./pkg/rest/... -run Integration -v
//
// They create and remove TXT records under _acme-challenge.netcup-itest.<domain>
// in the given zone, and touch nothing else.
const integrationScope = "netcup-itest"

func integrationClient(t *testing.T) (*Client, string) {
	t.Helper()
	apiKey := os.Getenv("NETCUP_API_KEY")
	domain := os.Getenv("NETCUP_TEST_DOMAIN")
	if apiKey == "" || domain == "" {
		t.Skip("set NETCUP_API_KEY and NETCUP_TEST_DOMAIN to run integration tests")
	}
	return NewClient(apiKey, nil), strings.TrimSuffix(domain, ".")
}

// keyAuthorization returns a value shaped like a real ACME key authorization
// digest, which is the only thing the challenge endpoints accept.
func keyAuthorization(t *testing.T) string {
	t.Helper()
	buf := make([]byte, 32)
	_, err := rand.Read(buf)
	require.NoError(t, err)
	value := base64.RawURLEncoding.EncodeToString(buf)
	require.Len(t, value, 43)
	return value
}

// The full flow a cert-manager webhook performs, against the live API.
func TestIntegrationChallengeLifecycle(t *testing.T) {
	client, domainName := integrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// cert-manager presents a resolved FQDN with a trailing dot.
	fqdn := "_acme-challenge." + integrationScope + "." + domainName + "."

	domain, err := client.ResolveDomain(ctx, fqdn)
	require.NoError(t, err)
	assert.Equal(t, domainName, domain.Fqdn)
	require.True(t, domain.IsDnsManaged, "zone is not on the new DNS backend")
	t.Logf("resolved %s to domain id %d", fqdn, domain.Id)

	scope, err := AcmeScope(fqdn, domain.Fqdn)
	require.NoError(t, err)
	require.Equal(t, integrationScope, scope)

	value := keyAuthorization(t)
	// Remove the record even if an assertion below fails.
	defer func() {
		if err := client.DeleteAcmeChallenge(context.Background(), domain.Id, scope, value); err != nil && !IsNotFound(err) {
			t.Errorf("cleanup failed, record may remain: %v", err)
		}
	}()

	created, err := client.AddAcmeChallenge(ctx, domain.Id, scope, value)
	require.NoError(t, err)
	require.Len(t, created, 1)
	assert.Equal(t, "_acme-challenge."+integrationScope+"."+domainName, created[0].Fqdn)
	assert.Equal(t, value, created[0].Value)
	t.Logf("created with status %q", created[0].Status)

	// Present is called repeatedly for the same challenge; it must not fail.
	again, err := client.AddAcmeChallenge(ctx, domain.Id, scope, value)
	require.NoError(t, err, "adding an existing value must be idempotent")
	require.Len(t, again, 1)
	t.Logf("re-added with status %q", again[0].Status)

	listed, err := client.GetAcmeChallenges(ctx, domain.Id)
	require.NoError(t, err)
	var found bool
	for _, c := range listed {
		if c.Value == value {
			found = true
		}
	}
	assert.True(t, found, "created challenge missing from the listing")

	require.NoError(t, client.DeleteAcmeChallenge(ctx, domain.Id, scope, value))

	err = client.DeleteAcmeChallenge(ctx, domain.Id, scope, value)
	require.Error(t, err, "deleting a removed record must report not-found")
	assert.True(t, IsNotFound(err), "expected resourceDoesNotExist, got %v", err)
}

// A name that is not in the account must walk to the end and report
// not-found. example.com is used because it is certainly not in the account
// and is a syntactically valid hostname, so it reaches the lookup rather than
// being rejected by parameter validation.
func TestIntegrationResolveDomainUnknownName(t *testing.T) {
	client, _ := integrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	_, err := client.ResolveDomain(ctx, "_acme-challenge.nothing-here.example.com")

	require.Error(t, err)
	assert.True(t, IsNotFound(err), "expected not-found, got %v", err)
	assert.False(t, IsAuthError(err))
}

// An invalid key must abort the walk with an auth error, not be mistaken for
// a missing zone.
func TestIntegrationResolveDomainInvalidKey(t *testing.T) {
	_, domainName := integrationClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	bad := NewClient(strings.Repeat("x", 64), nil)
	_, err := bad.ResolveDomain(ctx, "_acme-challenge."+domainName)

	require.Error(t, err)
	assert.True(t, IsAuthError(err), "expected authenticationError, got %v", err)
	assert.False(t, IsNotFound(err))
}
