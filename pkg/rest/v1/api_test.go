package v1

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testApiKey = "test-api-key"

// route describes one expected request and the canned response for it.
type route struct {
	method string
	path   string // path and query, as sent (e.g. "/domain?fqdn=example.com")
	status int
	body   string // canned response body; empty means no body at all
	// wantBody, when set, is the request body the route expects, compared as
	// JSON rather than as bytes.
	wantBody string
}

// withTestServer serves the given routes, matching on method and full request
// URI. It fails the test on an unexpected request or a missing bearer token.
func withTestServer(t *testing.T, routes ...route) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+testApiKey {
			t.Errorf("missing or wrong bearer token: %q", got)
			http.Error(w, `{"success":false}`, http.StatusUnauthorized)
			return
		}
		for _, rt := range routes {
			if rt.method == r.Method && rt.path == r.URL.RequestURI() {
				if rt.wantBody != "" {
					got, _ := io.ReadAll(r.Body)
					var want, have interface{}
					require.NoError(t, json.Unmarshal([]byte(rt.wantBody), &want))
					require.NoError(t, json.Unmarshal(got, &have))
					assert.Equal(t, want, have, "unexpected request body")
				}
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(rt.status)
				if rt.body != "" {
					_, _ = w.Write([]byte(rt.body))
				}
				return
			}
		}
		t.Errorf("unexpected request: %s %s", r.Method, r.URL.RequestURI())
		http.Error(w, `{"success":false}`, http.StatusNotFound)
	}))
}

func testClient(url string) *Client {
	return NewClient(testApiKey, &ClientOptions{Endpoint: url})
}

const domainFoundBody = `{
  "success": true, "errors": [], "messages": [],
  "meta": {"pagination": {"page": 1, "perPage": 50, "totalEntries": 1}},
  "result": [{"id": 1047093, "fqdn": "example.com", "isDnsManaged": true}]
}`

func TestGetDomainsReturnsTheDomain(t *testing.T) {
	ts := withTestServer(t, route{"GET", "/domain?fqdn=example.com", 200, domainFoundBody, ""})
	defer ts.Close()

	domains, err := testClient(ts.URL).GetDomains(context.Background(), "example.com")

	require.NoError(t, err)
	require.Len(t, domains, 1)
	assert.Equal(t, 1047093, domains[0].Id)
	assert.Equal(t, "example.com", domains[0].Fqdn)
	assert.True(t, domains[0].IsDnsManaged)
}

const domainNotFoundBody = `{
  "success": false,
  "errors": [{"code": "resourceDoesNotExist", "message": "No results found, the page number may be too high."}],
  "messages": [], "meta": null, "result": null
}`

const authErrorBody = `{
  "success": false,
  "errors": [{"code": "authenticationError", "message": "Authentication token is not valid or has expired."}],
  "messages": [], "meta": null, "result": null
}`

func TestGetDomainsUnknownNameYieldsNotFound(t *testing.T) {
	ts := withTestServer(t, route{"GET", "/domain?fqdn=nope.example.com", 404, domainNotFoundBody, ""})
	defer ts.Close()

	_, err := testClient(ts.URL).GetDomains(context.Background(), "nope.example.com")

	require.Error(t, err)
	var apiErr *APIError
	require.ErrorAs(t, err, &apiErr)
	assert.Equal(t, "resourceDoesNotExist", apiErr.Code())
	assert.Equal(t, 404, apiErr.StatusCode)
	assert.True(t, IsNotFound(err))
	assert.False(t, IsAuthError(err))
}

// The API answers an invalid key with HTTP 400 rather than 401, so the code is
// the only reliable discriminator.
func TestGetDomainsInvalidKeyYieldsAuthError(t *testing.T) {
	ts := withTestServer(t, route{"GET", "/domain?fqdn=example.com", 400, authErrorBody, ""})
	defer ts.Close()

	_, err := testClient(ts.URL).GetDomains(context.Background(), "example.com")

	require.Error(t, err)
	assert.True(t, IsAuthError(err))
	assert.False(t, IsNotFound(err))
}

const (
	testValue  = "odeFPdrsdv0DkYkJO27cpRGWydB05G9xxXJa9QZwv2Q"
	testScope  = "host"
	testDomain = 1047093
)

const challengeCreatedBody = `{
  "success": true, "errors": [], "messages": [], "meta": null,
  "result": [{"scope": "host", "fqdn": "_acme-challenge.host.example.com",
              "value": "odeFPdrsdv0DkYkJO27cpRGWydB05G9xxXJa9QZwv2Q", "status": "pending"}]
}`

const challengeExistsBody = `{
  "success": true, "errors": [], "messages": [], "meta": null,
  "result": [{"scope": "host", "fqdn": "_acme-challenge.host.example.com",
              "value": "odeFPdrsdv0DkYkJO27cpRGWydB05G9xxXJa9QZwv2Q", "status": "deployed"}]
}`

func TestAddAcmeChallengeCreates(t *testing.T) {
	ts := withTestServer(t, route{
		method: "POST", path: "/domain/1047093/acme/challenge", status: 201,
		wantBody: `{"scope":"host","value":"odeFPdrsdv0DkYkJO27cpRGWydB05G9xxXJa9QZwv2Q"}`,
		body:     challengeCreatedBody,
	})
	defer ts.Close()

	challenges, err := testClient(ts.URL).AddAcmeChallenge(context.Background(), testDomain, testScope, testValue)

	require.NoError(t, err)
	require.Len(t, challenges, 1)
	assert.Equal(t, "_acme-challenge.host.example.com", challenges[0].Fqdn)
	assert.Equal(t, "pending", challenges[0].Status)
}

// Adding a value that is already present answers 200 instead of 201, and is
// not an error: cert-manager calls Present repeatedly for the same challenge.
func TestAddAcmeChallengeIsIdempotent(t *testing.T) {
	ts := withTestServer(t, route{
		method: "POST", path: "/domain/1047093/acme/challenge", status: 200,
		wantBody: `{"scope":"host","value":"odeFPdrsdv0DkYkJO27cpRGWydB05G9xxXJa9QZwv2Q"}`,
		body:     challengeExistsBody,
	})
	defer ts.Close()

	challenges, err := testClient(ts.URL).AddAcmeChallenge(context.Background(), testDomain, testScope, testValue)

	require.NoError(t, err)
	require.Len(t, challenges, 1)
	assert.Equal(t, "deployed", challenges[0].Status)
}

func TestGetAcmeChallenges(t *testing.T) {
	ts := withTestServer(t, route{"GET", "/domain/1047093/acme/challenge", 200, challengeExistsBody, ""})
	defer ts.Close()

	challenges, err := testClient(ts.URL).GetAcmeChallenges(context.Background(), testDomain)

	require.NoError(t, err)
	require.Len(t, challenges, 1)
	assert.Equal(t, testValue, challenges[0].Value)
}

// A successful delete answers 204 with no body at all.
func TestDeleteAcmeChallenge(t *testing.T) {
	ts := withTestServer(t, route{
		method: "DELETE",
		path:   "/domain/1047093/acme/challenge/host/" + testValue,
		status: 204,
	})
	defer ts.Close()

	err := testClient(ts.URL).DeleteAcmeChallenge(context.Background(), testDomain, testScope, testValue)

	assert.NoError(t, err)
}

// Deleting a record that is already gone answers 404. The client reports it as
// an *APIError; treating it as success is the caller's decision.
func TestDeleteAcmeChallengeAlreadyGone(t *testing.T) {
	ts := withTestServer(t, route{
		method: "DELETE",
		path:   "/domain/1047093/acme/challenge/host/" + testValue,
		status: 404,
		body:   `{"success": false, "errors": [{"code": "resourceDoesNotExist", "message": "No result was found."}], "messages": [], "meta": null, "result": null}`,
	})
	defer ts.Close()

	err := testClient(ts.URL).DeleteAcmeChallenge(context.Background(), testDomain, testScope, testValue)

	require.Error(t, err)
	assert.True(t, IsNotFound(err))
}

func notFound(path string) route {
	return route{"GET", path, 404, domainNotFoundBody, ""}
}

func found(path string, id int, fqdn string) route {
	return route{"GET", path, 200, fmt.Sprintf(
		`{"success": true, "errors": [], "messages": [], "meta": null,
		  "result": [{"id": %d, "fqdn": %q, "isDnsManaged": true}]}`, id, fqdn), ""}
}

// The walk must stop at the most specific zone: a challenge below a delegated
// subzone belongs to that subzone, not to the parent domain.
func TestResolveDomainPrefersTheLongestMatch(t *testing.T) {
	ts := withTestServer(t,
		notFound("/domain?fqdn=_acme-challenge.host.sub.example.com"),
		notFound("/domain?fqdn=host.sub.example.com"),
		found("/domain?fqdn=sub.example.com", 222, "sub.example.com"),
		found("/domain?fqdn=example.com", 111, "example.com"),
	)
	defer ts.Close()

	domain, err := testClient(ts.URL).ResolveDomain(context.Background(), "_acme-challenge.host.sub.example.com")

	require.NoError(t, err)
	assert.Equal(t, 222, domain.Id)
	assert.Equal(t, "sub.example.com", domain.Fqdn)
}

// A multi-label public suffix must not be mistaken for the zone.
func TestResolveDomainHandlesMultiLabelSuffix(t *testing.T) {
	ts := withTestServer(t,
		notFound("/domain?fqdn=_acme-challenge.example.co.uk"),
		found("/domain?fqdn=example.co.uk", 333, "example.co.uk"),
	)
	defer ts.Close()

	domain, err := testClient(ts.URL).ResolveDomain(context.Background(), "_acme-challenge.example.co.uk")

	require.NoError(t, err)
	assert.Equal(t, 333, domain.Id)
}

func TestResolveDomainNotFound(t *testing.T) {
	ts := withTestServer(t,
		notFound("/domain?fqdn=_acme-challenge.example.com"),
		notFound("/domain?fqdn=example.com"),
	)
	defer ts.Close()

	_, err := testClient(ts.URL).ResolveDomain(context.Background(), "_acme-challenge.example.com")

	require.Error(t, err)
	assert.True(t, IsNotFound(err))
	assert.ErrorContains(t, err, "_acme-challenge.example.com")
}

// An invalid key must abort the walk. Walking on would exhaust the labels and
// report "no zone found", pointing at the wrong cause. The test server fails
// the test if a second request arrives.
func TestResolveDomainStopsOnAuthError(t *testing.T) {
	ts := withTestServer(t,
		route{"GET", "/domain?fqdn=_acme-challenge.example.com", 400, authErrorBody, ""},
	)
	defer ts.Close()

	_, err := testClient(ts.URL).ResolveDomain(context.Background(), "_acme-challenge.example.com")

	require.Error(t, err)
	assert.True(t, IsAuthError(err))
	assert.False(t, IsNotFound(err))
}

// A trailing dot is how cert-manager presents a resolved FQDN.
func TestResolveDomainAcceptsATrailingDot(t *testing.T) {
	ts := withTestServer(t,
		notFound("/domain?fqdn=_acme-challenge.example.com"),
		found("/domain?fqdn=example.com", 111, "example.com"),
	)
	defer ts.Close()

	domain, err := testClient(ts.URL).ResolveDomain(context.Background(), "_acme-challenge.example.com.")

	require.NoError(t, err)
	assert.Equal(t, 111, domain.Id)
}

func TestAcmeScope(t *testing.T) {
	for _, tc := range []struct {
		name  string
		fqdn  string
		zone  string
		scope string
	}{
		{"apex", "_acme-challenge.example.com", "example.com", "@"},
		{"single label", "_acme-challenge.host.example.com", "example.com", "host"},
		{"multiple labels", "_acme-challenge.a.b.example.com", "example.com", "a.b"},
		{"trailing dots", "_acme-challenge.host.example.com.", "example.com.", "host"},
		{"delegated subzone", "_acme-challenge.host.sub.example.com", "sub.example.com", "host"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			scope, err := AcmeScope(tc.fqdn, tc.zone)
			require.NoError(t, err)
			assert.Equal(t, tc.scope, scope)
		})
	}
}

func TestAcmeScopeRejectsBadInput(t *testing.T) {
	for _, tc := range []struct {
		name string
		fqdn string
		zone string
	}{
		// The API prepends _acme-challenge. itself, so a name without it would
		// silently produce a record one label too deep.
		{"missing challenge prefix", "host.example.com", "example.com"},
		{"name outside the zone", "_acme-challenge.host.example.org", "example.com"},
		{"zone equal to the full name", "_acme-challenge.example.com", "_acme-challenge.example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := AcmeScope(tc.fqdn, tc.zone)
			assert.Error(t, err)
		})
	}
}

func TestRequestsHonourContextCancellation(t *testing.T) {
	ts := withTestServer(t, route{"GET", "/domain?fqdn=example.com", 200, domainFoundBody, ""})
	defer ts.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := testClient(ts.URL).GetDomains(ctx, "example.com")

	require.Error(t, err)
	assert.ErrorIs(t, err, context.Canceled)
}

// http.DefaultClient has no overall timeout, so a server that accepts a
// request and then goes silent would block forever.
func TestDefaultClientHasATimeout(t *testing.T) {
	assert.NotZero(t, NewClient("key", nil).httpClient.Timeout)
	assert.NotZero(t, NewClient("key", &ClientOptions{Endpoint: "http://example.invalid"}).httpClient.Timeout)
}

func TestSuppliedHTTPClientIsUsed(t *testing.T) {
	custom := &http.Client{Timeout: 42 * time.Second}
	c := NewClient("key", &ClientOptions{HTTPClient: custom})
	assert.Same(t, custom, c.httpClient)
}
