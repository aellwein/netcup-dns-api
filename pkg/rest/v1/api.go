// Package v1 implements a client for the netcup REST API at
// https://api.netcup.com/v1, as described by
// https://api.netcup.com/v1/openapi.json.
//
// It is unrelated to the legacy CCP API in pkg/v1, which uses a different
// authentication scheme, request format and data model.
package v1

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultEndpoint is the base URL of the netcup REST API.
const DefaultEndpoint = "https://api.netcup.com/v1"

// DefaultTimeout bounds a single request when no HTTP client is supplied.
// http.DefaultClient has no overall timeout, so a server that accepts a
// request and then stops responding would block the caller indefinitely.
const DefaultTimeout = 30 * time.Second

// Client talks to the netcup REST API. It holds no session state; every
// request carries the API key as a bearer token.
type Client struct {
	apiKey     string
	endpoint   string
	httpClient *http.Client
}

// ClientOptions carries optional client settings.
type ClientOptions struct {
	// Endpoint overrides the API base URL. Useful for testing.
	Endpoint string
	// HTTPClient overrides the HTTP client used for requests.
	HTTPClient *http.Client
}

// NewClient returns a client authenticating with the given API key.
func NewClient(apiKey string, options *ClientOptions) *Client {
	c := &Client{
		apiKey:     apiKey,
		endpoint:   DefaultEndpoint,
		httpClient: &http.Client{Timeout: DefaultTimeout},
	}
	if options != nil {
		if options.Endpoint != "" {
			c.endpoint = options.Endpoint
		}
		if options.HTTPClient != nil {
			c.httpClient = options.HTTPClient
		}
	}
	return c
}

// Domain is a domain of the authenticated account.
type Domain struct {
	Id   int    `json:"id"`
	Fqdn string `json:"fqdn"`
	// IsDnsManaged reports whether the DNS of this domain can be managed
	// through the REST API. Domains still on the legacy backend report false.
	IsDnsManaged bool `json:"isDnsManaged"`
}

// AcmeChallenge is an ACME challenge TXT record managed through the dedicated
// challenge endpoints.
//
// Status reports netcup's deployment state, which reaches "deployed" within a
// second or two of the record being created. Note that this happens well
// before the record is resolvable on the authoritative nameservers, so it is
// not a signal that the challenge is ready to be validated.
type AcmeChallenge struct {
	// Scope is the record name relative to the zone, without the
	// _acme-challenge prefix, or "@" for the zone apex.
	Scope  string `json:"scope"`
	Fqdn   string `json:"fqdn"`
	Value  string `json:"value"`
	Status string `json:"status"`
}

// Message is a single error or informational message from the API.
type Message struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Error codes returned by the API. The HTTP status is not a reliable
// discriminator: an invalid API key is answered with 400, not 401.
const (
	// CodeResourceDoesNotExist is returned for a domain that is not in the
	// account, and for a challenge record that is not present.
	CodeResourceDoesNotExist = "resourceDoesNotExist"
	// CodeAuthenticationError is returned for an invalid or expired API key.
	CodeAuthenticationError = "authenticationError"
)

// APIError is returned when the API reports success: false. The messages are
// carried verbatim so callers can inspect codes the client does not know.
type APIError struct {
	StatusCode int
	Method     string
	Path       string
	Errors     []Message
}

func (e *APIError) Error() string {
	parts := make([]string, 0, len(e.Errors))
	for _, m := range e.Errors {
		parts = append(parts, fmt.Sprintf("%s: %s", m.Code, m.Message))
	}
	if len(parts) == 0 {
		return fmt.Sprintf("%s %s failed with HTTP %d", e.Method, e.Path, e.StatusCode)
	}
	return fmt.Sprintf("%s %s failed with HTTP %d: %s", e.Method, e.Path, e.StatusCode, strings.Join(parts, "; "))
}

// Code returns the first error code, or the empty string if there is none.
// Use HasCode to test an error that may carry several codes.
func (e *APIError) Code() string {
	if len(e.Errors) == 0 {
		return ""
	}
	return e.Errors[0].Code
}

// HasCode reports whether the error carries the given code.
func (e *APIError) HasCode(code string) bool {
	for _, m := range e.Errors {
		if m.Code == code {
			return true
		}
	}
	return false
}

// HasCode reports whether err is an *APIError carrying the given code.
func HasCode(err error, code string) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && apiErr.HasCode(code)
}

// IsNotFound reports whether err says the requested resource does not exist.
func IsNotFound(err error) bool {
	return HasCode(err, CodeResourceDoesNotExist)
}

// IsAuthError reports whether err says the API key was rejected.
func IsAuthError(err error) bool {
	return HasCode(err, CodeAuthenticationError)
}

// response is the envelope every API response is wrapped in.
type response struct {
	Success bool            `json:"success"`
	Errors  []Message       `json:"errors"`
	Result  json.RawMessage `json:"result"`
}

// GetDomains returns the domains matching the given fqdn, which is at most
// one. An unknown name is not an error at this level: it yields an *APIError
// with code "resourceDoesNotExist".
func (c *Client) GetDomains(ctx context.Context, fqdn string) ([]Domain, error) {
	var domains []Domain
	err := c.do(ctx, http.MethodGet, "domain?fqdn="+url.QueryEscape(fqdn), nil, &domains)
	return domains, err
}

// GetAcmeChallenges returns the ACME challenge records of a domain.
func (c *Client) GetAcmeChallenges(ctx context.Context, domainId int) ([]AcmeChallenge, error) {
	var challenges []AcmeChallenge
	err := c.do(ctx, http.MethodGet, acmePath(domainId), nil, &challenges)
	return challenges, err
}

// GetAcmeChallenge returns the ACME challenge record with the given scope and
// value, or an *APIError with code "resourceDoesNotExist" if there is none.
func (c *Client) GetAcmeChallenge(ctx context.Context, domainId int, scope string, value string) ([]AcmeChallenge, error) {
	var challenges []AcmeChallenge
	err := c.do(ctx, http.MethodGet, acmeRecordPath(domainId, scope, value), nil, &challenges)
	return challenges, err
}

// AddAcmeChallenge creates an ACME challenge record. The scope is the record
// name relative to the zone without the _acme-challenge prefix, which the API
// prepends itself, or "@" for the zone apex. The value must be an ACME key
// authorization digest: 43 characters of base64url.
//
// The call is idempotent. Adding a value that is already present succeeds.
func (c *Client) AddAcmeChallenge(ctx context.Context, domainId int, scope string, value string) ([]AcmeChallenge, error) {
	body := struct {
		Scope string `json:"scope"`
		Value string `json:"value"`
	}{Scope: scope, Value: value}

	var challenges []AcmeChallenge
	err := c.do(ctx, http.MethodPost, acmePath(domainId), body, &challenges)
	return challenges, err
}

// DeleteAcmeChallenge removes an ACME challenge record. Removing a record that
// is not present yields an *APIError with code "resourceDoesNotExist"; use
// IsNotFound to treat that as success.
func (c *Client) DeleteAcmeChallenge(ctx context.Context, domainId int, scope string, value string) error {
	return c.do(ctx, http.MethodDelete, acmeRecordPath(domainId, scope, value), nil, nil)
}

func acmePath(domainId int) string {
	return fmt.Sprintf("domain/%d/acme/challenge", domainId)
}

func acmeRecordPath(domainId int, scope string, value string) string {
	return fmt.Sprintf("domain/%d/acme/challenge/%s/%s",
		domainId, url.PathEscape(scope), url.PathEscape(value))
}

func (c *Client) do(ctx context.Context, method string, path string, body interface{}, result interface{}) error {
	var payload io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		payload = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.endpoint+"/"+path, payload)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("unable to read %s %s response: %w", method, path, err)
	}
	// A successful delete answers 204 with no body at all.
	if len(bytes.TrimSpace(raw)) == 0 {
		if resp.StatusCode >= 400 {
			return &APIError{StatusCode: resp.StatusCode, Method: method, Path: path}
		}
		return nil
	}

	var envelope response
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return fmt.Errorf("unable to decode %s %s response: %w", method, path, err)
	}
	if !envelope.Success {
		return &APIError{
			StatusCode: resp.StatusCode,
			Method:     method,
			Path:       path,
			Errors:     envelope.Errors,
		}
	}
	if result != nil && len(envelope.Result) > 0 {
		return json.Unmarshal(envelope.Result, result)
	}
	return nil
}

// ResolveDomain finds the domain of the account that owns the given name, by
// asking for successively shorter suffixes of it, longest match first. A name
// below a delegated subzone therefore resolves to that subzone rather than to
// its parent, and a multi-label public suffix is not mistaken for the zone.
//
// Names that are not in the account yield an *APIError with code
// "resourceDoesNotExist". Any other failure aborts the walk and is returned
// as-is, so an invalid API key is not reported as a missing zone.
//
// This is a convenience over GetDomains, which stays available for callers
// that want to do their own lookup.
func (c *Client) ResolveDomain(ctx context.Context, name string) (*Domain, error) {
	name = strings.TrimSuffix(name, ".")
	for remainder := name; strings.Count(remainder, ".") >= 1; {
		domains, err := c.GetDomains(ctx, remainder)
		switch {
		case err == nil && len(domains) > 0:
			return &domains[0], nil
		case err == nil, IsNotFound(err):
			// Not a domain of this account, try the next shorter suffix.
		default:
			return nil, err
		}
		_, remainder, _ = strings.Cut(remainder, ".")
	}
	return nil, &APIError{
		Method: http.MethodGet,
		Path:   "domain",
		Errors: []Message{{
			Code:    CodeResourceDoesNotExist,
			Message: fmt.Sprintf("no domain of this account owns %q", name),
		}},
	}
}

// AcmeChallengePrefix is the label the API prepends to a challenge scope. A
// name passed to AcmeScope is expected to carry it.
const AcmeChallengePrefix = "_acme-challenge."

// AcmeScope derives the scope of an ACME challenge record from its fully
// qualified name and the zone that owns it, as returned by ResolveDomain.
// Trailing dots on either argument are ignored.
//
// The scope is the part between the _acme-challenge prefix and the zone, or
// "@" when the challenge sits at the zone apex:
//
//	_acme-challenge.example.com      in example.com  ->  "@"
//	_acme-challenge.host.example.com in example.com  ->  "host"
//
// The prefix is required: the API prepends it itself, so passing a name
// without it would create the record one label too deep.
func AcmeScope(fqdn string, zone string) (string, error) {
	fqdn = strings.TrimSuffix(fqdn, ".")
	zone = strings.TrimSuffix(zone, ".")

	rest, found := strings.CutPrefix(fqdn, AcmeChallengePrefix)
	if !found {
		return "", fmt.Errorf("%q is not an ACME challenge name: expected the prefix %q", fqdn, AcmeChallengePrefix)
	}
	if rest == zone {
		return "@", nil
	}
	scope, found := strings.CutSuffix(rest, "."+zone)
	if !found || scope == "" {
		return "", fmt.Errorf("%q does not lie in the zone %q", fqdn, zone)
	}
	return scope, nil
}
