![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/aellwein/netcup-dns-api/go.yml?branch=main)
[![codecov](https://codecov.io/gh/aellwein/netcup-dns-api/graph/badge.svg?token=JWDZP4JX2P)](https://codecov.io/gh/aellwein/netcup-dns-api)
![GitHub](https://img.shields.io/github/license/aellwein/netcup-dns-api)
[![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/aellwein/netcup-dns-api)](https://github.com/aellwein/netcup-dns-api/releases/latest)

netcup-dns-api
==============

Implementation for [netcup DNS API](https://www.netcup-wiki.de/wiki/DNS_API) in Golang.

All DNS API is implemented:
* ``login``
* ``logout``
* ``infoDnsZone``
* ``infoDnsRecords``
* ``updateDnsZone``
* ``updateDnsRecords``


Example Usage
-------------

```golang
import (
	"log"

	netcup "github.com/aellwein/netcup-dns-api/pkg/v1"
)

func main() {
	client := netcup.NewNetcupDnsClient(12345, "myApiKey", "mySecretApiPassword")

	// Login to the API
	session, err := client.Login()
	if err != nil {
		panic(err)
	}
	defer session.Logout()

	if zone, err := session.InfoDnsZone("myowndomain.org"); err != nil {
		panic(err)
	} else {
		log.Println("DNS zone:", zone)
	}
}
```
This should give you an output like:
```
DNS zone: { "DomainName": "myowndomain.org", "Ttl": "...", "Serial": "...", "Refresh": "...", "Retry": "...", "Expire": "...", "DnsSecStatus": false
```

Error Handling
--------------

Usually one would expect an ``err`` set only in case of a "hard" or _non-recoverable_ error. This is true 
for a technical type of error, like failed REST API call or a broken network connection, but the 
Netcup API may set status to "error" in some cases, where you would rather 
[assume a warning](https://github.com/mrueg/external-dns-netcup-webhook/issues/5#issuecomment-1913528766).
In such case, the last response from Netcup API is preserved inside the ``NetcupSession`` and can be examined: 

```golang
recs, err := session.InfoDnsRecords("myowndomain.org")
if err != nil {
	if session.LastResponse != nil && 
		sess.LastResponse.Status == string(netcup.StatusError) &&
		sess.LastResponse.StatusCode == 5029 {
			// no records are found in the DNS zone - Netcup indicates an error here.
			println("no error")
		} else {
			return fmt.Errorf("non-recoverable error on InfoDnsRecords: %v", err)
		}
}
```

New netcup REST API
-------------------

``pkg/rest/v1`` implements netcup's newer REST API at ``https://api.netcup.com/v1``,
used for domains on their current DNS backend. It is a separate client: the REST API
authenticates with a single bearer token, keeps no session, and addresses zones by a
numeric id, so nothing is shared with the legacy CCP client above.

Currently the ACME challenge endpoints are implemented, along with the domain lookup
they need. The general record surface (zone revisions and changesets) is not covered yet.

```golang
import (
	"context"
	"log"

	netcup "github.com/aellwein/netcup-dns-api/pkg/rest/v1"
)

func main() {
	client := netcup.NewClient("myApiKey", nil)
	ctx := context.Background()

	// The ACME key authorization digest, 43 characters of base64url. With
	// cert-manager this is the Key of the ChallengeRequest.
	digest := "odeFPdrsdv0DkYkJO27cpRGWydB05G9xxXJa9QZwv2Q"

	// Find the zone that owns the challenge name, longest match first, so a
	// delegated subzone wins over its parent.
	domain, err := client.ResolveDomain(ctx, "_acme-challenge.host.myowndomain.org")
	if err != nil {
		panic(err)
	}

	scope, err := netcup.AcmeScope("_acme-challenge.host.myowndomain.org", domain.Fqdn)
	if err != nil {
		panic(err)
	}

	// Adding is idempotent, so this may be called repeatedly for the same value.
	if _, err := client.AddAcmeChallenge(ctx, domain.Id, scope, digest); err != nil {
		panic(err)
	}
	log.Println("challenge record created")

	if err := client.DeleteAcmeChallenge(ctx, domain.Id, scope, digest); err != nil && !netcup.IsNotFound(err) {
		panic(err)
	}
}
```

Errors from the API are returned as ``*APIError``, which carries the HTTP status and the
messages verbatim. Branch on the code rather than the HTTP status or the message text: an
invalid API key is answered with HTTP 400 rather than 401, and the human-readable messages
are reused generics.

```golang
if _, err := client.GetDomains(ctx, "myowndomain.org"); err != nil {
	switch {
	case netcup.IsAuthError(err):
		// the API key was rejected
	case netcup.IsNotFound(err):
		// no such domain in this account
	default:
		var apiErr *netcup.APIError
		if errors.As(err, &apiErr) {
			log.Println("netcup reported:", apiErr.Errors)
		}
	}
}
```

Note on deployment: a created challenge record reports ``status: "deployed"`` within a
second or two, but only becomes resolvable on the authoritative nameservers roughly a
minute later, and not on all of them at once. The status is therefore not a signal that
the challenge is ready to be validated; check DNS if you need to know that.

License
-------

[MIT License](LICENSE)
