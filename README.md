![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/aellwein/netcup-dns-api/go.yml?branch=main)
[![Go Report Card](https://goreportcard.com/badge/github.com/aellwein/netcup-dns-api)](https://goreportcard.com/report/github.com/aellwein/netcup-dns-api)
[![Codecov branch](https://img.shields.io/codecov/c/github/aellwein/netcup-dns-api/main)](https://app.codecov.io/gh/aellwein/netcup-dns-api)
![GitHub](https://img.shields.io/github/license/aellwein/netcup-dns-api)
![GitHub release (latest SemVer)](https://img.shields.io/github/v/release/aellwein/netcup-dns-api)

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

License
-------

[MIT License](LICENSE)
