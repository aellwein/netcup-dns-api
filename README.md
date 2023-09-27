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


License
-------

[MIT License](LICENSE)
