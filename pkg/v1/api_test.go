package v1

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLogin(t *testing.T) {
	ts := withTestServer()
	defer ts.Close()

	client := NewNetcupDnsClientWithOptions(1234567, "someKey", "somePass", &NetcupDnsClientOptions{ApiEndpoint: ts.URL, ClientRequestId: "someid"})
	sess, err := client.Login()
	assert.NoError(t, err)
	assert.Equal(t, "1337", sess.apiSessionId)
}

func TestLogout(t *testing.T) {
	ts := withTestServer()
	defer ts.Close()

	client := NewNetcupDnsClientWithOptions(1234567, "someKey", "somePass", &NetcupDnsClientOptions{ApiEndpoint: ts.URL, ClientRequestId: "someid"})
	sess, err := client.Login()
	assert.NoError(t, err)
	err = sess.Logout()
	assert.NoError(t, err)
}

func TestInfoDnsZone(t *testing.T) {
	ts := withTestServer()
	defer ts.Close()

	client := NewNetcupDnsClientWithOptions(1234567, "someKey", "somePass", &NetcupDnsClientOptions{ApiEndpoint: ts.URL, ClientRequestId: "someid"})
	sess, err := client.Login()
	assert.NoError(t, err)
	dns, err := sess.InfoDnsZone("example.org")
	assert.Equal(t, "example.org", dns.DomainName)
	assert.Equal(t, "1209600", dns.Expire)
}

func TestInfoDnsRecords(t *testing.T) {
	ts := withTestServer()
	defer ts.Close()

	client := NewNetcupDnsClientWithOptions(1234567, "someKey", "somePass", &NetcupDnsClientOptions{ApiEndpoint: ts.URL, ClientRequestId: "someid"})
	sess, err := client.Login()
	assert.NoError(t, err)
	dnsRecs, err := sess.InfoDnsRecords("example.org")
	assert.NoError(t, err)
	assert.NotEmpty(t, dnsRecs)
}

func TestUpdateDnsZone(t *testing.T) {
	ts := withTestServer()
	defer ts.Close()

	client := NewNetcupDnsClientWithOptions(1234567, "someKey", "somePass", &NetcupDnsClientOptions{ApiEndpoint: ts.URL, ClientRequestId: "someid"})
	sess, err := client.Login()
	assert.NoError(t, err)
	zone, err := sess.InfoDnsZone("example.org")
	assert.NoError(t, err)
	assert.Equal(t, "3600", zone.Ttl)

	zone.Ttl = "3601"

	zone2, err := sess.UpdateDnsZone("example.org", zone)
	assert.NoError(t, err)
	assert.Equal(t, "3601", zone2.Ttl)
}

func TestUpdateDnsRecords(t *testing.T) {
	ts := withTestServer()
	defer ts.Close()

	client := NewNetcupDnsClientWithOptions(1234567, "someKey", "somePass", &NetcupDnsClientOptions{ApiEndpoint: ts.URL, ClientRequestId: "someid"})
	sess, err := client.Login()
	assert.NoError(t, err)

	record := &DnsRecord{
		Id:           "",
		Hostname:     "subdomain",
		Type:         "TXT",
		Priority:     "0",
		Destination:  "test",
		DeleteRecord: false,
		State:        "yes",
	}

	recs, err := sess.UpdateDnsRecords("example.org", &[]DnsRecord{
		*record,
	})
	assert.NoError(t, err)
	assert.ElementsMatch(t, []DnsRecord{*record}, *recs)
}

func TestStringerImplsAreReturningValidJson(t *testing.T) {
	dnsZone := &DnsZoneData{
		DomainName:   "example.org",
		Ttl:          "3600",
		Serial:       "3423083",
		Refresh:      "28800",
		Retry:        "7200",
		Expire:       "1209600",
		DnsSecStatus: false,
	}
	nbr := &NetcupBaseResponseMessage{
		ServerRequestId: "serverid",
		ClientRequestId: "clientreqid",
		Action:          "action",
		Status:          "status",
		StatusCode:      200,
		ShortMessage:    "short",
		LongMessage:     "long",
	}

	sess := &NetcupSession{
		apiSessionId:   "apisess",
		apiKey:         "apikey",
		customerNumber: 12345,
		endpoint:       "netcup",
		LastResponse:   nbr,
	}
	dnsRecord := &DnsRecord{
		Id:           "392",
		Hostname:     "host.net",
		Type:         "MX",
		Priority:     "10",
		Destination:  "127.0.0.1",
		DeleteRecord: false,
		State:        "yes",
	}
	output := make(map[string]any)
	err := json.NewDecoder(strings.NewReader(dnsZone.String())).Decode(&output)
	assert.NoError(t, err)
	output = make(map[string]any)
	err = json.NewDecoder(strings.NewReader(nbr.String())).Decode(&output)
	assert.NoError(t, err)
	output = make(map[string]any)
	err = json.NewDecoder(strings.NewReader(sess.String())).Decode(&output)
	assert.NoError(t, err)
	output = make(map[string]any)
	err = json.NewDecoder(strings.NewReader(dnsRecord.String())).Decode(&output)
	assert.NoError(t, err)
}

func withTestServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dec := json.NewDecoder(r.Body)
		type UniBody struct {
			Action string         `json:"action"`
			Params map[string]any `json:"param"`
		}
		// we use a map as "uni-body" payload receiver to cope with any possible request type.
		ub := &UniBody{
			Params: make(map[string]any),
		}
		err := dec.Decode(ub)
		if err != nil {
			http.Error(w, fmt.Sprintf("unable to decode payload: %v", err), 400)
			return
		}

		switch ub.Action {
		case string(actionLogin):
			w.Header().Set("Content-Type", "application/json")
			resp := &LoginResponsePayload{
				ResponseData: &LoginResponseData{
					ApiSessionId: "1337",
				},
			}
			enc := json.NewEncoder(w)
			if err := enc.Encode(resp); err != nil {
				panic(err)
			}
			return

		case string(actionLogout):
			resp := make(map[string]string)
			enc := json.NewEncoder(w)
			if err := enc.Encode(resp); err != nil {
				panic(err)
			}
			return

		case string(actionInfoDnsRecords):
			if ub.Params["domainname"] != "example.org" {
				http.Error(w, "not found", 404)
			}
			resp := &InfoDnsRecordsResponsePayload{
				ResponseData: &InfoDnsRecordsResponseData{
					DnsRecords: []DnsRecord{
						{
							Id:           "1234",
							Hostname:     "www",
							Type:         "A",
							Priority:     "10",
							Destination:  "127.0.0.1",
							DeleteRecord: false,
							State:        "yes",
						},
						{
							Id:           "12345",
							Hostname:     "subdomain",
							Type:         "A",
							Priority:     "10",
							Destination:  "127.0.0.1",
							DeleteRecord: false,
							State:        "yes",
						},
					},
				},
			}
			enc := json.NewEncoder(w)
			if err := enc.Encode(resp); err != nil {
				panic(err)
			}
			return

		case string(actionInfoDnsZone):
			if ub.Params["domainname"] != "example.org" {
				http.Error(w, "not found", 404)
			}
			resp := &InfoDnsZoneResponsePayload{
				ResponseData: &DnsZoneData{
					DomainName:   "example.org",
					Ttl:          "3600",
					Serial:       "3423083",
					Refresh:      "28800",
					Retry:        "7200",
					Expire:       "1209600",
					DnsSecStatus: false,
				},
			}
			enc := json.NewEncoder(w)
			if err := enc.Encode(resp); err != nil {
				panic(err)
			}
			return

		case string(actionUpdateDnsZone):
			if ub.Params["domainname"] != "example.org" {
				http.Error(w, "not found", 404)
			}
			dnsZoneResp := &DnsZoneData{
				DomainName:   ub.Params["dnszone"].(map[string]any)["name"].(string),
				Ttl:          ub.Params["dnszone"].(map[string]any)["ttl"].(string),
				Serial:       ub.Params["dnszone"].(map[string]any)["serial"].(string),
				Refresh:      ub.Params["dnszone"].(map[string]any)["refresh"].(string),
				Retry:        ub.Params["dnszone"].(map[string]any)["retry"].(string),
				Expire:       ub.Params["dnszone"].(map[string]any)["expire"].(string),
				DnsSecStatus: ub.Params["dnszone"].(map[string]any)["dnssecstatus"].(bool),
			}
			resp := &UpdateDnsZoneResponsePayload{
				ResponseData: dnsZoneResp,
			}
			enc := json.NewEncoder(w)
			if err := enc.Encode(resp); err != nil {
				panic(err)
			}
			return

		case string(actionUpdateDnsRecords):
			if ub.Params["domainname"] != "example.org" {
				http.Error(w, "not found", 404)
			}
			recs := castToDnsRecords(ub.Params["dnsrecordset"].(map[string]any)["dnsrecords"].([]interface{}))

			resp := &UpdateDnsRecordsResponsePayload{
				ResponseData: &UpdateDnsRecordsResponseData{
					DnsRecords: *recs,
				},
			}
			enc := json.NewEncoder(w)
			if err := enc.Encode(resp); err != nil {
				panic(err)
			}
			return

		default:
			http.Error(w, fmt.Sprintf("unknown action: %s", ub.Action), 400)
			return
		}

	}))
}

func castToDnsRecords(r []interface{}) *[]DnsRecord {
	res := make([]DnsRecord, 0)
	for _, i := range r {
		m := i.(map[string]any)
		rec := DnsRecord{
			Id:           m["id"].(string),
			Hostname:     m["hostname"].(string),
			Type:         m["type"].(string),
			Priority:     m["priority"].(string),
			Destination:  m["destination"].(string),
			DeleteRecord: m["deleterecord"].(bool),
			State:        m["state"].(string),
		}
		res = append(res, rec)
	}
	return &res
}
