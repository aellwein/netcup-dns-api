package v1

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLogin(t *testing.T) {
	ts := withTestServer(
		successfulLoginRequest(),
		successfulLoginResponse(),
	)
	defer ts.Close()

	client := NewNetcupDnsClientWithOptions(1234567, "someKey", "somePass", &NetcupDnsClientOptions{ApiEndpoint: ts.URL, ClientRequestId: "someId"})
	sess, err := client.Login()

	assert.NoError(t, err)
	assert.Equal(t, string(StatusSuccess), sess.LastResponse.Status)
	assert.NotEmpty(t, sess.apiSessionId)
}

func TestLoginFailed(t *testing.T) {
	ts := withTestServer(
		successfulLoginRequest(),
		unsuccessfulLoginResponse(),
	)
	defer ts.Close()

	client := NewNetcupDnsClientWithOptions(1234567, "someKey", "somePass", &NetcupDnsClientOptions{ApiEndpoint: ts.URL, ClientRequestId: "someId"})
	_, err := client.Login()

	assert.Error(t, err)
	assert.ErrorContains(t, err, "Login failed")
}

func TestLogout(t *testing.T) {
	ts := withTestServer(
		successfulLoginRequest(),
		successfulLoginResponse(),
		successfulLogoutRequest(),
		successfulLogoutResponse(),
	)
	defer ts.Close()

	client := NewNetcupDnsClientWithOptions(1234567, "someKey", "somePass", &NetcupDnsClientOptions{ApiEndpoint: ts.URL, ClientRequestId: "someId"})
	sess, err := client.Login()
	assert.NoError(t, err)

	err = sess.Logout()
	assert.NoError(t, err)
}

func TestInfoDnsZone(t *testing.T) {
	ts := withTestServer(
		successfulLoginRequest(),
		successfulLoginResponse(),
		successfulInfoDnsZoneRequest(),
		successfulInfoDnsZoneResponse(),
		successfulLogoutRequest(),
		successfulLogoutResponse(),
	)
	defer ts.Close()

	client := NewNetcupDnsClientWithOptions(1234567, "someKey", "somePass", &NetcupDnsClientOptions{ApiEndpoint: ts.URL, ClientRequestId: "someId"})
	sess, err := client.Login()
	assert.NoError(t, err)
	defer sess.Logout()

	dns, err := sess.InfoDnsZone("example.org")
	assert.NoError(t, err)
	assert.Equal(t, "example.org", dns.DomainName)
	assert.Equal(t, "1209600", dns.Expire)
}

func TestInfoDnsZoneFailed(t *testing.T) {
	ts := withTestServer(
		successfulLoginRequest(),
		successfulLoginResponse(),
		unsuccessfulInfoDnsZoneRequest(),
		unsuccessfulInfoDnsZoneResponse(),
		successfulLogoutRequest(),
		successfulLogoutResponse(),
	)
	defer ts.Close()

	client := NewNetcupDnsClientWithOptions(1234567, "someKey", "somePass", &NetcupDnsClientOptions{ApiEndpoint: ts.URL, ClientRequestId: "someId"})
	sess, err := client.Login()
	assert.NoError(t, err)
	defer sess.Logout()

	_, err = sess.InfoDnsZone("wrongdomain.org")

	assert.Error(t, err)
	assert.ErrorContains(t, err, "InfoDnsZone failed")
}

func TestInfoDnsRecords(t *testing.T) {
	ts := withTestServer(
		successfulLoginRequest(),
		successfulLoginResponse(),
		successfulInfoDnsRecordsRequest(),
		successfulInfoDnsRecordsResponse(),
		successfulLogoutRequest(),
		successfulLogoutResponse(),
	)
	defer ts.Close()

	client := NewNetcupDnsClientWithOptions(1234567, "someKey", "somePass", &NetcupDnsClientOptions{ApiEndpoint: ts.URL, ClientRequestId: "someId"})
	sess, err := client.Login()
	assert.NoError(t, err)
	defer sess.Logout()

	dnsRecs, err := sess.InfoDnsRecords("example.org")

	assert.NoError(t, err)
	assert.NotEmpty(t, dnsRecs)
}

func TestInfoDnsRecordsFailed(t *testing.T) {
	ts := withTestServer(
		successfulLoginRequest(),
		successfulLoginResponse(),
		unsuccessfulInfoDnsRecordsRequest(),
		unsuccessfulInfoDnsRecordsResponse(),
		successfulLogoutRequest(),
		successfulLogoutResponse(),
	)
	defer ts.Close()

	client := NewNetcupDnsClientWithOptions(1234567, "someKey", "somePass", &NetcupDnsClientOptions{ApiEndpoint: ts.URL, ClientRequestId: "someId"})
	sess, err := client.Login()
	assert.NoError(t, err)
	defer sess.Logout()

	_, err = sess.InfoDnsRecords("wrongdomain.org")

	assert.Error(t, err)
	assert.ErrorContains(t, err, "InfoDnsRecords failed")
}

func TestUpdateDnsZone(t *testing.T) {
	ts := withTestServer(
		successfulLoginRequest(),
		successfulLoginResponse(),
		successfulInfoDnsZoneRequest(),
		successfulInfoDnsZoneResponse(),
		successfulUpdateDnsZoneRequest(),
		successfulUpdateDnsZoneResponse(),
		successfulLogoutRequest(),
		successfulLogoutResponse(),
	)
	defer ts.Close()

	client := NewNetcupDnsClientWithOptions(1234567, "someKey", "somePass", &NetcupDnsClientOptions{ApiEndpoint: ts.URL, ClientRequestId: "someId"})
	sess, err := client.Login()
	assert.NoError(t, err)
	defer sess.Logout()

	zone, err := sess.InfoDnsZone("example.org")
	assert.NoError(t, err)
	assert.Equal(t, "3600", zone.Ttl)

	zone.Ttl = "3601"

	zone2, err := sess.UpdateDnsZone("example.org", zone)
	assert.NoError(t, err)
	assert.Equal(t, "3601", zone2.Ttl)
}

func TestUpdateDnsZoneFailed(t *testing.T) {
	ts := withTestServer(
		successfulLoginRequest(),
		successfulLoginResponse(),
		unsuccessfulUpdateDnsZoneRequest(),
		unsuccessfulUpdateDnsZoneResponse(),
		successfulLogoutRequest(),
		successfulLogoutResponse(),
	)
	defer ts.Close()

	client := NewNetcupDnsClientWithOptions(1234567, "someKey", "somePass", &NetcupDnsClientOptions{ApiEndpoint: ts.URL, ClientRequestId: "someId"})
	sess, err := client.Login()
	assert.NoError(t, err)
	defer sess.Logout()

	zone := &DnsZoneData{
		DomainName:   "wrongdomain.org",
		Ttl:          "3601",
		Serial:       "3423083",
		Refresh:      "28800",
		Retry:        "7200",
		Expire:       "1209600",
		DnsSecStatus: false,
	}
	_, err = sess.UpdateDnsZone("wrongdomain.org", zone)

	assert.Error(t, err)
	assert.ErrorContains(t, err, "UpdateDnsZone failed")
}

func TestUpdateDnsRecords(t *testing.T) {
	ts := withTestServer(
		successfulLoginRequest(),
		successfulLoginResponse(),
		successfulInfoDnsRecordsRequest(),
		successfulInfoDnsRecordsResponse(),
		successfulUpdateDnsRecordsRequest(),
		successfulUpdateDnsRecordsResponse(),
		successfulLogoutRequest(),
		successfulLogoutResponse(),
	)
	defer ts.Close()

	client := NewNetcupDnsClientWithOptions(1234567, "someKey", "somePass", &NetcupDnsClientOptions{ApiEndpoint: ts.URL, ClientRequestId: "someId"})
	sess, err := client.Login()
	assert.NoError(t, err)
	defer sess.Logout()

	inRecs, err := sess.InfoDnsRecords("example.org")
	assert.NoError(t, err)
	assert.Equal(t, 2, len(*inRecs))

	(*inRecs)[1].DeleteRecord = true // second record is supposed to be deleted

	outRecs, err := sess.UpdateDnsRecords("example.org", inRecs)
	assert.NoError(t, err)

	assert.Equal(t, 1, len(*outRecs))
}

func TestUpdateDnsRecordsFailed(t *testing.T) {
	ts := withTestServer(
		successfulLoginRequest(),
		successfulLoginResponse(),
		unsuccessfulUpdateDnsRecordsRequest(),
		unsuccessfulUpdateDnsRecordsResponse(),
		successfulLogoutRequest(),
		successfulLogoutResponse(),
	)
	defer ts.Close()

	client := NewNetcupDnsClientWithOptions(1234567, "someKey", "somePass", &NetcupDnsClientOptions{ApiEndpoint: ts.URL, ClientRequestId: "someId"})
	sess, err := client.Login()
	assert.NoError(t, err)
	defer sess.Logout()

	_, err = sess.UpdateDnsRecords("wrongdomain.org", &[]DnsRecord{
		{
			Id:           "1234",
			Hostname:     "www",
			Type:         "A",
			Priority:     "10",
			Destination:  "127.0.0.1",
			DeleteRecord: false,
			State:        "yes",
		},
	})

	assert.Error(t, err)
	assert.ErrorContains(t, err, "UpdateDnsRecords failed")
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
	output := make(map[string]interface{})
	err := json.NewDecoder(strings.NewReader(dnsZone.String())).Decode(&output)
	assert.NoError(t, err)
	output = make(map[string]interface{})
	err = json.NewDecoder(strings.NewReader(nbr.String())).Decode(&output)
	assert.NoError(t, err)
	output = make(map[string]interface{})
	err = json.NewDecoder(strings.NewReader(sess.String())).Decode(&output)
	assert.NoError(t, err)
	output = make(map[string]interface{})
	err = json.NewDecoder(strings.NewReader(dnsRecord.String())).Decode(&output)
	assert.NoError(t, err)
}

func successfulLoginRequest() *LoginPayload {
	return &LoginPayload{
		Action: actionLogin,
		Params: &LoginParams{
			CustomerNumber:  1234567,
			ApiKey:          "someKey",
			ApiPassword:     "somePass",
			ClientRequestId: "someId",
		},
	}
}

func successfulLoginResponse() *LoginResponsePayload {
	return &LoginResponsePayload{
		NetcupBaseResponseMessage: NetcupBaseResponseMessage{
			ServerRequestId: "xyz",
			ClientRequestId: "someId",
			Action:          string(actionLogin),
			Status:          string(StatusSuccess),
			StatusCode:      200,
			ShortMessage:    "Ok",
			LongMessage:     "Login was ok",
		},
		ResponseData: &LoginResponseData{
			ApiSessionId: "1337",
		},
	}
}

func unsuccessfulLoginResponse() map[string]interface{} {
	return map[string]interface{}{
		"serverrequestid": "xyz",
		"clientrequestid": "someId",
		"action":          actionLogin,
		"status":          string(StatusError),
		"statuscode":      400,
		"shortmessage":    "invalid credentials",
		"longmessage":     "invalid credentials",
		"responsedata":    "",
	}
}

func successfulLogoutRequest() *BasePayload {
	return &BasePayload{
		Action: actionLogout,
		Params: &NetcupBaseParams{
			CustomerNumber:  1234567,
			ApiSessionId:    "1337",
			ApiKey:          "someKey",
			ClientRequestId: "someId",
		},
	}
}

// we don't have an explicit type for logout response...
func successfulLogoutResponse() map[string]interface{} {
	return map[string]interface{}{
		"action":     string(actionLogout),
		"statuscode": string(StatusSuccess),
	}
}

func successfulInfoDnsZoneRequest() *InfoDnsZonePayload {
	return &InfoDnsZonePayload{
		Action: actionInfoDnsZone,
		Params: &InfoDnsZoneParams{
			NetcupBaseParams: NetcupBaseParams{
				CustomerNumber:  1234567,
				ApiSessionId:    "1337",
				ApiKey:          "someKey",
				ClientRequestId: "someId",
			},
			DomainName: "example.org",
		},
	}
}

func unsuccessfulInfoDnsZoneRequest() *InfoDnsZonePayload {
	return &InfoDnsZonePayload{
		Action: actionInfoDnsZone,
		Params: &InfoDnsZoneParams{
			NetcupBaseParams: NetcupBaseParams{
				CustomerNumber:  1234567,
				ApiSessionId:    "1337",
				ApiKey:          "someKey",
				ClientRequestId: "someId",
			},
			DomainName: "wrongdomain.org",
		},
	}
}

func successfulInfoDnsZoneResponse() *InfoDnsZoneResponsePayload {
	return &InfoDnsZoneResponsePayload{
		NetcupBaseResponseMessage: NetcupBaseResponseMessage{
			Action:          string(actionInfoDnsZone),
			ServerRequestId: "xyz",
			ClientRequestId: "someId",
			Status:          string(StatusSuccess),
			StatusCode:      200,
			ShortMessage:    "",
			LongMessage:     "",
		},
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
}

func unsuccessfulInfoDnsZoneResponse() map[string]interface{} {
	return map[string]interface{}{
		"action":          string(actionInfoDnsZone),
		"serverrequestid": "xyz",
		"clientrequestid": "someId",
		"status":          string(StatusError),
		"statuscode":      400,
		"shortmessage":    "invalid domain name",
		"longmessage":     "invalid domain name provided",
		"responsedata":    "",
	}
}

func successfulInfoDnsRecordsRequest() *InfoDnsRecordsPayload {
	return &InfoDnsRecordsPayload{
		Action: actionInfoDnsRecords,
		Params: &InfoDnsRecordsParams{
			NetcupBaseParams: NetcupBaseParams{
				CustomerNumber:  1234567,
				ApiSessionId:    "1337",
				ApiKey:          "someKey",
				ClientRequestId: "someId",
			},
			DomainName: "example.org",
		},
	}
}

func unsuccessfulInfoDnsRecordsRequest() *InfoDnsRecordsPayload {
	return &InfoDnsRecordsPayload{
		Action: actionInfoDnsRecords,
		Params: &InfoDnsRecordsParams{
			NetcupBaseParams: NetcupBaseParams{
				CustomerNumber:  1234567,
				ApiSessionId:    "1337",
				ApiKey:          "someKey",
				ClientRequestId: "someId",
			},
			DomainName: "wrongdomain.org",
		},
	}
}

func successfulInfoDnsRecordsResponse() *InfoDnsRecordsResponsePayload {
	return &InfoDnsRecordsResponsePayload{
		NetcupBaseResponseMessage: NetcupBaseResponseMessage{
			ServerRequestId: "xyz",
			ClientRequestId: "someId",
			Action:          string(actionInfoDnsRecords),
			Status:          string(StatusSuccess),
			StatusCode:      200,
			ShortMessage:    "request ok",
			LongMessage:     "whatever a long message is",
		},
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
}

func unsuccessfulInfoDnsRecordsResponse() map[string]interface{} {
	return map[string]interface{}{
		"action":          string(actionInfoDnsRecords),
		"serverrequestid": "xyz",
		"clientrequestid": "someId",
		"status":          string(StatusError),
		"statuscode":      400,
		"shortmessage":    "invalid domain name",
		"longmessage":     "invalid domain name provided",
		"responsedata":    "",
	}
}

func successfulUpdateDnsZoneRequest() *UpdateDnsZonePayload {
	return &UpdateDnsZonePayload{
		Action: actionUpdateDnsZone,
		Params: &UpdateDnsZoneParams{
			NetcupBaseParams: NetcupBaseParams{
				CustomerNumber:  1234567,
				ApiSessionId:    "1337",
				ApiKey:          "someKey",
				ClientRequestId: "someId",
			},
			DomainName: "example.org",
			DnsZone: &DnsZoneData{
				DomainName:   "example.org",
				Ttl:          "3601",
				Serial:       "3423083",
				Refresh:      "28800",
				Retry:        "7200",
				Expire:       "1209600",
				DnsSecStatus: false,
			},
		},
	}
}

func unsuccessfulUpdateDnsZoneRequest() *UpdateDnsZonePayload {
	return &UpdateDnsZonePayload{
		Action: actionUpdateDnsZone,
		Params: &UpdateDnsZoneParams{
			NetcupBaseParams: NetcupBaseParams{
				CustomerNumber:  1234567,
				ApiSessionId:    "1337",
				ApiKey:          "someKey",
				ClientRequestId: "someId",
			},
			DomainName: "wrongdomain.org",
			DnsZone: &DnsZoneData{
				DomainName:   "wrongdomain.org",
				Ttl:          "3601",
				Serial:       "3423083",
				Refresh:      "28800",
				Retry:        "7200",
				Expire:       "1209600",
				DnsSecStatus: false,
			},
		},
	}
}

func successfulUpdateDnsZoneResponse() *UpdateDnsZoneResponsePayload {
	return &UpdateDnsZoneResponsePayload{
		NetcupBaseResponseMessage: NetcupBaseResponseMessage{
			ServerRequestId: "xyz",
			ClientRequestId: "someId",
			Action:          string(actionUpdateDnsZone),
			Status:          string(StatusSuccess),
			StatusCode:      200,
			ShortMessage:    "update was ok",
			LongMessage:     "Update of the DNS zone was done correctly",
		},
		ResponseData: &DnsZoneData{
			DomainName:   "example.org",
			Ttl:          "3601",
			Serial:       "3423083",
			Refresh:      "28800",
			Retry:        "7200",
			Expire:       "1209600",
			DnsSecStatus: false,
		},
	}
}

func unsuccessfulUpdateDnsZoneResponse() map[string]interface{} {
	return map[string]interface{}{
		"action":          string(actionUpdateDnsRecords),
		"serverrequestid": "xyz",
		"clientrequestid": "someId",
		"status":          string(StatusError),
		"statuscode":      400,
		"shortmessage":    "invalid domain name",
		"longmessage":     "invalid domain name provided",
		"responsedata":    "",
	}
}

func successfulUpdateDnsRecordsRequest() *UpdateDnsRecordsPayload {
	return &UpdateDnsRecordsPayload{
		Action: actionUpdateDnsRecords,
		Params: &UpdateDnsRecordsParams{
			NetcupBaseParams: NetcupBaseParams{
				CustomerNumber:  1234567,
				ApiSessionId:    "1337",
				ApiKey:          "someKey",
				ClientRequestId: "someId",
			},
			DomainName: "example.org",
			DnsRecords: &DnsRecordSet{
				Content: []DnsRecord{
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
						DeleteRecord: true,
						State:        "yes",
					},
				},
			},
		},
	}
}

func unsuccessfulUpdateDnsRecordsRequest() *UpdateDnsRecordsPayload {
	return &UpdateDnsRecordsPayload{
		Action: actionUpdateDnsRecords,
		Params: &UpdateDnsRecordsParams{
			NetcupBaseParams: NetcupBaseParams{
				CustomerNumber:  1234567,
				ApiSessionId:    "1337",
				ApiKey:          "someKey",
				ClientRequestId: "someId",
			},
			DomainName: "wrongdomain.org",
			DnsRecords: &DnsRecordSet{
				Content: []DnsRecord{
					{
						Id:           "1234",
						Hostname:     "www",
						Type:         "A",
						Priority:     "10",
						Destination:  "127.0.0.1",
						DeleteRecord: false,
						State:        "yes",
					},
				},
			},
		},
	}
}

func successfulUpdateDnsRecordsResponse() *UpdateDnsRecordsResponsePayload {
	return &UpdateDnsRecordsResponsePayload{
		NetcupBaseResponseMessage: NetcupBaseResponseMessage{
			ServerRequestId: "xyz",
			ClientRequestId: "someId",
			Action:          string(actionUpdateDnsRecords),
			Status:          string(StatusSuccess),
			StatusCode:      200,
			ShortMessage:    "update ok",
			LongMessage:     "DNS records were updated",
		},
		ResponseData: &UpdateDnsRecordsResponseData{
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
			},
		},
	}
}

func unsuccessfulUpdateDnsRecordsResponse() map[string]interface{} {
	return map[string]interface{}{
		"action":          string(actionUpdateDnsRecords),
		"serverrequestid": "xyz",
		"clientrequestid": "someId",
		"status":          string(StatusError),
		"statuscode":      400,
		"shortmessage":    "invalid domain name",
		"longmessage":     "invalid domain name provided",
		"responsedata":    "",
	}
}

func withTestServer(reqResp ...interface{}) *httptest.Server {
	var reqIdx int
	var reqIdxP *int = &reqIdx

	if len(reqResp) == 0 || len(reqResp)%2 != 0 {
		panic("expected sequence of request and response payloads (both mandatory)")
	}
	serv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if *reqIdxP >= len(reqResp) {
			http.Error(w, fmt.Sprintf("Too much requests as expected: %d, expected: %d", *reqIdxP, len(reqResp)/2), 500)
			return
		}
		req := reqResp[*reqIdxP]
		resp := reqResp[*reqIdxP+1]
		*reqIdxP = *reqIdxP + 2

		expectedReq := toAnyJson(&req)
		dec := json.NewDecoder(r.Body)
		receivedReq := make(map[string]interface{})
		if err := dec.Decode(&receivedReq); err != nil {
			http.Error(w, fmt.Sprintf("unable to decode incoming request: %v", err), 400)
			return
		}
		if !reflect.DeepEqual(expectedReq, receivedReq) {
			http.Error(w, fmt.Sprintf("request is not as expected:\nexpected:\n%v\nreceived:\n%v", expectedReq, receivedReq), 400)
			return
		}
		enc := json.NewEncoder(w)
		if err := enc.Encode(resp); err != nil {
			http.Error(w, fmt.Sprintf("unable to encode response: %v", err), 400)
			return
		}
	}))
	return serv
}

func toAnyJson(someStruct *interface{}) map[string]interface{} {
	if b, err := json.Marshal(*someStruct); err != nil {
		panic(err)
	} else {
		result := make(map[string]interface{})
		if err := json.Unmarshal(b, &result); err != nil {
			panic(err)
		}
		return result
	}
}
