package v1

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
)

const (
	// API endpoint for JSON requests
	netcupApiEndpointJSON = "https://ccp.netcup.net/run/webservice/servers/endpoint.php?JSON"
	// JSON content type
	netcupApiContentType = "application/json"
)

// Type for action field of a request payload
type RequestAction string

const (
	actionLogin            RequestAction = "login"
	actionLogout           RequestAction = "logout"
	actionInfoDnsZone      RequestAction = "infoDnsZone"
	actionInfoDnsRecords   RequestAction = "infoDnsRecords"
	actionUpdateDnsZone    RequestAction = "updateDnsZone"
	actionUpdateDnsRecords RequestAction = "updateDnsRecords"
)

// Holder for Netcup DNS client context.
type NetcupDnsClient struct {
	customerNumber  int
	apiKey          string
	apiPassword     string
	clientRequestId string
	apiEndpoint     string
}

// Additional optional flags for client creation
type NetcupDnsClientOptions struct {
	ClientRequestId string
	ApiEndpoint     string // useful for testing
}

// Netcup session context object to hold session information, like apiSessionId or last response.
type NetcupSession struct {
	apiSessionId   string
	apiKey         string
	customerNumber int
	endpoint       string
	LastResponse   *NetcupBaseResponseMessage
}

// DnsZoneData holds information about a DNS zone of a domain.
type DnsZoneData struct {
	DomainName   string `json:"name"`
	Ttl          string `json:"ttl"`
	Serial       string `json:"serial"`
	Refresh      string `json:"refresh"`
	Retry        string `json:"retry"`
	Expire       string `json:"expire"`
	DnsSecStatus bool   `json:"dnssecstatus"`
}

// DnsRecord holds information about a single DNS record entry.
type DnsRecord struct {
	Id           string `json:"id"`
	Hostname     string `json:"hostname"`
	Type         string `json:"type"`
	Priority     string `json:"priority"`
	Destination  string `json:"destination"`
	DeleteRecord bool   `json:"deleterecord"`
	State        string `json:"state"`
}

// Response message, as defined by the Netcup API. This is intentionally not complete,
// because the responseData can vary by any sub type of message.
type NetcupBaseResponseMessage struct {
	ServerRequestId string `json:"serverrequestid"`
	ClientRequestId string `json:"clientrequestid"`
	Action          string `json:"action"`
	Status          string `json:"status"`
	StatusCode      int    `json:"statuscode"`
	ShortMessage    string `json:"shortmessage"`
	LongMessage     string `json:"longmessage"`
}

// Parameters used for login() request. These are special in the way they don't
// contain apisessionid field and contain apipassword initially.
type LoginParams struct {
	CustomerNumber  int    `json:"customernumber"`
	ApiKey          string `json:"apikey"`
	ApiPassword     string `json:"apipassword"`
	ClientRequestId string `json:"clientrequestid"`
}

// Payload used for login request
type LoginPayload struct {
	Action RequestAction `json:"action"`
	Params *LoginParams  `json:"param"`
}

// Base payload for all API requests, except for login().
type BasePayload struct {
	Action RequestAction     `json:"action"`
	Params *NetcupBaseParams `json:"param"`
}

// This is what Netcup expects to be in "params" (except for login() request, which doesn't have ApiSessionId)
type NetcupBaseParams struct {
	CustomerNumber  int    `json:"customernumber"`
	ApiSessionId    string `json:"apisessionid"`
	ApiKey          string `json:"apikey"`
	ClientRequestId string `json:"clientrequestid"`
}

// Inner resonse data of a login response.
type LoginResponseData struct {
	ApiSessionId string `json:"apisessionid"`
}

// Response payload of a login response.
type LoginResponsePayload struct {
	NetcupBaseResponseMessage
	ResponseData *LoginResponseData `json:"responsedata"`
}

// Inner response data of InfoDnsZone response.
type InfoDnsZoneResponsePayload struct {
	NetcupBaseResponseMessage
	ResponseData *DnsZoneData `json:"responsedata"`
}

// Parameters for InfoDnsZone request
type InfoDnsZoneParams struct {
	NetcupBaseParams
	DomainName string `json:"domainname"`
}

// Payload for InfoDnsZone request
type InfoDnsZonePayload struct {
	Action RequestAction      `json:"action"`
	Params *InfoDnsZoneParams `json:"param"`
}

// Parameters for InfoDnsRecords
type InfoDnsRecordsParams InfoDnsZoneParams

// Payload for InfoDnsRecords request
type InfoDnsRecordsPayload struct {
	Action RequestAction         `json:"action"`
	Params *InfoDnsRecordsParams `json:"param"`
}

type InfoDnsRecordsResponseData struct {
	DnsRecords []DnsRecord `json:"dnsrecords"`
}
type InfoDnsRecordsResponsePayload struct {
	NetcupBaseResponseMessage
	ResponseData *InfoDnsRecordsResponseData `json:"responsedata"`
}

type UpdateDnsZoneParams struct {
	NetcupBaseParams
	DomainName string       `json:"domainname"`
	DnsZone    *DnsZoneData `json:"dnszone"`
}

// Payload for UpdateDnsZone request
type UpdateDnsZonePayload struct {
	Action RequestAction        `json:"action"`
	Params *UpdateDnsZoneParams `json:"param"`
}

type UpdateDnsZoneResponsePayload InfoDnsZoneResponsePayload

type DnsRecordSet struct {
	Content []DnsRecord `json:"dnsrecords"`
}

type UpdateDnsRecordsParams struct {
	NetcupBaseParams
	DomainName string        `json:"domainname"`
	DnsRecords *DnsRecordSet `json:"dnsrecordset"`
}

type UpdateDnsRecordsPayload struct {
	Action RequestAction           `json:"action"`
	Params *UpdateDnsRecordsParams `json:"param"`
}

type UpdateDnsRecordsResponseData struct {
	DnsRecords []DnsRecord `json:"dnsrecords"`
}

// Response payload sent by Netcup upon updateDnsRecords() request
type UpdateDnsRecordsResponsePayload struct {
	NetcupBaseResponseMessage
	ResponseData *UpdateDnsRecordsResponseData `json:"responsedata"`
}

// Creates a new client to interact with Netcup DNS API.
func NewNetcupDnsClient(customerNumber int, apiKey string, apiPassword string) *NetcupDnsClient {
	return &NetcupDnsClient{
		customerNumber: customerNumber,
		apiKey:         apiKey,
		apiPassword:    apiPassword,
		apiEndpoint:    netcupApiEndpointJSON,
	}
}

// Create a new client to interact with Netcup DNS API, using own given clientRequestId.
func NewNetcupDnsClientWithOptions(customerNumber int, apiKey string, apiPassword string, opts *NetcupDnsClientOptions) *NetcupDnsClient {
	client := NewNetcupDnsClient(customerNumber, apiKey, apiPassword)
	if opts.ApiEndpoint != "" {
		client.apiEndpoint = opts.ApiEndpoint
	}
	if opts.ClientRequestId != "" {
		client.clientRequestId = opts.ClientRequestId
	}
	return client
}

/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//   API Implementation
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// Login to Netcup API. Returns a valid NetcupSession or error.
func (c *NetcupDnsClient) Login() (*NetcupSession, error) {

	if buf, err := doPost(c.apiEndpoint, &LoginPayload{
		Action: actionLogin,
		Params: &LoginParams{
			CustomerNumber:  c.customerNumber,
			ApiKey:          c.apiKey,
			ApiPassword:     c.apiPassword,
			ClientRequestId: c.clientRequestId,
		},
	}); err != nil {
		return nil, err
	} else {
		lr := &LoginResponsePayload{
			ResponseData: &LoginResponseData{},
		}

		dec := json.NewDecoder(buf)
		if err := dec.Decode(&lr); err != nil {
			return nil, err
		}
		return &NetcupSession{
			apiSessionId:   lr.ResponseData.ApiSessionId,
			apiKey:         c.apiKey,
			customerNumber: c.customerNumber,
			endpoint:       c.apiEndpoint,
			LastResponse:   &lr.NetcupBaseResponseMessage,
		}, nil
	}
}

// Query information about DNS zone.
func (s *NetcupSession) InfoDnsZone(domainName string) (*DnsZoneData, error) {
	if buf, err := doPost(s.endpoint, &InfoDnsZonePayload{
		Action: actionInfoDnsZone,
		Params: &InfoDnsZoneParams{
			NetcupBaseParams: NetcupBaseParams{
				CustomerNumber:  s.customerNumber,
				ApiKey:          s.apiKey,
				ApiSessionId:    s.apiSessionId,
				ClientRequestId: s.LastResponse.ClientRequestId,
			},
			DomainName: domainName,
		},
	}); err != nil {
		return nil, err
	} else {
		resp := &InfoDnsZoneResponsePayload{
			ResponseData: &DnsZoneData{},
		}
		dec := json.NewDecoder(buf)
		if err := dec.Decode(resp); err != nil {
			return nil, err
		} else {
			s.LastResponse = &resp.NetcupBaseResponseMessage
			return resp.ResponseData, nil
		}
	}
}

// Query information about all DNS records.
func (s *NetcupSession) InfoDnsRecords(domainName string) (*[]DnsRecord, error) {
	if buf, err := doPost(s.endpoint, &InfoDnsRecordsPayload{
		Action: actionInfoDnsRecords,
		Params: &InfoDnsRecordsParams{
			NetcupBaseParams: NetcupBaseParams{
				CustomerNumber:  s.customerNumber,
				ApiKey:          s.apiKey,
				ApiSessionId:    s.apiSessionId,
				ClientRequestId: s.LastResponse.ClientRequestId,
			},
			DomainName: domainName,
		},
	}); err != nil {
		return nil, err
	} else {
		resp := &InfoDnsRecordsResponsePayload{
			ResponseData: &InfoDnsRecordsResponseData{
				DnsRecords: make([]DnsRecord, 0),
			},
		}
		dec := json.NewDecoder(buf)
		if err := dec.Decode(resp); err != nil {
			return nil, err
		} else {
			s.LastResponse = &resp.NetcupBaseResponseMessage
			return &resp.ResponseData.DnsRecords, nil
		}
	}
}

// Update data of a DNS zone, returning an updated DnsZoneData.
func (s *NetcupSession) UpdateDnsZone(domainName string, dnsZone *DnsZoneData) (*DnsZoneData, error) {
	if buf, err := doPost(s.endpoint, &UpdateDnsZonePayload{
		Action: actionUpdateDnsZone,
		Params: &UpdateDnsZoneParams{
			NetcupBaseParams: NetcupBaseParams{
				CustomerNumber:  s.customerNumber,
				ApiKey:          s.apiKey,
				ApiSessionId:    s.apiSessionId,
				ClientRequestId: s.LastResponse.ClientRequestId,
			},
			DomainName: domainName,
			DnsZone:    dnsZone,
		},
	}); err != nil {
		return nil, err
	} else {
		resp := &UpdateDnsZoneResponsePayload{
			ResponseData: &DnsZoneData{},
		}
		dec := json.NewDecoder(buf)
		if err := dec.Decode(resp); err != nil {
			return nil, err
		} else {
			s.LastResponse = &resp.NetcupBaseResponseMessage
			return resp.ResponseData, nil
		}
	}
}

// Update set of DNS records for a given domain name, returning updated DNS records.
func (s *NetcupSession) UpdateDnsRecords(domainName string, dnsRecordSet *[]DnsRecord) (*[]DnsRecord, error) {
	if buf, err := doPost(s.endpoint, &UpdateDnsRecordsPayload{
		Action: actionUpdateDnsRecords,
		Params: &UpdateDnsRecordsParams{
			NetcupBaseParams: NetcupBaseParams{
				CustomerNumber:  s.customerNumber,
				ApiKey:          s.apiKey,
				ApiSessionId:    s.apiSessionId,
				ClientRequestId: s.LastResponse.ClientRequestId,
			},
			DomainName: domainName,
			DnsRecords: &DnsRecordSet{
				Content: *dnsRecordSet,
			},
		},
	}); err != nil {
		return nil, err
	} else {
		resp := &UpdateDnsRecordsResponsePayload{
			ResponseData: &UpdateDnsRecordsResponseData{
				DnsRecords: make([]DnsRecord, 0),
			},
		}
		dec := json.NewDecoder(buf)
		if err := dec.Decode(resp); err != nil {
			return nil, err
		} else {
			s.LastResponse = &resp.NetcupBaseResponseMessage
			return &resp.ResponseData.DnsRecords, nil
		}
	}
}

// Logout from active Netcup session. This may return an error (which can be ignored).
func (s *NetcupSession) Logout() error {
	req := &BasePayload{
		Action: actionLogout,
		Params: &NetcupBaseParams{
			CustomerNumber:  s.customerNumber,
			ApiSessionId:    s.apiSessionId,
			ApiKey:          s.apiKey,
			ClientRequestId: s.LastResponse.ClientRequestId,
		},
	}
	if resp, err := doPost(s.endpoint, req); err != nil {
		log.Printf("error while logout(): %v. Response was: %v", err, resp.String())
		return err
	}
	return nil
}

// Stringer implementation for NetcupSession.
func (s *NetcupSession) String() string {
	return fmt.Sprintf(
		"{ "+
			"\"apiSessionId\": \"%s\", "+
			"\"LastResponse\": %v "+
			"}",
		s.apiSessionId,
		s.LastResponse,
	)
}

// Stringer implementation for NetcupBaseResponseMessage.
func (r *NetcupBaseResponseMessage) String() string {
	return fmt.Sprintf(
		"{ "+
			"\"ServerRequestId\": \"%s\", "+
			"\"ClientRequestId\": \"%s\", "+
			"\"Action\": \"%s\", "+
			"\"Status\": \"%s\", "+
			"\"StatusCode\": \"%d\", "+
			"\"ShortMessage\": \"%s\", "+
			"\"LongMessage\": \"%s\" "+
			"}",
		r.ServerRequestId,
		r.ClientRequestId,
		r.Action,
		r.Status,
		r.StatusCode,
		r.ShortMessage,
		r.LongMessage,
	)
}

// Stringer implementation for DnsZoneData.
func (d *DnsZoneData) String() string {
	return fmt.Sprintf(
		"{ "+
			"\"DomainName\": \"%s\", "+
			"\"Ttl\": \"%s\", "+
			"\"Serial\": \"%s\", "+
			"\"Refresh\": \"%s\", "+
			"\"Retry\": \"%s\", "+
			"\"Expire\": \"%s\", "+
			"\"DnsSecStatus\": %v "+
			"}",
		d.DomainName,
		d.Ttl,
		d.Serial,
		d.Refresh,
		d.Retry,
		d.Expire,
		d.DnsSecStatus,
	)
}

// Stringer implementation for DnsRecord
func (d *DnsRecord) String() string {
	return fmt.Sprintf(
		"{ "+
			"\"Id\": \"%s\", "+
			"\"Hostname\": \"%s\", "+
			"\"Type\": \"%s\", "+
			"\"Priority\": \"%s\", "+
			"\"Destination\": \"%s\", "+
			"\"DeleteRecord\": %v, "+
			"\"State\": \"%s\" "+
			"}",
		d.Id,
		d.Hostname,
		d.Type,
		d.Priority,
		d.Destination,
		d.DeleteRecord,
		d.State,
	)
}

// internal helper for doing HTTP post with given payload.
func doPost(endpoint string, payload any) (*bytes.Buffer, error) {
	var buf bytes.Buffer

	enc := json.NewEncoder(&buf)
	if err := enc.Encode(payload); err != nil {
		return nil, err
	}

	if resp, err := http.Post(endpoint, netcupApiContentType, &buf); err != nil {
		return nil, err
	} else {
		if resp.StatusCode >= 400 {
			return nil, fmt.Errorf("unexpected error code: %d", resp.StatusCode)
		}
		buf.Reset()
		if _, err := buf.ReadFrom(resp.Body); err != nil {
			resp.Body.Close()
			return nil, err
		}
		resp.Body.Close()
	}
	return &buf, nil
}
