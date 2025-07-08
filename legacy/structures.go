package main

import "net/http"

// Struct to store DNS result with TTL
type DNSRecordWithTTL struct {
	IP  string `json:"ip"`
	TTL uint32 `json:"ttl"`
}

type TCPResponse struct {
	SourcePort      uint16 `json:"sourcePort"`
	DestinationPort uint16 `json:"destinationPort"`
	SequenceNumber  uint32 `json:"sequenceNumber"`
	AckNumber       uint32 `json:"ackNumber"`
	DataOffset      uint32 `json:"dataOffset"`
	Flags           byte   `json:"flags"`
	WindowSize      uint16 `json:"windowSize"`
	Checksum        uint16 `json:"checksum"`
	UrgentPointer   uint16 `json:"urgentPointer"`
	SYNFlag         bool   `json:"synFlag"`
	ACKFlag         bool   `json:"ackFlag"`
	FINFlag         bool   `json:"finFlag"`
	RSTFlag         bool   `json:"rstFlag"`
	PSHFlag         bool   `json:"pshFlag"`
	URGFlag         bool   `json:"urgFlag"`
	ECEFlag         bool   `json:"eceFlag"`
	CWRFlag         bool   `json:"cwrFlag"`
	TCPOptions      []byte `json:"tcpOptions"`
}

type TCPResults struct {
	TCPResponse *TCPResponse `json:"tcpResponse,omitempty"`
	Error       string       `json:"error,omitempty"`
}

type response struct {
	Domain           string             `json:"domain"`
	KeepAliveTimeout string             `json:"keepAliveTimeout"`
	RequestDuration  int64              `json:"requestDuration"`
	TLSVersion       string             `json:"tlsVersion"`
	ConnectionHeader string             `json:"connectionHeader"`
	ServerHeader     string             `json:"serverHeader"`
	PoweredHeader    string             `json:"poweredHeader"`
	ForwardHeader    string             `json:"forwardHeader"`
	RealIPHeader     string             `json:"realIPHeader"`
	XCacheHeader     string             `json:"xCacheHeader"`
	CloudflareHeader string             `json:"cloudflareHeader"`
	CloudFrontHeader string             `json:"cloudFrontHeader"`
	AkamaiHeader     string             `json:"akamaiHeader"`
	CnameRecords     []string           `json:"cnameRecords"`
	ARecordsWithTTL  []DNSRecordWithTTL `json:"aRecordsWithTTL"`
	TCPResults       string             `json:"tcpResults"`
	CSPDetails       string             `json:"cspDetails"`
	RequestHeaders   http.Header        `json:"-"`
	ResponseHeaders  http.Header        `json:"-"`
	Error            string             `json:"error,omitempty"`
}
