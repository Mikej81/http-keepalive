package main

// Response structure
type response struct {
	Domain           string   `json:"domain"`
	KeepAliveTimeout string   `json:"keepAliveTimeout"`
	RequestDuration  int64    `json:"requestDuration"`
	TLSVersion       string   `json:"tlsVersion"`
	ConnectionHeader string   `json:"connectionHeader"`
	CnameRecords     []string `json:"cnameRecords,omitempty"`
	ARecords         []string `json:"aRecords,omitempty"`
	TCPResults       string   `json:"tcpResults,omitempty"` // Changed to string
}

// TCPResults is the structure to hold TCP handshake and analysis results.
type TCPResults struct {
	TLSVersion  uint16       `json:"tls_version,omitempty"`
	CipherSuite uint16       `json:"cipher_suite,omitempty"`
	TCPResponse *TCPResponse `json:"tcp_response,omitempty"`
	Error       string       `json:"error,omitempty"`
}

// TCPResponse holds details of the TCP packet analysis.
type TCPResponse struct {
	SourcePort      uint16 `json:"source_port"`
	DestinationPort uint16 `json:"destination_port"`
	SequenceNumber  uint32 `json:"sequence_number"`
	AckNumber       uint32 `json:"ack_number"`
	DataOffset      uint32 `json:"data_offset"`
	Flags           uint8  `json:"flags"`
	WindowSize      uint16 `json:"window_size"`
	Checksum        uint16 `json:"checksum"`
	UrgentPointer   uint16 `json:"urgent_pointer"`
	SYNFlag         bool   `json:"syn_flag"`
	ACKFlag         bool   `json:"ack_flag"`
	FINFlag         bool   `json:"fin_flag"`
	RSTFlag         bool   `json:"rst_flag"`
	PSHFlag         bool   `json:"psh_flag"`
	URGFlag         bool   `json:"urg_flag"`
	ECEFlag         bool   `json:"ece_flag"`
	CWRFlag         bool   `json:"cwr_flag"`
	TCPOptions      []byte `json:"tcp_options"`
}
