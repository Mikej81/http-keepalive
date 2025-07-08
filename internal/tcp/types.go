package tcp

import (
	"time"
)

// Response represents TCP connection analysis results
type Response struct {
	SourcePort      uint16 `json:"sourcePort"`
	DestinationPort uint16 `json:"destinationPort"`
	SequenceNumber  uint32 `json:"sequenceNumber"`
	AckNumber       uint32 `json:"ackNumber"`
	DataOffset      uint32 `json:"dataOffset"`
	Flags           byte   `json:"flags"`
	WindowSize      uint16 `json:"windowSize"`
	Checksum        uint16 `json:"checksum"`
	UrgentPointer   uint16 `json:"urgentPointer"`
	
	// Flag breakdown
	SYNFlag bool `json:"synFlag"`
	ACKFlag bool `json:"ackFlag"`
	FINFlag bool `json:"finFlag"`
	RSTFlag bool `json:"rstFlag"`
	PSHFlag bool `json:"pshFlag"`
	URGFlag bool `json:"urgFlag"`
	ECEFlag bool `json:"eceFlag"`
	CWRFlag bool `json:"cwrFlag"`
	
	TCPOptions []byte `json:"tcpOptions"`
	
	// Connection analysis fields
	ConnectTime         int64  `json:"connectTime"`         // milliseconds
	WriteLatency        int64  `json:"writeLatency"`        // milliseconds  
	ReadLatency         int64  `json:"readLatency"`         // milliseconds
	KeepAliveSupported  bool   `json:"keepAliveSupported"`
	ConnectionQuality   string `json:"connectionQuality"`   // Excellent, Good, Fair, Poor
}

// AnalysisResult contains the results of TCP handshake analysis
type AnalysisResult struct {
	TCPResponse *Response `json:"tcpResponse,omitempty"`
	Error       string    `json:"error,omitempty"`
}

// Config holds TCP analyzer configuration
type Config struct {
	Timeout      time.Duration
	MaxRetries   int
	RetryDelay   time.Duration
	BufferSize   int
}

// Analyzer defines the interface for TCP analysis
type Analyzer interface {
	AnalyzeHandshake(target string) (*AnalysisResult, error)
}

// OptionType represents TCP option types
type OptionType byte

const (
	OptionEndOfList     OptionType = 0
	OptionNOP           OptionType = 1
	OptionMSS           OptionType = 2
	OptionWindowScale   OptionType = 3
	OptionSACKPermitted OptionType = 4
	OptionSACK          OptionType = 5
	OptionTimestamps    OptionType = 8
)

// Option represents a parsed TCP option
type Option struct {
	Type   OptionType `json:"type"`
	Length int        `json:"length"`
	Data   []byte     `json:"data"`
}