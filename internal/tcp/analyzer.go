package tcp

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"
)

const (
	defaultTimeout     = 15 * time.Second
	defaultMaxRetries  = 10
	defaultRetryDelay  = 1 * time.Second
	defaultBufferSize  = 4096
	minTCPPacketLength = 20
)

// Client implements the Analyzer interface
type Client struct {
	config *Config
}

// NewAnalyzer creates a new TCP analyzer with the given configuration
func NewAnalyzer(config *Config) *Client {
	if config == nil {
		config = &Config{
			Timeout:    defaultTimeout,
			MaxRetries: defaultMaxRetries,
			RetryDelay: defaultRetryDelay,
			BufferSize: defaultBufferSize,
		}
	}
	return &Client{config: config}
}

// AnalyzeHandshake performs TCP connection analysis on the given target
func (c *Client) AnalyzeHandshake(target string) (*AnalysisResult, error) {
	result := &AnalysisResult{}
	
	addr, err := net.ResolveTCPAddr("tcp", target)
	if err != nil {
		return result, fmt.Errorf("error resolving address: %w", err)
	}

	// Measure connection timing
	startTime := time.Now()
	
	conn, err := c.establishConnection(target, addr)
	if err != nil {
		return result, fmt.Errorf("error connecting to target: %w", err)
	}
	defer conn.Close()
	
	connectTime := time.Since(startTime)
	
	// Analyze the TCP connection properties
	tcpResponse, err := c.analyzeConnection(conn, addr, connectTime)
	if err != nil {
		result.Error = err.Error()
		return result, nil
	}

	result.TCPResponse = tcpResponse
	return result, nil
}

// establishConnection attempts to establish a connection, trying both TCP and TLS
func (c *Client) establishConnection(target string, addr *net.TCPAddr) (net.Conn, error) {
	// Try regular TCP connection first
	conn, err := net.DialTCP("tcp", nil, addr)
	if err == nil {
		return conn, nil
	}

	// If TCP fails, try TLS connection
	tlsConn, err := tls.Dial("tcp", target, &tls.Config{
		InsecureSkipVerify: true,
	})
	if err != nil {
		return nil, fmt.Errorf("both TCP and TLS connections failed: %w", err)
	}

	return tlsConn, nil
}

// readWithRetries reads data from connection with retry logic
func (c *Client) readWithRetries(conn net.Conn) ([]byte, error) {
	conn.SetReadDeadline(time.Now().Add(c.config.Timeout))
	
	buf := make([]byte, c.config.BufferSize)
	totalRead := 0
	
	for retries := 0; retries < c.config.MaxRetries; retries++ {
		n, err := conn.Read(buf[totalRead:])
		if n > 0 {
			totalRead += n
		}
		
		if err == nil {
			break
		}
		
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			time.Sleep(c.config.RetryDelay)
			continue
		}
		
		return nil, fmt.Errorf("read error after %d attempts: %w", retries+1, err)
	}
	
	if totalRead == 0 {
		return nil, fmt.Errorf("no data received after %d attempts", c.config.MaxRetries)
	}
	
	return buf[:totalRead], nil
}

// analyzeConnection analyzes TCP connection properties
func (c *Client) analyzeConnection(conn net.Conn, addr *net.TCPAddr, connectTime time.Duration) (*Response, error) {
	response := &Response{
		DestinationPort: uint16(addr.Port),
		ConnectTime:     connectTime.Milliseconds(),
	}

	// Get TCP connection info if available
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		// Get local address info
		if localAddr := tcpConn.LocalAddr(); localAddr != nil {
			if tcpLocalAddr, ok := localAddr.(*net.TCPAddr); ok {
				response.SourcePort = uint16(tcpLocalAddr.Port)
			}
		}
		
		// Test TCP keep-alive settings
		if err := tcpConn.SetKeepAlive(true); err == nil {
			response.KeepAliveSupported = true
		}
		
		// Test write timeout
		writeStart := time.Now()
		tcpConn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, err := tcpConn.Write([]byte("GET / HTTP/1.1\r\nHost: " + addr.IP.String() + "\r\nConnection: close\r\n\r\n"))
		if err == nil {
			response.WriteLatency = time.Since(writeStart).Milliseconds()
		}
		
		// Test read timeout  
		readStart := time.Now()
		tcpConn.SetReadDeadline(time.Now().Add(5 * time.Second))
		buffer := make([]byte, 1024)
		_, err = tcpConn.Read(buffer)
		if err == nil {
			response.ReadLatency = time.Since(readStart).Milliseconds()
		}
	}
	
	// Simulate some TCP analysis values for now
	response.WindowSize = 65535  // Standard window size
	response.ACKFlag = true      // Connection established
	response.PSHFlag = true      // Data pushed
	
	// Add connection quality metrics
	response.ConnectionQuality = c.assessConnectionQuality(connectTime, response.WriteLatency, response.ReadLatency)

	return response, nil
}

// assessConnectionQuality provides a simple quality assessment
func (c *Client) assessConnectionQuality(connectTime time.Duration, writeLatency, readLatency int64) string {
	totalLatency := connectTime.Milliseconds() + writeLatency + readLatency
	
	if totalLatency < 50 {
		return "Excellent"
	} else if totalLatency < 150 {
		return "Good"  
	} else if totalLatency < 300 {
		return "Fair"
	} else {
		return "Poor"
	}
}

// parseTCPOptions parses TCP options and logs them
func (c *Client) parseTCPOptions(options []byte) {
	log.Printf("Parsing TCP options")
	
	for i := 0; i < len(options); {
		if i >= len(options) {
			break
		}
		
		opt := OptionType(options[i])
		
		switch opt {
		case OptionEndOfList:
			log.Println("TCP Option: End of Option List")
			i++
			
		case OptionNOP:
			log.Println("TCP Option: No-Operation (NOP)")
			i++
			
		case OptionMSS:
			if i+3 >= len(options) {
				log.Println("TCP Option: Invalid MSS option length")
				return
			}
			mss := binary.BigEndian.Uint16(options[i+2 : i+4])
			log.Printf("TCP Option: Maximum Segment Size: %d", mss)
			i += 4
			
		case OptionWindowScale:
			if i+2 >= len(options) {
				log.Println("TCP Option: Invalid Window Scale option length")
				return
			}
			shiftCount := options[i+2]
			log.Printf("TCP Option: Window Scale: %d", shiftCount)
			i += 3
			
		case OptionSACKPermitted:
			log.Println("TCP Option: Selective Acknowledgment (SACK) Permitted")
			i += 2
			
		case OptionSACK:
			if i+1 >= len(options) || i+int(options[i+1]) > len(options) {
				log.Println("TCP Option: Invalid SACK option length")
				return
			}
			sackLen := int(options[i+1])
			log.Printf("TCP Option: SACK: %x", options[i+2:i+sackLen])
			i += sackLen
			
		case OptionTimestamps:
			if i+9 >= len(options) {
				log.Println("TCP Option: Invalid Timestamps option length")
				return
			}
			tsVal := binary.BigEndian.Uint32(options[i+2 : i+6])
			tsEcho := binary.BigEndian.Uint32(options[i+6 : i+10])
			log.Printf("TCP Option: Timestamps: Val=%d Echo=%d", tsVal, tsEcho)
			i += 10
			
		default:
			if i+1 >= len(options) {
				log.Println("TCP Option: Invalid option - no length field")
				return
			}
			if i+int(options[i+1]) > len(options) {
				log.Println("TCP Option: Invalid option length")
				return
			}
			log.Printf("TCP Option: Unknown option: %d, Length: %d", opt, options[i+1])
			i += int(options[i+1])
		}
	}
}