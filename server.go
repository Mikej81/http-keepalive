package main

import (
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"
)

const port = ":3000"
const publicDir = "public"

func main() {
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/analyze", analyzeHandler)
	fs := http.FileServer(http.Dir(publicDir))
	http.Handle("/public/", http.StripPrefix("/public/", fs))

	log.Printf("Server running at http://localhost%s\n", port)
	if err := http.ListenAndServe(port, nil); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/" {
		tmpl := template.Must(template.ParseFiles(filepath.Join(publicDir, "index.html")))
		tmpl.Execute(w, nil)
		return
	}
	http.ServeFile(w, r, filepath.Join(publicDir, r.URL.Path))
}

func analyzeHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var reqData struct {
		Domain string `json:"domain"`
	}

	err := json.NewDecoder(r.Body).Decode(&reqData)
	if err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	domain := reqData.Domain

	if !strings.HasPrefix(domain, "http://") && !strings.HasPrefix(domain, "https://") {
		domain = "http://" + domain
	}

	parsedURL, err := url.Parse(domain)
	if err != nil {
		http.Error(w, "Invalid URL", http.StatusBadRequest)
		return
	}

	dnsDomain := parsedURL.Hostname()
	port := parsedURL.Port()
	if port == "" {
		port = "80"
	}

	response, err := attemptHTTPConnection(domain, dnsDomain)
	if err != nil && port == "80" {
		domain = "https://" + dnsDomain
		parsedURL, err = url.Parse(domain)
		if err != nil {
			http.Error(w, "Invalid URL", http.StatusBadRequest)
			return
		}
		port = "443"
		response, err = attemptHTTPConnection(domain, dnsDomain)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to fetch data: %v", err), http.StatusInternalServerError)
			return
		}
	}

	responseObj := response
	w.Header().Set("Content-Type", "application/json")
	log.Printf("Response: %+v\n", responseObj) // Log the response
	json.NewEncoder(w).Encode(responseObj)
}

func attemptHTTPConnection(domain, dnsDomain string) (response, error) {
	// Resolve the domain to get A records
	cnameRecords, aRecords, err := resolveCnameAndARecords(dnsDomain)
	if err != nil {
		return response{}, fmt.Errorf("failed to resolve DNS records: %v", err)
	}

	if len(aRecords) == 0 {
		return response{}, fmt.Errorf("no A records found for the domain")
	}

	// Use the first A record (IP address) for TCP analysis
	//ip := aRecords[0]

	startTime := time.Now()

	finalDomain, tlsVersion, headers, tcpResults, err := httpsGetWithTLSInfo(domain, dnsDomain)
	if err != nil {
		return response{}, fmt.Errorf("failed to fetch data: %v", err)
	}

	timeoutValue := "Not Defined"
	connectionHeader := "Not Defined"

	if ka, ok := headers["Keep-Alive"]; ok {
		timeoutValue = extractTimeoutValue(ka[0])
	}
	if conn, ok := headers["Connection"]; ok {
		connectionHeader = conn[0]
	}

	duration := time.Since(startTime).Milliseconds()

	return response{
		Domain:           finalDomain,
		KeepAliveTimeout: timeoutValue,
		RequestDuration:  duration,
		TLSVersion:       tlsVersion,
		ConnectionHeader: connectionHeader,
		CnameRecords:     cnameRecords,
		ARecords:         aRecords,
		TCPResults:       string(tcpResults), // Convert to string
	}, nil
}

func httpsGetWithTLSInfo(url string, ip string) (string, string, http.Header, []byte, error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // Use with caution
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return nil
		},
	}

	resp, err := client.Get(url)
	if err != nil {
		return "", "", nil, nil, err
	}
	defer resp.Body.Close()

	finalURL := resp.Request.URL.String()

	// Extract port from the URL
	port := "443" // Default to HTTPS port
	if strings.HasPrefix(finalURL, "https://") {
		port = "443"
	} else if strings.HasPrefix(finalURL, "http://") {
		port = "80"
	}

	_, portString, _ := net.SplitHostPort(resp.Request.URL.Host)
	if portString != "" {
		port = portString
	}

	// TCP Analysis using the IP address and port
	//tcpResults, tcpErr := analyzeTCPHandshake(ip + ":" + port)
	tcpResults, tcpErr := analyzeTCPHandshake(ip + ":" + port)
	if tcpErr != nil {
		fmt.Printf("TCP Error: %v\n", tcpErr)
	}

	jsonResults, err := json.MarshalIndent(tcpResults, "", " ")
	if err != nil {
		fmt.Printf("Error Marshaling TCP JSON: %v\n", err)
	}

	_, err = io.ReadAll(resp.Body)
	if err != nil {
		return "", "", nil, nil, err
	}

	tlsVersion := "Unknown"
	if resp.TLS != nil {
		tlsVersion = tlsVersionToString(resp.TLS.Version)
	}

	return finalURL, tlsVersion, resp.Header, jsonResults, nil
}

func tlsVersionToString(version uint16) string {
	switch version {
	case tls.VersionTLS13:
		return "TLS 1.3"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS10:
		return "TLS 1.0"
	default:
		return "Unknown"
	}
}

func extractTimeoutValue(keepAliveHeader string) string {
	if strings.Contains(keepAliveHeader, "timeout=") {
		parts := strings.Split(keepAliveHeader, "=")
		if len(parts) > 1 {
			return parts[1]
		}
	}
	return "Not Defined"
}

func resolveCnameAndARecords(domain string) ([]string, []string, error) {
	cnameRecords, err := net.LookupCNAME(domain)
	if err != nil && !isNotFoundError(err) {
		return nil, nil, err
	}

	aRecords, err := net.LookupHost(domain)
	if err != nil && !isNotFoundError(err) {
		return nil, nil, err
	}

	return []string{cnameRecords}, aRecords, nil
}

func analyzeTCPHandshake(target string) (*TCPResults, error) {
	results := &TCPResults{}
	addr, err := net.ResolveTCPAddr("tcp", target)
	if err != nil {
		return results, fmt.Errorf("error resolving address: %v\n", err)
	}

	var conn net.Conn

	// Try to connect via TCP first
	conn, err = net.DialTCP("tcp", nil, addr)
	if err == nil {
		defer conn.Close()

		// You gotta say hello!
		httpRequest := "GET / HTTP/1.1\r\nHost: " + target + "\r\nConnection: close\r\n\r\n"
		n, err := conn.Write([]byte(httpRequest))
		if err != nil {
			log.Println(n, err)
		}

		fmt.Printf("CON: Sent %d bytes: %s\n", n, httpRequest)
	} else {
		// If TCP connection fails, try TLS
		conn, err = tls.Dial("tcp", target, &tls.Config{
			InsecureSkipVerify: true,
		})
		if err != nil {
			return results, fmt.Errorf("error connecting to target: %v\n", err)
		}
		defer conn.Close()
	}

	if tlsConn, ok := conn.(*tls.Conn); ok {
		// TLS connection
		err = tlsConn.Handshake()
		if err != nil {
			return results, fmt.Errorf("TLS handshake error: %v\n", err)
		}

		// Send an HTTP GET request over the TLS connection
		httpRequest := "GET / HTTP/1.1\r\nHost: " + addr.IP.String() + "\r\nConnection: close\r\n\r\n"
		n, err := tlsConn.Write([]byte(httpRequest))
		if err != nil {
			return nil, fmt.Errorf("error writing to TLS connection: %v\n", err)
		}
		fmt.Printf("TLS-CON: Sent %d bytes: %s\n", n, httpRequest)

		results.TLSVersion = tlsConn.ConnectionState().Version
		results.CipherSuite = tlsConn.ConnectionState().CipherSuite
	}

	// // You gotta say hello!
	// httpRequest := "GET / HTTP/1.1\r\nHost: " + target + "\r\nConnection: close\r\n\r\n"
	// n, err := conn.Write([]byte(httpRequest))
	// if err != nil {
	// 	log.Println(n, err)
	// }

	// fmt.Printf("CON: Sent %d bytes: %s\n", n, httpRequest)

	// Set a longer timeout to read the SYN-ACK
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	// Create a buffer to store the SYN-ACK response
	buf := make([]byte, 256)
	maxRetries := 5
	for retries := 0; retries < maxRetries; retries++ {
		_, err = conn.Read(buf)
		if err == nil {
			break
		}
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			fmt.Println("Read timed out, retrying...")
			time.Sleep(100 * time.Millisecond) // Wait 100ms before retrying
			continue
		}
		return results, fmt.Errorf("error reading SYN-ACK: %v\n", err)
	}

	if err != nil {
		return results, fmt.Errorf("failed to read SYN-ACK from %s after %d attempts: %v\n", addr, maxRetries, err)
	}

	// Analyze the SYN-ACK response and populate the results
	response, err := analyzeTCPResponse(buf)
	if err != nil {
		results.Error = err.Error()
	} else {
		results.TCPResponse = response
	}

	return results, nil
}

func analyzeTCPResponse(buf []byte) (*TCPResponse, error) {
	if len(buf) < 20 {
		return nil, fmt.Errorf("Invalid TCP packet length\n")
	}

	response := &TCPResponse{
		SourcePort:      binary.BigEndian.Uint16(buf[0:2]),
		DestinationPort: binary.BigEndian.Uint16(buf[2:4]),
		SequenceNumber:  binary.BigEndian.Uint32(buf[4:8]),
		AckNumber:       binary.BigEndian.Uint32(buf[8:12]),
		DataOffset:      uint32(buf[12]>>4) * 4,
		Flags:           buf[13],
		WindowSize:      binary.BigEndian.Uint16(buf[14:16]),
		Checksum:        binary.BigEndian.Uint16(buf[16:18]),
		UrgentPointer:   binary.BigEndian.Uint16(buf[18:20]),
	}

	// Analyze TCP flags
	response.SYNFlag = response.Flags&0x02 != 0
	response.ACKFlag = response.Flags&0x10 != 0
	response.FINFlag = response.Flags&0x01 != 0
	response.RSTFlag = response.Flags&0x04 != 0
	response.PSHFlag = response.Flags&0x08 != 0
	response.URGFlag = response.Flags&0x20 != 0
	response.ECEFlag = response.Flags&0x40 != 0
	response.CWRFlag = response.Flags&0x80 != 0

	// Extract and parse TCP options
	if response.DataOffset > 20 {
		response.TCPOptions = buf[20:response.DataOffset]
		parseTCPOptions(response.TCPOptions)
	}

	return response, nil
}

func parseTCPOptions(options []byte) {
	fmt.Printf("parsing them options")
	for i := 0; i < len(options); {
		opt := options[i]
		switch opt {
		case 0: // End of Option List
			fmt.Println("End of Option List")
			i++
		case 1: // No-Operation (NOP)
			fmt.Println("No-Operation (NOP)")
			i++
		case 2: // Maximum Segment Size
			if i+3 >= len(options) {
				fmt.Println("Invalid MSS option length")
				return
			}
			mss := binary.BigEndian.Uint16(options[i+2 : i+4])
			fmt.Printf("Maximum Segment Size: %d\n", mss)
			i += 4
		case 3: // Window Scale
			if i+2 >= len(options) {
				fmt.Println("Invalid Window Scale option length")
				return
			}
			shiftCount := options[i+2]
			fmt.Printf("Window Scale: %d\n", shiftCount)
			i += 3
		case 4: // Selective Acknowledgment (SACK) Permitted
			fmt.Println("Selective Acknowledgment (SACK) Permitted")
			i += 2
		case 5: // SACK
			if i+1 >= len(options) || i+int(options[i+1]) > len(options) {
				fmt.Println("Invalid SACK option length")
				return
			}
			sackLen := int(options[i+1])
			fmt.Printf("SACK: %x\n", options[i+2:i+sackLen])
			i += sackLen
		case 8: // Timestamps
			if i+9 >= len(options) {
				fmt.Println("Invalid Timestamps option length")
				return
			}
			tsVal := binary.BigEndian.Uint32(options[i+2 : i+6])
			tsEcho := binary.BigEndian.Uint32(options[i+6 : i+10])
			fmt.Printf("Timestamps: Val=%d Echo=%d\n", tsVal, tsEcho)
			i += 10
		default:
			if i+1 >= len(options) || i+int(options[i+1]) > len(options) {
				fmt.Println("Invalid TCP option length")
				return
			}
			fmt.Printf("Unknown option: %d, Length: %d\n", opt, options[i+1])
			i += int(options[i+1])
		}
	}
}

func isNotFoundError(err error) bool {
	dnsErr, ok := err.(*net.DNSError)
	return ok && (dnsErr.Err == "no such host" || dnsErr.IsNotFound)
}
