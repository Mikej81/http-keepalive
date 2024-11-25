package main

import (
	"bufio"
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
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/miekg/dns"
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

	log.Println("Analyze handler hit") // Add this to check if the request reaches here

	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}

	var reqData struct {
		Domain       string `json:"domain"`
		UseCachedDns bool   `json:"useCachedDns"` // Flag to determine whether to use cached DNS or not
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

	// Use the `useCachedDns` flag to control how the DNS is resolved
	log.Printf("DNS resolution for domain: %s, using cached DNS: %v", dnsDomain, reqData.UseCachedDns)

	response, err := attemptHTTPConnection(domain, dnsDomain, reqData.UseCachedDns)
	if err != nil && port == "80" {
		domain = "https://" + dnsDomain
		parsedURL, err = url.Parse(domain)
		if err != nil {
			http.Error(w, "Invalid URL", http.StatusBadRequest)
			return
		}
		port = "443"
		response, err = attemptHTTPConnection(domain, dnsDomain, reqData.UseCachedDns)
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

func attemptHTTPConnection(domain, dnsDomain string, useCachedDns bool) (response, error) {
	// Resolve the domain to get A records
	cnameRecords, aRecords, err := resolveCnameAndARecords(dnsDomain, useCachedDns)
	if err != nil {
		return response{}, fmt.Errorf("failed to resolve DNS records: %v", err)
	}

	if len(aRecords) == 0 {
		return response{}, fmt.Errorf("no A records found for the domain")
	}

	startTime := time.Now()

	finalDomain, tlsVersion, requestHeaders, responseHeaders, tcpResults, err := httpsGetWithTLSInfo(domain, dnsDomain)
	if err != nil {
		return response{}, fmt.Errorf("failed to fetch data: %v", err)
	}

	// Initialize all header variables with "Not Defined"
	timeoutValue := "Not Defined"
	connectionHeader := "Not Defined"
	serverHeader := "Not Defined"
	poweredHeader := "Not Defined" // Powered By
	forwardHeader := "Not Defined" // X-Forwarded-For (XFF)
	realipHeader := "Not Defined"  // X-Real-IP
	xcacheHeader := "No"           // Cache status from Varnish, Squid, or AWS CloudFront
	cloudflareHeader := "No"       // Cloudflare specific headers
	cloudfrontHeader := "No"       // AWS Cloudfront
	akamaiHeader := "No"

	// Check each header and update its corresponding variable
	// if ka, ok := headers["Keep-Alive"]; ok {
	// 	timeoutValue = extractTimeoutValue(ka[0])
	// }
	if conn, ok := responseHeaders["Keep-Alive"]; ok {
		timeoutValue = extractTimeoutValue(conn[0])
	}
	if conn, ok := responseHeaders["Connection"]; ok {
		connectionHeader = conn[0]
	}
	if conn, ok := responseHeaders["Server"]; ok {
		serverHeader = conn[0]
	}
	if conn, ok := responseHeaders["X-Powered-By"]; ok {
		poweredHeader = conn[0]
	}
	if conn, ok := responseHeaders["X-Forwarded-For"]; ok {
		forwardHeader = conn[0]
	}
	if conn, ok := responseHeaders["X-Real-IP"]; ok {
		realipHeader = conn[0]
	}
	if conn, ok := responseHeaders["X-Cache"]; ok {
		xcacheHeader = conn[0]
	}
	if conn, ok := responseHeaders["CF-Ray"]; ok {
		cloudflareHeader = conn[0]
	} else if conn, ok := responseHeaders["CF-Cache-Status"]; ok {
		cloudflareHeader = conn[0] // Fallback to CF-Cache-Status if CF-Ray is not present
	}

	// New: Check if Akamai CDN is used
	akamaiDetected := checkAkamai(responseHeaders)
	if akamaiDetected {
		akamaiHeader = "Detected"
	}

	// Check the Set-Cookie header for CloudFront indication
	if cookies, ok := responseHeaders["Set-Cookie"]; ok {
		for _, cookie := range cookies {
			if strings.Contains(cookie, "AWSALB") {
				cloudfrontHeader = "Detected"
				break // No need to check further if we've found the indicator
			}
		}
	}

	// Final adjustments based on conditions
	if forwardHeader == "Not Defined" && realipHeader != "Not Defined" {
		forwardHeader = realipHeader // Use X-Real-IP if X-Forwarded-For is not defined
	}

	duration := time.Since(startTime).Milliseconds()

	// Generate CSP details
	cspDetails, cspErr := generateCSP(domain)
	if cspErr != nil {
		// Handle the error as needed
		fmt.Printf("Error generating CSP: %v\n", cspErr)
		cspDetails = "Error generating CSP"
	}

	return response{
		Domain:           finalDomain,
		KeepAliveTimeout: timeoutValue,
		RequestDuration:  duration,
		TLSVersion:       tlsVersion,
		ConnectionHeader: connectionHeader,
		ServerHeader:     serverHeader,
		PoweredHeader:    poweredHeader,
		ForwardHeader:    forwardHeader,
		RealIPHeader:     realipHeader,
		XCacheHeader:     xcacheHeader,
		CloudflareHeader: cloudflareHeader,
		CloudFrontHeader: cloudfrontHeader,
		AkamaiHeader:     akamaiHeader,
		CnameRecords:     cnameRecords,
		ARecordsWithTTL:  aRecords,
		TCPResults:       string(tcpResults), // Convert to string if necessary
		CSPDetails:       cspDetails,
		RequestHeaders:   requestHeaders,
		ResponseHeaders:  responseHeaders,
	}, nil
}

func checkAkamai(headers http.Header) bool {
	// Check for Akamai-specific headers
	_, xAkamaiTransformed := headers["X-Akamai-Transformed"]
	_, xAkamaiSessionInfo := headers["X-Akamai-Session-Info"]
	_, akamaiOriginHop := headers["Akamai-Origin-Hop"]
	_, trueClientIP := headers["True-Client-IP"]
	_, xAkamaiStaging := headers["X-Akamai-Staging"]

	return xAkamaiTransformed || xAkamaiSessionInfo || akamaiOriginHop || trueClientIP || xAkamaiStaging
}

func httpsGetWithTLSInfo(url string, ip string) (string, string, http.Header, http.Header, []byte, error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // Use with caution
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse // stop after 10 redirects
			}
			// Print or log the redirect
			fmt.Printf("Redirecting to: %s\n", req.URL)
			return nil // continue following redirects
		},
	}

	// Create a new request so we can inspect or modify it
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", "", nil, nil, nil, err
	}

	resp, err := client.Get(url)
	if err != nil {
		return "", "", nil, nil, nil, err
	}
	defer resp.Body.Close()

	// Capture the request headers (after any modifications by the transport)
	requestHeaders := req.Header

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
		// Decide whether to proceed without TCP data or return an error
		// For now, include the error message in the results
		tcpResults.Error = tcpErr.Error()
	}

	jsonResults, err := json.MarshalIndent(tcpResults, "", " ")
	if err != nil {
		fmt.Printf("Error Marshaling TCP JSON: %v\n", err)
	}

	_, err = io.ReadAll(resp.Body)
	if err != nil {
		return "", "", nil, nil, nil, err
	}

	tlsVersion := "Unknown"
	if resp.TLS != nil {
		tlsVersion = tlsVersionToString(resp.TLS.Version)
	}

	return finalURL, tlsVersion, requestHeaders, resp.Header, jsonResults, nil
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

func getSystemDNSServer() (string, error) {
	file, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return "", fmt.Errorf("failed to open resolv.conf: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "nameserver") {
			parts := strings.Fields(line)
			if len(parts) > 1 {
				return parts[1] + ":53", nil // Return DNS server with port 53
			}
		}
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("failed to read resolv.conf: %v", err)
	}

	return "", fmt.Errorf("no nameserver found in resolv.conf")
}

func resolveCnameAndARecords(domain string, useCachedDns bool) ([]string, []DNSRecordWithTTL, error) {
	log.Println("DNS Analyze handler hit") // Add this to check if the request reaches here

	var dnsServer string
	var err error

	// If useCachedDns is true, get the system's DNS server, otherwise use 8.8.8.8
	if useCachedDns {
		// Use the system DNS server
		dnsServer, err = getSystemDNSServer()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to get system DNS server: %v", err)
		}
		log.Println("Using system DNS server:", dnsServer)
	} else {
		// Use Google's DNS server (8.8.8.8)
		dnsServer = "8.8.8.8:53"
		log.Println("Using Google's DNS server: 8.8.8.8")
	}

	cnameRecords, err := net.LookupCNAME(domain)
	if err != nil && !isNotFoundError(err) {
		return nil, nil, err
	}

	// Custom DNS query to fetch A records with TTL using the miekg/dns package
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)

	// Use the system's default resolver, no need to specify a DNS server
	c := new(dns.Client)
	in, _, err := c.Exchange(m, dnsServer) // Use the retrieved DNS server
	if err != nil {
		log.Println("DNS Analyze handler hit error")
		return nil, nil, fmt.Errorf("failed to query DNS: %v", err)
	}

	var aRecordsWithTTL []DNSRecordWithTTL
	for _, ans := range in.Answer {
		if a, ok := ans.(*dns.A); ok {
			aRecordsWithTTL = append(aRecordsWithTTL, DNSRecordWithTTL{
				IP:  a.A.String(),
				TTL: a.Header().Ttl,
			})
		}
	}

	return []string{cnameRecords}, aRecordsWithTTL, nil
}

func analyzeTCPHandshake(target string) (TCPResults, error) {
	results := TCPResults{}
	addr, err := net.ResolveTCPAddr("tcp", target)
	if err != nil {
		return results, fmt.Errorf("error resolving address: %v", err)
	}

	var conn net.Conn

	// Try to connect via TCP first
	conn, err = net.DialTCP("tcp", nil, addr)
	if err != nil {
		// If TCP connection fails, try TLS
		conn, err = tls.Dial("tcp", target, &tls.Config{
			InsecureSkipVerify: true,
		})
		if err != nil {
			return results, fmt.Errorf("error connecting to target: %v", err)
		}
	}
	defer conn.Close()

	// Send an HTTP GET request
	httpRequest := "GET / HTTP/1.1\r\nHost: " + addr.IP.String() + "\r\nConnection: close\r\n\r\n"
	_, err = conn.Write([]byte(httpRequest))
	if err != nil {
		return results, fmt.Errorf("error writing to connection: %v", err)
	}

	// Set a longer timeout and increase retries
	conn.SetReadDeadline(time.Now().Add(15 * time.Second)) // Increased timeout

	buf := make([]byte, 4096) // Increased buffer size
	totalRead := 0
	maxRetries := 10
	retryInterval := 1 * time.Second

	var readErr error
	for retries := 0; retries < maxRetries; retries++ {
		n, err := conn.Read(buf[totalRead:])
		if n > 0 {
			totalRead += n
		}
		if err == nil {
			// Successfully read data
			break
		}
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			fmt.Println("Read timed out, retrying...")
			time.Sleep(retryInterval) // Wait before retrying
			continue
		}
		readErr = err
		fmt.Printf("Error reading data: %v\n", err)
		break
	}

	if totalRead == 0 {
		return results, fmt.Errorf("no data received from %s after %d attempts: %v", addr, maxRetries, readErr)
	}

	// Analyze the response data
	responseData := buf[:totalRead]
	response, err := analyzeTCPResponse(responseData)
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

func (r *TCPResponse) String() string {
	return fmt.Sprintf("SourcePort: %d, DestinationPort: %d, SequenceNumber: %d, AckNumber: %d, DataOffset: %d, Flags: %08b, WindowSize: %d, Checksum: %d, UrgentPointer: %d, SYN: %t, ACK: %t, FIN: %t, RST: %t, PSH: %t, URG: %t, ECE: %t, CWR: %t, TCPOptions: %x",
		r.SourcePort, r.DestinationPort, r.SequenceNumber, r.AckNumber, r.DataOffset, r.Flags, r.WindowSize, r.Checksum, r.UrgentPointer,
		r.SYNFlag, r.ACKFlag, r.FINFlag, r.RSTFlag, r.PSHFlag, r.URGFlag, r.ECEFlag, r.CWRFlag, r.TCPOptions)
}

func isNotFoundError(err error) bool {
	dnsErr, ok := err.(*net.DNSError)
	return ok && (dnsErr.Err == "no such host" || dnsErr.IsNotFound)
}
