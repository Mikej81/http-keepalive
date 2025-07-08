package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"http-keepalive/internal/config"
	"http-keepalive/internal/csp"
	"http-keepalive/internal/dns"
	"http-keepalive/internal/handlers"
	httpAnalyzer "http-keepalive/internal/http"
	"http-keepalive/internal/tcp"
)

func main() {
	// Load configuration
	cfg := config.Load()
	if err := cfg.Validate(); err != nil {
		log.Fatalf("Configuration validation failed: %v", err)
	}

	// Initialize dependencies
	deps, dnsConfig := initializeDependencies(cfg)

	// Create service
	service := handlers.NewAnalysisService(deps, dnsConfig)

	// Create handlers
	handlerConfig := &handlers.Config{
		PublicDir:    cfg.Server.PublicDir,
		TemplateDir:  cfg.Server.PublicDir,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}
	handler := handlers.New(service, handlerConfig)

	// Setup HTTP server
	server := setupHTTPServer(cfg, handler)

	// Start server with graceful shutdown
	startServerWithGracefulShutdown(server)
}

// initializeDependencies creates all service dependencies
func initializeDependencies(cfg *config.Config) (*handlers.Dependencies, *dns.Config) {
	// Initialize DNS resolver
	dnsConfig := &dns.Config{
		UseCachedDNS: cfg.DNS.UseCachedDNS,
		DNSServer:    cfg.DNS.DefaultServer,
		Timeout:      cfg.DNS.Timeout,
	}
	dnsResolver := dns.NewResolver(dnsConfig)

	// Initialize HTTP analyzer
	httpConfig := &httpAnalyzer.Config{
		Timeout:            cfg.HTTP.Timeout,
		InsecureSkipVerify: cfg.HTTP.InsecureSkipVerify,
		MaxRedirects:       cfg.HTTP.MaxRedirects,
		UserAgent:          cfg.HTTP.UserAgent,
	}
	httpAnalyzer := httpAnalyzer.NewAnalyzer(httpConfig)

	// Initialize TCP analyzer
	tcpConfig := &tcp.Config{
		Timeout:    cfg.TCP.Timeout,
		MaxRetries: cfg.TCP.MaxRetries,
		RetryDelay: cfg.TCP.RetryDelay,
		BufferSize: cfg.TCP.BufferSize,
	}
	tcpAnalyzer := tcp.NewAnalyzer(tcpConfig)

	// Initialize CSP evaluator
	cspConfig := &csp.Config{
		Timeout:         cfg.CSP.Timeout,
		UserAgent:       cfg.CSP.UserAgent,
		MaxDepth:        cfg.CSP.MaxDepth,
		FollowRedirects: cfg.CSP.FollowRedirects,
	}
	cspEvaluator := csp.NewEvaluator(cspConfig)

	return &handlers.Dependencies{
		DNSResolver:  dnsResolver,
		HTTPAnalyzer: httpAnalyzer,
		TCPAnalyzer:  tcpAnalyzer,
		CSPEvaluator: cspEvaluator,
	}, dnsConfig
}

// setupHTTPServer creates and configures the HTTP server
func setupHTTPServer(cfg *config.Config, handler *handlers.Handler) *http.Server {
	mux := http.NewServeMux()
	handler.SetupRoutes(mux)

	server := &http.Server{
		Addr:         cfg.Server.Port,
		Handler:      mux,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
		IdleTimeout:  cfg.Server.IdleTimeout,
	}

	return server
}

// startServerWithGracefulShutdown starts the server and handles graceful shutdown
func startServerWithGracefulShutdown(server *http.Server) {
	// Create a channel to receive OS signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Start server in a goroutine
	go func() {
		log.Printf("Server starting on %s", server.Addr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed to start: %v", err)
		}
	}()

	// Wait for termination signal
	<-sigChan
	log.Println("Server shutting down...")

	// Create shutdown context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Attempt graceful shutdown
	if err := server.Shutdown(ctx); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
	} else {
		log.Println("Server stopped gracefully")
	}
}