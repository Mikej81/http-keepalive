/**
 * HTTP Keep-Alive Analyzer - Modern JavaScript Application
 * @description Client-side application for domain analysis
 */

'use strict';

class DomainAnalyzer {
  constructor() {
    this.elements = {};
    this.chart = null;
    this.isAnalyzing = false;
    
    this.init();
  }

  /**
   * Initialize the application
   */
  init() {
    this.cacheElements();
    this.bindEvents();
    this.initializeTabs();
    this.setInitialState();
    
    // Check if Chart.js is available
    if (typeof Chart === 'undefined') {
      console.warn('Chart.js not loaded. Charts will be disabled.');
    }
  }

  /**
   * Cache DOM elements for better performance
   */
  cacheElements() {
    this.elements = {
      form: document.getElementById('domainForm'),
      domainInput: document.getElementById('domain'),
      useCachedDns: document.getElementById('useCachedDns'),
      domainError: document.getElementById('domain-error'),
      loading: document.getElementById('loading'),
      error: document.getElementById('error'),
      errorMessage: document.getElementById('error-message'),
      retryBtn: document.getElementById('retry-btn'),
      results: document.getElementById('results'),
      summaryContent: document.getElementById('summary-content'),
      
      // Tab elements
      tabs: document.querySelectorAll('.tabs__tab'),
      tabPanels: document.querySelectorAll('.tab-panel'),
      
      // Result containers
      chartCanvas: document.getElementById('analysisChart'),
      dnsResults: document.getElementById('dns-results'),
      headersResults: document.getElementById('headers-results'),
      tcpResults: document.getElementById('tcp-results'),
      cspResults: document.getElementById('csp-results'),
    };
    
    // Debug: Log missing elements (development only)
    if (location.hostname === 'localhost' || location.hostname === '127.0.0.1') {
      Object.entries(this.elements).forEach(([key, element]) => {
        if (!element || (element.length === 0 && element.length !== undefined)) {
          console.warn(`Element not found: ${key}`);
        }
      });
    }
  }

  /**
   * Bind event listeners
   */
  bindEvents() {
    // Form submission
    if (this.elements.form) {
      this.elements.form.addEventListener('submit', (e) => this.handleFormSubmit(e));
    } else {
      console.error('Form element not found - check HTML structure');
    }
    
    // Tab navigation
    this.elements.tabs.forEach(tab => {
      tab.addEventListener('click', (e) => this.handleTabClick(e));
      tab.addEventListener('keydown', (e) => this.handleTabKeydown(e));
    });
    
    // Retry button
    this.elements.retryBtn?.addEventListener('click', () => this.retryAnalysis());
    
    // Domain input validation
    this.elements.domainInput?.addEventListener('input', () => this.validateDomainInput());
  }

  /**
   * Initialize tab functionality
   */
  initializeTabs() {
    // Activate first tab by default
    if (this.elements.tabs.length > 0) {
      this.activateTab(this.elements.tabs[0]);
    }
  }

  /**
   * Set initial page state
   */
  setInitialState() {
    // Hide loading, error, and results by default
    this.hideLoading();
    this.hideError();
    this.hideResults();
    
    // Reset form state
    this.setLoadingState(false);
    this.clearDomainError();
    
    // Application ready
    if (location.hostname === 'localhost' || location.hostname === '127.0.0.1') {
      console.log('HTTP Keep-Alive Analyzer initialized');
    }
  }

  /**
   * Handle form submission
   * @param {Event} event - Form submit event
   */
  async handleFormSubmit(event) {
    event.preventDefault();
    
    if (this.isAnalyzing) {
      return;
    }
    
    let domain = this.elements.domainInput?.value?.trim();
    const useCachedDns = this.elements.useCachedDns?.checked || false;
    
    // Simple URL normalization - remove paths but keep domain
    if (domain && domain.includes('/')) {
      try {
        // If it looks like a URL, extract just the origin
        if (domain.startsWith('http://') || domain.startsWith('https://')) {
          const url = new URL(domain);
          domain = url.origin;
        } else {
          // If it's just domain/path, take only the first part
          domain = domain.split('/')[0];
        }
      } catch (e) {
        // If URL parsing fails, just remove everything after first slash
        domain = domain.split('/')[0];
      }
    }
    
    if (!this.validateDomain(domain)) {
      return;
    }
    
    try {
      this.setLoadingState(true);
      this.clearPreviousResults();
      
      const result = await this.analyzeDomain({ domain, useCachedDns });
      this.displayResults(result);
      
    } catch (error) {
      console.error('Analysis failed:', error);
      this.displayError(error.message || 'An unexpected error occurred');
    } finally {
      this.setLoadingState(false);
    }
  }

  /**
   * Validate domain input
   * @param {string} domain - Domain to validate
   * @returns {boolean} - Whether domain is valid
   */
  validateDomain(domain) {
    if (!domain) {
      this.showDomainError('Please enter a domain name');
      return false;
    }
    
    // Very basic validation - just check it's not empty and has a dot
    if (domain.length < 4 || !domain.includes('.')) {
      this.showDomainError('Please enter a valid domain name');
      return false;
    }
    
    this.clearDomainError();
    return true;
  }


  /**
   * Validate domain input on input event
   */
  validateDomainInput() {
    const domain = this.elements.domainInput?.value?.trim();
    
    if (domain && !this.validateDomain(domain)) {
      // Don't show error on empty input during typing
      return;
    }
    
    this.clearDomainError();
  }

  /**
   * Show domain validation error
   * @param {string} message - Error message
   */
  showDomainError(message) {
    if (this.elements.domainError) {
      this.elements.domainError.textContent = message;
      this.elements.domainInput?.setAttribute('aria-invalid', 'true');
    }
  }

  /**
   * Clear domain validation error
   */
  clearDomainError() {
    if (this.elements.domainError) {
      this.elements.domainError.textContent = '';
      this.elements.domainInput?.setAttribute('aria-invalid', 'false');
    }
  }

  /**
   * Analyze domain via API
   * @param {Object} data - Analysis request data
   * @returns {Promise<Object>} - Analysis result
   */
  async analyzeDomain(data) {
    const response = await fetch('/analyze', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(data),
    });
    
    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(`Analysis failed: ${errorText}`);
    }
    
    return await response.json();
  }

  /**
   * Set loading state
   * @param {boolean} loading - Whether to show loading state
   */
  setLoadingState(loading) {
    this.isAnalyzing = loading;
    
    // Update submit button
    const submitBtn = this.elements.form?.querySelector('button[type="submit"]');
    if (submitBtn) {
      submitBtn.disabled = loading;
      submitBtn.classList.toggle('btn--loading', loading);
    }
    
    // Show/hide loading indicator
    if (this.elements.loading) {
      this.elements.loading.setAttribute('aria-hidden', !loading);
      this.elements.loading.style.display = loading ? 'block' : 'none';
    }
    
    // Hide error and results during loading
    if (loading) {
      this.hideError();
      this.hideResults();
    }
  }

  /**
   * Clear previous results
   */
  clearPreviousResults() {
    // Clear result containers
    Object.values(this.elements).forEach(element => {
      if (element?.classList?.contains('results-content')) {
        element.innerHTML = '';
      }
    });
    
    // Destroy existing chart but don't destroy the canvas
    if (this.chart) {
      this.chart.destroy();
      this.chart = null;
    }
  }

  /**
   * Display analysis results
   * @param {Object} data - Analysis result data
   */
  displayResults(data) {
    this.hideError();
    this.hideLoading();
    
    if (!data || !data.responses || data.responses.length === 0) {
      this.displayError('No analysis data received');
      return;
    }
    
    // Show results container
    this.showResults();
    
    // Update summary
    this.updateSummary(data);
    
    // Update all result sections
    this.updateDnsResults(data);
    this.updateHeadersResults(data);
    this.updateTcpResults(data);
    this.updateCspResults(data);
    this.updateChart(data);
    
    // Activate overview tab
    const overviewTab = document.querySelector('.tabs__tab[data-target="overview"]');
    if (overviewTab) {
      this.activateTab(overviewTab);
    }
  }

  /**
   * Update analysis summary
   * @param {Object} data - Analysis result data
   */
  updateSummary(data) {
    if (!this.elements.summaryContent) return;
    
    const responses = data.responses || [];
    const cnameRecords = data.cnameRecords || data.CNAMERecords || [];
    const aRecords = data.aRecords || data.ARecords || [];
    
    // Analyze server fingerprinting and CDN detection
    const serverFingerprint = this.analyzeServerFingerprint(responses);
    const cdnDetection = this.analyzeCDNDetection(responses);
    
    const summaryHtml = `
      <div class="cdn-detection">
        <h4>🌐 CDN Detection</h4>
        <div class="cdn-info">
          ${cdnDetection.map(cdn => `
            <div class="cdn-item ${cdn.detected ? 'detected' : 'not-detected'}" 
                 title="${this.createCDNTooltip(cdn)}"
                 data-evidence='${JSON.stringify(cdn.evidence)}'>
              <div class="cdn-item-header">
                <span class="cdn-name">${cdn.name}</span>
                ${cdn.evidence.length > 0 ? `<span class="evidence-indicator" title="Hover for details">ℹ️</span>` : ''}
              </div>
              <span class="cdn-status">${cdn.status}</span>
              <span class="cdn-confidence confidence-${cdn.confidence.toLowerCase()}">${cdn.confidence}</span>
            </div>
          `).join('')}
        </div>
      </div>

      <div class="summary-stats">
        <div class="stat">
          <span class="stat__label">A Records Found:</span>
          <span class="stat__value">${aRecords.length}</span>
        </div>
        <div class="stat">
          <span class="stat__label">Successful Responses:</span>
          <span class="stat__value">${responses.filter(r => !r.error).length}</span>
        </div>
        <div class="stat">
          <span class="stat__label">Average Response Time:</span>
          <span class="stat__value">${this.calculateAverageResponseTime(responses)}ms</span>
        </div>
      </div>
      
      <div class="server-fingerprint">
        <h4>🖥️ Server Fingerprint</h4>
        <div class="fingerprint-info">
          <div class="fingerprint-item">
            <span class="label">Server Type:</span>
            <span class="value ${serverFingerprint.confidence.toLowerCase()}-confidence">${serverFingerprint.type}</span>
          </div>
          <div class="fingerprint-item">
            <span class="label">Version:</span>
            <span class="value">${serverFingerprint.version}</span>
          </div>
          <div class="fingerprint-item">
            <span class="label">Platform:</span>
            <span class="value">${serverFingerprint.platform}</span>
          </div>
          <div class="fingerprint-item">
            <span class="label">Confidence:</span>
            <span class="value confidence-${serverFingerprint.confidence.toLowerCase()}">${serverFingerprint.confidence}</span>
          </div>
          ${serverFingerprint.loadBalancer !== 'Unknown' ? `
          <div class="fingerprint-item">
            <span class="label">Load Balancer:</span>
            <span class="value">${serverFingerprint.loadBalancer}</span>
          </div>
          ` : ''}
        </div>
      </div>
    `;
    
    this.elements.summaryContent.innerHTML = summaryHtml;
  }

  /**
   * Calculate average response time
   * @param {Array} responses - Response array
   * @returns {number} - Average response time
   */
  calculateAverageResponseTime(responses) {
    const validResponses = responses.filter(r => !r.error && r.requestDuration);
    if (validResponses.length === 0) return 0;
    
    const total = validResponses.reduce((sum, r) => sum + (r.requestDuration || 0), 0);
    return Math.round(total / validResponses.length);
  }

  /**
   * Analyze server fingerprinting from responses
   * @param {Array} responses - Response array
   * @returns {Object} - Server fingerprint analysis
   */
  analyzeServerFingerprint(responses) {
    const validResponses = responses.filter(r => !r.error && r.serverInfo);
    
    if (validResponses.length === 0) {
      return {
        type: 'Unknown',
        version: 'Unknown',
        platform: 'Unknown',
        confidence: 'Low',
        loadBalancer: 'Unknown'
      };
    }

    // Use the first valid response for fingerprinting
    const serverInfo = validResponses[0].serverInfo;
    
    return {
      type: serverInfo.serverType || 'Unknown',
      version: serverInfo.version || 'Unknown',
      platform: serverInfo.platform || 'Unknown',
      confidence: serverInfo.confidence || 'Low',
      loadBalancer: serverInfo.loadBalancer || 'Unknown'
    };
  }

  /**
   * Analyze CDN detection from responses with confidence levels
   * @param {Array} responses - Response array
   * @returns {Array} - CDN detection results with confidence and evidence
   */
  analyzeCDNDetection(responses) {
    const validResponses = responses.filter(r => !r.error && (r.cdnDetections || r.cdnInfo));
    
    if (validResponses.length === 0) {
      return [
        { name: 'Cloudflare', detected: false, status: 'Not Detected', confidence: 'Low', evidence: [] },
        { name: 'CloudFront', detected: false, status: 'Not Detected', confidence: 'Low', evidence: [] },
        { name: 'Akamai', detected: false, status: 'Not Detected', confidence: 'Low', evidence: [] },
        { name: 'Fastly', detected: false, status: 'Not Detected', confidence: 'Low', evidence: [] },
        { name: 'KeyCDN', detected: false, status: 'Not Detected', confidence: 'Low', evidence: [] },
        { name: 'MaxCDN', detected: false, status: 'Not Detected', confidence: 'Low', evidence: [] },
        { name: 'Incapsula', detected: false, status: 'Not Detected', confidence: 'Low', evidence: [] },
        { name: 'Sucuri', detected: false, status: 'Not Detected', confidence: 'Low', evidence: [] }
      ];
    }

    // Use the first valid response for CDN detection
    const firstResponse = validResponses[0];
    const results = [];
    
    // Check if we have the new confidence-based detection
    if (firstResponse.cdnDetections) {
      const cdnDetections = firstResponse.cdnDetections;
      
      // Map the detections with proper naming
      const cdnMapping = {
        cloudflare: 'Cloudflare',
        cloudfront: 'CloudFront', 
        akamai: 'Akamai',
        fastly: 'Fastly',
        keycdn: 'KeyCDN',
        maxcdn: 'MaxCDN',
        incapsula: 'Incapsula',
        sucuri: 'Sucuri'
      };
      
      for (const [key, displayName] of Object.entries(cdnMapping)) {
        const detection = cdnDetections[key];
        if (detection) {
          results.push({
            name: displayName,
            detected: detection.detected,
            status: detection.detected ? detection.primaryEvidence || 'Detected' : 'Not Detected',
            confidence: detection.confidence || 'Low',
            evidence: detection.evidence || [],
            primaryEvidence: detection.primaryEvidence || ''
          });
        } else {
          results.push({
            name: displayName,
            detected: false,
            status: 'Not Detected',
            confidence: 'Low',
            evidence: [],
            primaryEvidence: ''
          });
        }
      }
    } else {
      // Fallback to old CDN detection format
      const cdnInfo = firstResponse.cdnInfo;
      
      return [
        { 
          name: 'Cloudflare', 
          detected: cdnInfo.cloudflare !== 'No', 
          status: cdnInfo.cloudflare === 'No' ? 'Not Detected' : cdnInfo.cloudflare,
          confidence: 'Unknown',
          evidence: [],
          primaryEvidence: cdnInfo.cloudflare !== 'No' ? cdnInfo.cloudflare : ''
        },
        { 
          name: 'CloudFront', 
          detected: cdnInfo.cloudfront !== 'No', 
          status: cdnInfo.cloudfront === 'No' ? 'Not Detected' : cdnInfo.cloudfront,
          confidence: 'Unknown', 
          evidence: [],
          primaryEvidence: cdnInfo.cloudfront !== 'No' ? cdnInfo.cloudfront : ''
        },
        { 
          name: 'Akamai', 
          detected: cdnInfo.akamai !== 'No', 
          status: cdnInfo.akamai === 'No' ? 'Not Detected' : cdnInfo.akamai,
          confidence: 'Unknown',
          evidence: [],
          primaryEvidence: cdnInfo.akamai !== 'No' ? cdnInfo.akamai : ''
        },
        { 
          name: 'Fastly', 
          detected: cdnInfo.fastly !== 'No', 
          status: cdnInfo.fastly === 'No' ? 'Not Detected' : cdnInfo.fastly,
          confidence: 'Unknown',
          evidence: [],
          primaryEvidence: cdnInfo.fastly !== 'No' ? cdnInfo.fastly : ''
        },
        { 
          name: 'KeyCDN', 
          detected: cdnInfo.keycdn !== 'No', 
          status: cdnInfo.keycdn === 'No' ? 'Not Detected' : cdnInfo.keycdn,
          confidence: 'Unknown',
          evidence: [],
          primaryEvidence: cdnInfo.keycdn !== 'No' ? cdnInfo.keycdn : ''
        },
        { 
          name: 'MaxCDN', 
          detected: cdnInfo.maxcdn !== 'No', 
          status: cdnInfo.maxcdn === 'No' ? 'Not Detected' : cdnInfo.maxcdn,
          confidence: 'Unknown',
          evidence: [],
          primaryEvidence: cdnInfo.maxcdn !== 'No' ? cdnInfo.maxcdn : ''
        },
        { 
          name: 'Incapsula', 
          detected: cdnInfo.incapsula !== 'No', 
          status: cdnInfo.incapsula === 'No' ? 'Not Detected' : cdnInfo.incapsula,
          confidence: 'Unknown',
          evidence: [],
          primaryEvidence: cdnInfo.incapsula !== 'No' ? cdnInfo.incapsula : ''
        },
        { 
          name: 'Sucuri', 
          detected: cdnInfo.sucuri !== 'No', 
          status: cdnInfo.sucuri === 'No' ? 'Not Detected' : cdnInfo.sucuri,
          confidence: 'Unknown',
          evidence: [],
          primaryEvidence: cdnInfo.sucuri !== 'No' ? cdnInfo.sucuri : ''
        }
      ];
    }
    
    return results;
  }

  /**
   * Create tooltip content for CDN detection
   * @param {Object} cdn - CDN detection object
   * @returns {string} - Tooltip content
   */
  createCDNTooltip(cdn) {
    if (!cdn.detected) {
      return `${cdn.name}\nStatus: Not detected\nNo CDN indicators found`;
    }
    
    let tooltip = `${cdn.name}\nConfidence: ${cdn.confidence}`;
    
    if (cdn.primaryEvidence) {
      tooltip += `\n\nPrimary Evidence:\n${cdn.primaryEvidence}`;
    }
    
    if (cdn.evidence && cdn.evidence.length > 0) {
      tooltip += `\n\nDetection Evidence:`;
      cdn.evidence.forEach((evidence, index) => {
        tooltip += `\n${index + 1}. ${evidence}`;
      });
    }
    
    return tooltip;
  }

  /**
   * Update DNS results
   * @param {Object} data - Analysis result data
   */
  updateDnsResults(data) {
    if (!this.elements.dnsResults) return;
    
    // Handle both old and new API response formats
    const cnameRecords = data.cnameRecords || data.CNAMERecords || [];
    const aRecords = data.aRecords || data.ARecords || [];
    
    let html = '<div class="table-container"><table><thead><tr><th>Type</th><th>Value</th><th>TTL</th></tr></thead><tbody>';
    
    // Add CNAME records
    cnameRecords.forEach(cname => {
      html += `<tr><td>CNAME</td><td>${this.escapeHtml(cname)}</td><td>N/A</td></tr>`;
    });
    
    // Add A records
    aRecords.forEach(record => {
      const ip = record.ip || record.IP;
      const ttl = record.ttl || record.TTL;
      const ttlDisplay = ttl ? `${Math.round(ttl / 1000000000)}s` : 'N/A';
      html += `<tr><td>A</td><td>${this.escapeHtml(ip)}</td><td>${ttlDisplay}</td></tr>`;
    });
    
    html += '</tbody></table></div>';
    
    this.elements.dnsResults.innerHTML = html;
  }

  /**
   * Update headers results
   * @param {Object} data - Analysis result data
   */
  updateHeadersResults(data) {
    if (!this.elements.headersResults) return;
    
    const { responses = [], stableHeaders = {} } = data;
    
    let html = '<div class="accordion">';
    
    responses.forEach((response, index) => {
      const responseHeaders = response.responseHeaders || {};
      
      // Show all headers, but highlight differing ones
      const differingHeaders = this.findDifferingHeaders(responseHeaders, stableHeaders);
      
      let contentHtml;
      if (Object.keys(responseHeaders).length > 0) {
        contentHtml = this.formatAllHeaders(responseHeaders, differingHeaders);
      } else {
        contentHtml = '<p>No headers available for this server.</p>';
      }
      
      html += this.createAccordionItem(
        `Server ${index + 1}: ${this.escapeHtml(response.domain)}`,
        contentHtml
      );
    });
    
    html += '</div>';
    
    this.elements.headersResults.innerHTML = html;
    this.initializeAccordions(this.elements.headersResults);
  }

  /**
   * Find headers that differ from stable headers
   * @param {Object} headers - Response headers
   * @param {Object} stableHeaders - Stable headers across all responses
   * @returns {Object} - Differing headers
   */
  findDifferingHeaders(headers, stableHeaders) {
    const differing = {};
    
    for (const [key, value] of Object.entries(headers)) {
      if (!stableHeaders.hasOwnProperty(key)) {
        differing[key] = value;
      }
    }
    
    return differing;
  }

  /**
   * Update TCP results
   * @param {Object} data - Analysis result data
   */
  updateTcpResults(data) {
    if (!this.elements.tcpResults) return;
    
    const { responses = [] } = data;
    
    let html = '<div class="accordion">';
    
    responses.forEach((response, index) => {
      let tcpData;
      try {
        tcpData = JSON.parse(response.tcpResults || '{}');
      } catch (e) {
        tcpData = { error: 'Failed to parse TCP results' };
      }
      
      const contentHtml = tcpData.tcpResponse 
        ? this.formatTcpData(tcpData.tcpResponse)
        : `<p>${tcpData.error || 'No TCP data available'}</p>`;
      
      html += this.createAccordionItem(
        `TCP Analysis for Server ${index + 1}`,
        contentHtml
      );
    });
    
    html += '</div>';
    
    this.elements.tcpResults.innerHTML = html;
    this.initializeAccordions(this.elements.tcpResults);
  }

  /**
   * Update CSP results
   * @param {Object} data - Analysis result data
   */
  updateCspResults(data) {
    if (!this.elements.cspResults) return;
    
    const { responses = [] } = data;
    
    if (responses.length === 0) {
      this.elements.cspResults.innerHTML = '<p>No CSP data available.</p>';
      return;
    }
    
    const firstResponse = responses[0];
    const cspDetails = firstResponse.cspDetails || 'No CSP policy generated';
    
    const html = `
      <div class="csp-result">
        <h4>Generated CSP for: ${this.escapeHtml(firstResponse.domain)}</h4>
        <pre><code>${this.escapeHtml(cspDetails)}</code></pre>
      </div>
    `;
    
    this.elements.cspResults.innerHTML = html;
  }

  /**
   * Update analysis chart
   * @param {Object} data - Analysis result data
   */
  updateChart(data) {
    if (!this.elements.chartCanvas || typeof Chart === 'undefined') {
      return;
    }
    
    const responses = data.responses || [];
    const aRecords = data.aRecords || data.ARecords || [];
    
    // Simple validation
    if (aRecords.length === 0 || responses.length === 0) {
      return;
    }
    
    // Prepare chart data - keep it simple
    const labels = aRecords.map(record => record.ip || record.IP);
    const keepAliveData = responses.map(response => {
      if (response.error) return 0;
      const timeout = parseInt(response.keepAliveTimeout, 10);
      return isNaN(timeout) ? 0 : timeout;
    });
    const durationData = responses.map(response => {
      if (response.error) return 0;
      return response.requestDuration || 0;
    });
    
    const ctx = this.elements.chartCanvas.getContext('2d');
    
    // Destroy existing chart
    if (this.chart) {
      this.chart.destroy();
    }
    
    this.chart = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: labels,
        datasets: [{
          label: 'Keep-Alive Timeout (s)',
          data: keepAliveData,
          backgroundColor: 'rgba(37, 99, 235, 0.7)',
          borderColor: 'rgba(37, 99, 235, 1)',
          borderWidth: 2
        }, {
          label: 'Request Duration (ms)',
          data: durationData,
          backgroundColor: 'rgba(16, 185, 129, 0.7)',
          borderColor: 'rgba(16, 185, 129, 1)',
          borderWidth: 2
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'top',
            labels: {
              color: '#ffffff'
            }
          },
          title: {
            display: true,
            text: 'Keep-Alive Analysis by Server IP',
            color: '#ffffff'
          }
        },
        scales: {
          y: {
            beginAtZero: true,
            grid: {
              color: 'rgba(255, 255, 255, 0.1)'
            },
            ticks: {
              color: '#ffffff'
            },
            title: {
              color: '#ffffff'
            }
          },
          x: {
            grid: {
              color: 'rgba(255, 255, 255, 0.1)'
            },
            ticks: {
              color: '#ffffff'
            },
            title: {
              color: '#ffffff'
            }
          }
        }
      }
    });
  }

  /**
   * Show chart no data message
   */
  showChartNoData() {
    if (this.chart) {
      this.chart.destroy();
      this.chart = null;
    }
    
    // Don't replace the canvas container, just show a message
    console.warn('No data available for chart display');
  }

  /**
   * Show chart error message
   * @param {string} message - Error message
   */
  showChartError(message) {
    if (this.chart) {
      this.chart.destroy();
      this.chart = null;
    }
    
    // Don't replace the canvas container, just log the error
    console.error('Chart error:', message);
  }

  /**
   * Format headers for display
   * @param {Object} headers - Headers object
   * @param {boolean} highlight - Whether to highlight as differing
   * @returns {string} - Formatted HTML
   */
  formatHeaders(headers, highlight = false) {
    if (!headers || typeof headers !== 'object') {
      return '<p>No headers available.</p>';
    }
    
    let html = '<div class="table-container"><table><thead><tr><th>Header</th><th>Value</th></tr></thead><tbody>';
    
    for (const [key, value] of Object.entries(headers)) {
      const displayValue = Array.isArray(value) ? value.join(', ') : value;
      const rowClass = highlight ? ' class="diff-header"' : '';
      const keyDisplay = highlight ? `! ${key}` : key;
      
      html += `<tr${rowClass}><td>${this.escapeHtml(keyDisplay)}</td><td>${this.escapeHtml(displayValue)}</td></tr>`;
    }
    
    html += '</tbody></table></div>';
    return html;
  }

  /**
   * Format all headers with differing ones highlighted
   * @param {Object} allHeaders - All response headers
   * @param {Object} differingHeaders - Headers that differ from stable ones
   * @returns {string} - Formatted HTML
   */
  formatAllHeaders(allHeaders, differingHeaders) {
    if (!allHeaders || typeof allHeaders !== 'object') {
      return '<p>No headers available.</p>';
    }
    
    let html = '<div class="table-container"><table><thead><tr><th>Header</th><th>Value</th><th>Status</th></tr></thead><tbody>';
    
    for (const [key, value] of Object.entries(allHeaders)) {
      const displayValue = Array.isArray(value) ? value.join(', ') : value;
      const isDiffering = differingHeaders.hasOwnProperty(key);
      const rowClass = isDiffering ? ' class="diff-header"' : '';
      const status = isDiffering ? 'Different' : 'Stable';
      
      html += `<tr${rowClass}><td>${this.escapeHtml(key)}</td><td>${this.escapeHtml(displayValue)}</td><td>${status}</td></tr>`;
    }
    
    html += '</tbody></table></div>';
    return html;
  }

  /**
   * Format TCP data for display
   * @param {Object} tcp - TCP data object
   * @returns {string} - Formatted HTML
   */
  formatTcpData(tcp) {
    if (!tcp) return '<p>No TCP data available</p>';
    
    const flags = [
      `SYN: ${tcp.synFlag || false}`,
      `ACK: ${tcp.ackFlag || false}`,
      `FIN: ${tcp.finFlag || false}`,
      `RST: ${tcp.rstFlag || false}`,
      `PSH: ${tcp.pshFlag || false}`,
      `URG: ${tcp.urgFlag || false}`,
      `ECE: ${tcp.eceFlag || false}`,
      `CWR: ${tcp.cwrFlag || false}`
    ].join('<br>');
    
    // Enhanced TCP analysis display
    return `
      <div class="tcp-analysis">
        <div class="tcp-connection-info">
          <h5>🔗 Connection Analysis</h5>
          <div class="table-container">
            <table>
              <tbody>
                <tr><th>Connection Time</th><td>${tcp.connectTime || 'N/A'}ms</td></tr>
                <tr><th>Connection Quality</th><td class="quality-${(tcp.connectionQuality || 'unknown').toLowerCase()}">${tcp.connectionQuality || 'Unknown'}</td></tr>
                <tr><th>Keep-Alive Supported</th><td>${tcp.keepAliveSupported ? '✅ Yes' : '❌ No'}</td></tr>
                <tr><th>Write Latency</th><td>${tcp.writeLatency || 'N/A'}ms</td></tr>
                <tr><th>Read Latency</th><td>${tcp.readLatency || 'N/A'}ms</td></tr>
              </tbody>
            </table>
          </div>
        </div>
        
        <div class="tcp-packet-info">
          <h5>📊 TCP Details</h5>
          <div class="table-container">
            <table>
              <tbody>
                <tr><th>Source Port</th><td>${tcp.sourcePort || 'N/A'}</td></tr>
                <tr><th>Destination Port</th><td>${tcp.destinationPort || 'N/A'}</td></tr>
                <tr><th>Window Size</th><td>${tcp.windowSize || 'N/A'}</td></tr>
                <tr><th>TCP Flags</th><td>${flags}</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    `;
  }

  /**
   * Create accordion item HTML
   * @param {string} title - Accordion title
   * @param {string} content - Accordion content
   * @returns {string} - Accordion HTML
   */
  createAccordionItem(title, content) {
    return `
      <div class="accordion-item">
        <button class="accordion-header" type="button">
          ${this.escapeHtml(title)}
        </button>
        <div class="accordion-body">
          ${content}
        </div>
      </div>
    `;
  }

  /**
   * Initialize accordion functionality
   * @param {Element} container - Container element
   */
  initializeAccordions(container) {
    const headers = container.querySelectorAll('.accordion-header');
    
    headers.forEach(header => {
      header.addEventListener('click', () => {
        const body = header.nextElementSibling;
        const isActive = header.classList.contains('active');
        
        // Close all accordions in this container
        container.querySelectorAll('.accordion-header').forEach(h => {
          h.classList.remove('active');
          h.nextElementSibling.classList.remove('active');
        });
        
        // Toggle current accordion
        if (!isActive) {
          header.classList.add('active');
          body.classList.add('active');
        }
      });
    });
  }

  /**
   * Handle tab click
   * @param {Event} event - Click event
   */
  handleTabClick(event) {
    const tab = event.currentTarget;
    this.activateTab(tab);
  }

  /**
   * Handle tab keyboard navigation
   * @param {Event} event - Keydown event
   */
  handleTabKeydown(event) {
    const { key } = event;
    const currentTab = event.currentTarget;
    const tabs = Array.from(this.elements.tabs);
    const currentIndex = tabs.indexOf(currentTab);
    
    let newIndex = currentIndex;
    
    switch (key) {
      case 'ArrowLeft':
        newIndex = currentIndex > 0 ? currentIndex - 1 : tabs.length - 1;
        break;
      case 'ArrowRight':
        newIndex = currentIndex < tabs.length - 1 ? currentIndex + 1 : 0;
        break;
      case 'Home':
        newIndex = 0;
        break;
      case 'End':
        newIndex = tabs.length - 1;
        break;
      default:
        return;
    }
    
    event.preventDefault();
    tabs[newIndex].focus();
    this.activateTab(tabs[newIndex]);
  }

  /**
   * Activate a tab
   * @param {Element} tab - Tab element to activate
   */
  activateTab(tab) {
    const target = tab.dataset.target;
    
    // Update tab states
    this.elements.tabs.forEach(t => {
      const isActive = t === tab;
      t.setAttribute('aria-selected', isActive);
      t.classList.toggle('active', isActive);
    });
    
    // Update panel states
    this.elements.tabPanels.forEach(panel => {
      const isActive = panel.id === `${target}-panel`;
      panel.setAttribute('aria-hidden', !isActive);
      panel.classList.toggle('tab-panel--active', isActive);
      
      if (isActive) {
        panel.focus();
      }
    });
  }

  /**
   * Display error message
   * @param {string} message - Error message
   */
  displayError(message) {
    this.hideLoading();
    this.hideResults();
    
    if (this.elements.errorMessage) {
      this.elements.errorMessage.textContent = message;
    }
    
    if (this.elements.error) {
      this.elements.error.setAttribute('aria-hidden', 'false');
      this.elements.error.style.display = 'block';
    }
  }

  /**
   * Hide error message
   */
  hideError() {
    if (this.elements.error) {
      this.elements.error.setAttribute('aria-hidden', 'true');
      this.elements.error.style.display = 'none';
    }
  }

  /**
   * Hide loading indicator
   */
  hideLoading() {
    if (this.elements.loading) {
      this.elements.loading.setAttribute('aria-hidden', 'true');
      this.elements.loading.style.display = 'none';
    }
  }

  /**
   * Show results container
   */
  showResults() {
    if (this.elements.results) {
      this.elements.results.setAttribute('aria-hidden', 'false');
      this.elements.results.style.display = 'block';
    }
  }

  /**
   * Hide results container
   */
  hideResults() {
    if (this.elements.results) {
      this.elements.results.setAttribute('aria-hidden', 'true');
      this.elements.results.style.display = 'none';
    }
  }

  /**
   * Retry analysis
   */
  retryAnalysis() {
    if (this.elements.form) {
      this.elements.form.dispatchEvent(new Event('submit'));
    }
  }

  /**
   * Escape HTML to prevent XSS
   * @param {string} text - Text to escape
   * @returns {string} - Escaped text
   */
  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  }
}

// Initialize application when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  new DomainAnalyzer();
});