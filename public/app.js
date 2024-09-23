document.addEventListener('DOMContentLoaded', function () {
    const form = document.getElementById('domainForm');
    const dnsDiv = document.getElementById('dns_results');
    const tcpDiv = document.getElementById('tcp_results');
    const resultsDiv = document.getElementById('results');
    const tcpHeaderTable = document.getElementById('tcp_header');

    form.addEventListener('submit', function (event) {
        event.preventDefault(); // Prevent the default form submission

        const domainInput = document.getElementById('domain').value;
        const data = { domain: domainInput };

        // Clear previous results and hide the divs
        resultsDiv.innerHTML = '';
        resultsDiv.style.display = 'none';
        dnsDiv.innerHTML = 'Loading DNS Results...';
        dnsDiv.style.display = 'none';

        // Make the HTTP request using Fetch API to the server-side `/analyze` endpoint
        fetch('/analyze', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(data),
        })
            .then(response => {
                if (!response.ok) {
                    throw new Error(`HTTP error! status: ${response.status}`);
                }
                return response.json();
            })
            .then(data => {
                // Safely handle cnameRecords and aRecordsWithTTL
                const cnameRecords = Array.isArray(data.cnameRecords) ? data.cnameRecords : [];
                const aRecordsWithTTL = Array.isArray(data.aRecordsWithTTL) ? data.aRecordsWithTTL : [];

                // Update DNS Results with TTL for A records
                dnsDiv.innerHTML = '<h3>DNS Results</h3>' +
                    '<table><tr><th>Type</th><th>Value</th><th>TTL</th></tr>' +
                    cnameRecords.map(record => `<tr><td>CNAME</td><td>${record}</td><td>N/A</td></tr>`).join('') + // CNAME doesn't have TTL in this example
                    aRecordsWithTTL.map(record => `<tr><td>A</td><td>${record.ip}</td><td>${record.ttl}</td></tr>`).join('') +
                    '</table>';
                dnsDiv.style.display = 'block'; // Show the div

                // Parse the tcpResults string to a JSON object
                let tcpData;
                try {
                    tcpData = JSON.parse(data.tcpResults);
                } catch (e) {
                    console.error('Failed to parse tcpResults:', e);
                    tcpDiv.innerHTML = 'Failed to parse TCP Results';
                    tcpDiv.style.display = 'block';
                    return;
                }

                // Update TCP Results
                if (tcpData && tcpData.tcp_response) {
                    const tcpResponse = tcpData.tcp_response;
                    const flagsContent = `
                        SYN: ${tcpResponse.syn_flag}<br>
                        ACK: ${tcpResponse.ack_flag}<br>
                        FIN: ${tcpResponse.fin_flag}<br>
                        RST: ${tcpResponse.rst_flag}<br>
                        PSH: ${tcpResponse.psh_flag}<br>
                        URG: ${tcpResponse.urg_flag}<br>
                        ECE: ${tcpResponse.ece_flag}<br>
                        CWR: ${tcpResponse.cwr_flag}
                    `;
                    const tcpHeaderContent = `
                        <tr>
                            <td colspan="2"><b>Source Port:</b><br/> ${tcpResponse.source_port}</td>
                            <td colspan="2"><b>Destination Port:</b><br/> ${tcpResponse.destination_port}</td>
                        </tr>
                        <tr>
                            <td colspan="4"><b>Sequence Number:</b><br/> ${tcpResponse.sequence_number}</td>
                        </tr>
                        <tr>
                            <td colspan="4"><b>Acknowledgement Number:</b><br/> ${tcpResponse.ack_number}</td>
                        </tr>
                        <tr>
                            <td><b>DO:</b><br> ${tcpResponse.data_offset}</td>
                            <td><b>Reserved</b></td>
                            <td><b>Flags:</b><br/>${flagsContent}</td>
                            <td><b>Window Size:</b><br/> ${tcpResponse.window_size}</td>
                        </tr>
                        <tr>
                            <td colspan="2"><b>Checksum:</b><br/> ${tcpResponse.checksum}</td>
                            <td colspan="2"><b>Urgent Pointer:</b><br/> ${tcpResponse.urgent_pointer}</td>
                        </tr>
                        <tr>
                            <td colspan="4"><b>Options:</b><br/> ${tcpResponse.tcp_options || 'None'}</td>
                        </tr>
                    `;
                    if (tcpHeaderTable) {
                        tcpHeaderTable.innerHTML = tcpHeaderContent;
                    }
                    tcpDiv.style.display = 'block'; // Show the div
                } else {
                    tcpDiv.innerHTML = 'No TCP Results';
                    tcpDiv.style.display = 'block';
                }

                // Convert keepAliveTimeout to a number if possible, else default to 0
                let keepAliveTimeout = parseInt(data.keepAliveTimeout, 10);
                if (!Number.isInteger(keepAliveTimeout)) {
                    keepAliveTimeout = 0; // Default to 0 if the value is non-numeric or not an integer
                }

                // Create content to display
                const content = `
                    <h2>Analysis Results for ${data.domain}</h2>
                    <p>Server-Side TLS Version: <b>${data.tlsVersion}</b></p>
                    <p><span style="color: lightgrey;">[Header]</span> Keep-Alive: Timeout=${data.keepAliveTimeout}</p>
                    <p><span style="color: lightgrey;">[Header]</span> Connection: ${data.connectionHeader}</p>
                    <p><span style="color: lightgrey;">[Header]</span> Server: ${data.serverHeader}</p>
                    <p><span style="color: lightgrey;">[Header]</span> X-Powered-By: ${data.poweredHeader}</p>
                    <p><span style="color: lightgrey;">[Header]</span> X-Forwarded-For/X-Real-IP: ${data.forwardHeader}</p>
                    <p><span style="color: lightgrey;">[Cache Detected]</span> ${data.xCacheHeader}</p>
                    <p><span style="color: lightgrey;">[Cloudflare Detected]</span> ${data.cloudflareHeader}</p>
                    <p><span style="color: lightgrey;">[Cloudfront Detected]</span> ${data.cloudfrontHeader}</p>
                     <p><span style="color: lightgrey;">[Akamai Detected]</span> ${data.akamaiHeader}</p>   
                    <p>Request Duration: ${data.requestDuration} milliseconds</p>
                `;
                resultsDiv.innerHTML = content;
                resultsDiv.style.display = 'block'; // Show the div

                // Update Chart
                updateChart(data.domain, keepAliveTimeout, data.requestDuration);
            })
            .catch(error => {
                console.error('Fetch Error:', error);
                dnsDiv.innerHTML = 'Failed to load DNS Results';
                dnsDiv.style.display = 'block'; // Show the div
                tcpDiv.innerHTML = 'Failed to load TCP Results';
                tcpDiv.style.display = 'block'; // Show the div
            });
    });

    function updateChart(domain, keepAliveTimeout, requestDuration) {
        const ctx = document.getElementById('analysisChart').getContext('2d', { willReadFrequently: true });
        if (window.myChart) {
            window.myChart.destroy(); // Destroy the existing chart instance if exists
        }
        window.myChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: [domain],
                datasets: [{
                    label: 'Keep-Alive Timeout (seconds)',
                    data: [keepAliveTimeout],
                    backgroundColor: 'rgba(255, 99, 132, 0.2)',
                    borderColor: 'rgba(255, 99, 132, 1)',
                    borderWidth: 1
                }, {
                    label: 'Request Duration (ms)',
                    data: [requestDuration],
                    backgroundColor: 'rgba(54, 162, 235, 0.2)',
                    borderColor: 'rgba(54, 162, 235, 1)',
                    borderWidth: 1
                }]
            },
            options: {
                scales: {
                    y: {
                        beginAtZero: true
                    }
                },
                responsive: true,
                plugins: {
                    legend: {
                        position: 'top',
                    },
                    title: {
                        display: true,
                        text: 'Domain Analysis: Keep-Alive Timeout vs. Request Duration'
                    }
                }
            }
        });
    }
});
