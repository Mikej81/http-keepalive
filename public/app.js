document.addEventListener('DOMContentLoaded', function () {
    const form = document.getElementById('domainForm');
    const dnsDiv = document.getElementById('dns_results');
    const tcpDiv = document.getElementById('tcp_results');
    const resultsDiv = document.getElementById('results');

    form.addEventListener('submit', function (event) {
        event.preventDefault(); // Prevent the default form submission

        const domainInput = document.getElementById('domain').value;
        const data = { domain: domainInput };

        // Clear previous results and hide the divs
        resultsDiv.innerHTML = '';
        resultsDiv.style.display = 'none';
        dnsDiv.innerHTML = 'Loading DNS Results...';
        dnsDiv.style.display = 'none';
        tcpDiv.innerHTML = 'Loading TCP Results...';
        tcpDiv.style.display = 'none';

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
                // Update DNS Results
                dnsDiv.innerHTML = '<h3>DNS Results</h3>' +
                    '<table><tr><th>Type</th><th>Value</th></tr>' +
                    data.cnameRecords.map(record => `<tr><td>CNAME</td><td>${record}</td></tr>`).join('') +
                    data.aRecords.map(record => `<tr><td>A</td><td>${record}</td></tr>`).join('') +
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
                    const tcpContent = `
                        <h3>TCP Results</h3>
                        <table>
                            <tr><th>Field</th><th>Value</th></tr>
                            ${Object.entries(tcpData.tcp_response).map(([key, value]) => `
                                <tr><td>${key}</td><td>${value}</td></tr>
                            `).join('')}
                        </table>
                    `;
                    tcpDiv.innerHTML = tcpContent;
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
        const ctx = document.getElementById('analysisChart').getContext('2d');
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
