// Assuming the data received is an object with keys as labels and values as data points
// For example: { "Metric1": 10, "Metric2": 20, ... }

document.addEventListener('DOMContentLoaded', function () {
    const form = document.getElementById('domainForm');

    form.addEventListener('submit', function (event) {
        event.preventDefault(); // Prevent the default form submission

        const domainInput = document.getElementById('domain').value;
        const data = { domain: domainInput };

        console.log('Analyzing domain:', domainInput); // Debugging line to confirm function execution

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
                console.log('Analysis result:', data); // Debugging line to check the response
                displayResults(data);
            })
            .catch(error => {
                console.error('Fetch Error:', error);
            });
    });

    function displayResults(data) {
        const resultsDiv = document.getElementById('results');

        // Convert keepAliveTimeout to a number if possible, else default to 0
        let keepAliveTimeout = parseInt(data.keepAliveTimeout, 10);
        if (!Number.isInteger(keepAliveTimeout)) {
            keepAliveTimeout = 0; // Default to 0 if the value is non-numeric or not an integer
        }

        // Create content to display
        const content = `
        <h2>Analysis Results for ${data.domain}</h2>
        <p>Server-Side TLS Version:<b> ${data.tlsVersion}</b></p>
        <p><span style="color: lightgrey;">[Header]</span> Keep-Alive: Timeout=${data.keepAliveTimeout}</p>
        <p><span style="color: lightgrey;">[Header]</span> Connection: ${data.connectionHeader} </p>
        <p>Request Duration: ${data.requestDuration} milliseconds</p>
    `;
        resultsDiv.innerHTML = `<p>${content}</p>`;

        // Here you could also call a function to update a chart with the keepAliveTimeout value
        // For example, if displaying multiple domains' keep-alive values in a bar chart
        updateChart(data.domain, keepAliveTimeout, data.requestDuration);
    }

    function resetCanvas() {
        // Remove the existing canvas element
        const chartContainer = document.getElementById('chartContainer');
        chartContainer.innerHTML = '';

        // Create a new canvas element and append it to the chart container
        const canvas = document.createElement('canvas');
        canvas.id = 'analysisChart';
        chartContainer.appendChild(canvas);
    }


    function updateChart(domain, keepAliveTimeout, requestDuration) {
        // Remove the existing canvas and add a new one
        //resetCanvas();

        // Ensure the data for the new website is fully ready
        if (!domain || isNaN(keepAliveTimeout) || isNaN(requestDuration)) {
            console.error('Data for chart is incomplete or unavailable:', domain, keepAliveTimeout, requestDuration);
            return; // Exit the function if data is not ready or invalid
        }

        const ctx = document.getElementById('analysisChart').getContext('2d');

        if (!window.myChart) {
            // If the chart does not exist, create it with two datasets
            window.myChart = new Chart(ctx, {
                type: 'bar',
                data: {
                    labels: [domain], // Initialize labels array with the first domain
                    datasets: [{
                        label: 'Keep-Alive Timeout (seconds)',
                        data: [keepAliveTimeout], // Initialize with the first keep-alive timeout value
                        backgroundColor: 'rgba(255, 99, 132, 0.2)',
                        borderColor: 'rgba(255, 99, 132, 1)',
                        borderWidth: 1
                    }, {
                        label: 'Request Duration (ms)',
                        data: [requestDuration], // Initialize with the first request duration
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
        } else {
            // If the chart already exists, update it with new data
            // Clear existing data labels and datasets
            window.myChart.data.labels = [];
            window.myChart.data.datasets.forEach((dataset) => {
                dataset.data = [];
            });

            window.myChart.data.labels.push(domain);
            window.myChart.data.datasets[0].data.push(keepAliveTimeout); // Update keep-alive timeout dataset
            window.myChart.data.datasets[1].data.push(requestDuration); // Update request duration dataset
            window.myChart.update();
        }
    }

});
