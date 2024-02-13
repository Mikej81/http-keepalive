const express = require('express');
const bodyParser = require('body-parser');
const axios = require('axios');
const path = require('path');
const https = require('https');
const http2 = require('http2');

const app = express();
const port = 3000;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json()); // Support json encoded bodies
app.use(express.static('public')); // Serve static files

// Route for the home page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '/public/index.html'));
});

const httpsAgent = new https.Agent({
    rejectUnauthorized: false, // This bypasses SSL certificate validation. Use with caution!
});

function httpsGetWithTLSInfo(url) {
    return new Promise((resolve, reject) => {
        // Parse the URL to get hostname and path
        const { hostname, pathname, search } = new URL(url);
        const options = {
            hostname,
            port: 443,
            path: `${pathname}${search || ''}`,
            method: 'GET'
        };

        const req = https.request(options, (res) => {
            let data = '';
            res.on('data', (chunk) => { data += chunk; });
            res.on('end', () => {
                // Resolve the promise with data, TLS version, and headers
                resolve({
                    data,
                    tlsVersion: req.socket.getProtocol(),
                    headers: res.headers // Include response headers
                });
            });
        });

        req.on('error', (error) => {
            console.error('Request error:', error);
            reject(error);
        });

        // Log the TLS version once the secure connection is established
        req.on('socket', (socket) => {
            socket.on('secureConnect', () => {
                //console.log('TLS Version:', socket.getProtocol());
            });
        });

        req.end();
    });
}


// Analysis route
app.post('/analyze', async (req, res) => {
    let { domain } = req.body;
    try {
        if (!/^https?:\/\//i.test(domain)) {
            domain = `https://${domain}`; // Default to https if no protocol is specified
        }

        const startTime = Date.now(); // Capture start time

        // Await the response from httpsGetWithTLSInfo directly
        const { data, tlsVersion, headers } = await httpsGetWithTLSInfo(domain);

        // Initialize timeoutValue with a default
        let timeoutValue = "Not Defined";
        let connectionHeader = "Not Defined";

        // Parsing Keep-Alive header for timeout value
        if (headers && 'keep-alive' in headers) {
            const keepAliveHeader = headers['keep-alive'];
            const timeoutMatch = keepAliveHeader.match(/timeout=(\d+)/);
            if (timeoutMatch && timeoutMatch[1]) {
                timeoutValue = timeoutMatch[1]; // Extracted timeout value in seconds
            }
        }

        if (headers && 'connection' in headers) {
            connectionHeader = headers['connection'];
        }

        const endTime = Date.now(); // Capture end time
        const duration = endTime - startTime; // Calculate duration

        // Return the required information
        res.json({
            domain: domain,
            keepAliveTimeout: timeoutValue,
            requestDuration: duration,
            tlsVersion: tlsVersion, // Ensure tlsVersion is defined outside the .then()
            connectionHeader: connectionHeader // Add connectionHeader to the response

        });

    } catch (error) {
        console.error('Error:', error);
        res.status(500).send({ error: 'Failed to fetch or analyze domain' });
    }
});


// Start the server
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});
