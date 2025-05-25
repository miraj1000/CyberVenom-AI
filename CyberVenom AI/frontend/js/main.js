// Tab switching functionality
document.querySelectorAll('.tab-btn').forEach(button => {
    button.addEventListener('click', () => {
        const tabId = button.getAttribute('data-tab');
        
        // Update active tab button
        document.querySelectorAll('.tab-btn').forEach(btn => btn.classList.remove('active'));
        button.classList.add('active');
        
        // Show/hide tab content
        document.querySelectorAll('.tab-content').forEach(content => {
            content.classList.remove('active');
        });
        document.getElementById(tabId).classList.add('active');
    });
});

// Vulnerability Scanner
function scanVulnerabilities() {
    const url = document.getElementById('targetUrl').value;
    const resultsDiv = document.getElementById('vulnerabilityResults');
    
    if (!url) {
        showError(resultsDiv, 'Please enter a target URL');
        return;
    }
    
    // Simulate vulnerability scan (in real deployment, this would be API calls)
    const vulnerabilities = [
        { type: 'XSS', found: true },
        { type: 'SQL Injection', found: false },
        { type: 'CSRF', found: true }
    ];
    
    displayResults(resultsDiv, vulnerabilities);
}

// Port Scanner
function scanPorts() {
    const host = document.getElementById('host').value;
    const ports = document.getElementById('ports').value;
    const resultsDiv = document.getElementById('portResults');
    
    if (!host) {
        showError(resultsDiv, 'Please enter a host');
        return;
    }
    
    // Simulate port scan
    const openPorts = [80, 443];
    const portArray = ports ? ports.split(',') : [];
    
    const results = portArray.map(port => ({
        port: parseInt(port.trim()),
        status: openPorts.includes(parseInt(port.trim())) ? 'open' : 'closed'
    }));
    
    displayPortResults(resultsDiv, results);
}

// Password Checker
function checkPassword() {
    const password = document.getElementById('password').value;
    const resultsDiv = document.getElementById('passwordResults');
    
    if (!password) {
        showError(resultsDiv, 'Please enter a password');
        return;
    }
    
    // Simulate password strength check
    const strength = {
        length: password.length >= 8,
        hasNumbers: /[0-9]/.test(password),
        hasSpecial: /[!@#$%^&*(),.?":{}|<>]/.test(password),
        hasUppercase: /[A-Z]/.test(password),
        hasLowercase: /[a-z]/.test(password)
    };
    
    displayPasswordResults(resultsDiv, strength);
}

// AI Code Generator
function generateCode() {
    const prompt = document.getElementById('aiPrompt').value;
    const resultsDiv = document.getElementById('aiResults');
    
    if (!prompt) {
        showError(resultsDiv, 'Please enter a prompt');
        return;
    }
    
    // Simulate AI code generation
    const generatedCode = `// AI Generated Code based on: "${prompt}"
function checkPasswordStrength(password) {
    // Implementation based on prompt
    return {
        score: 100,
        recommendations: []
    };
}`;
    
    displayCodeResults(resultsDiv, generatedCode);
}

// Helper functions
function showError(element, message) {
    element.innerHTML = `<div class="danger">${message}</div>`;
}

function displayResults(element, vulnerabilities) {
    const results = vulnerabilities.map(vuln => 
        `<div class="${vuln.found ? 'danger' : 'success'}">
            ${vuln.type}: ${vuln.found ? 'Vulnerable' : 'Secure'}
        </div>`
    ).join('');
    element.innerHTML = results;
}

function displayPortResults(element, results) {
    const portResults = results.map(port => 
        `<div class="${port.status === 'open' ? 'danger' : 'success'}">
            Port ${port.port}: ${port.status}
        </div>`
    ).join('');
    element.innerHTML = portResults;
}

function displayPasswordResults(element, strength) {
    const checks = Object.entries(strength).map(([check, result]) => 
        `<div class="${result ? 'success' : 'warning'}">
            ${check}: ${result ? '✓' : '✗'}
        </div>`
    );
    element.innerHTML = checks.join('');
}

function displayCodeResults(element, code) {
    element.innerHTML = `
        <div class="success">
            <pre><code>${code}</code></pre>
        </div>
    `;
}
