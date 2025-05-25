# CyberVenom AI - Security Testing Toolkit

A powerful security testing toolkit designed for ethical hackers and security researchers.

## Features

- Website Vulnerability Scanner (XSS, SQLi, CSRF)
- Open Port Scanner
- Password Strength Checker
- AI Code Generator for Security Tools
- Secure Data Encryption
- Clean CLI Interface

## Installation

1. Clone the repository:
```bash
git clone [repository-url]
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### CLI Interface

Run the tool with different commands:

```bash
# Scan a website for vulnerabilities
python cybervenom.py scan http://example.com

# Perform a full scan
python cybervenom.py scan http://example.com --full

# Scan open ports
python cybervenom.py port 192.168.1.1

# Check password strength
python cybervenom.py password mypassword123

# Generate code using AI
python cybervenom.py ai "Write a secure password checker"
```

## Security Notes

- All sensitive data is encrypted using AES
- API keys are stored securely
- Tool is designed for educational and security testing purposes only

## License

This tool is for educational purposes only. Use responsibly and only on systems you have permission to test.

## Developed by

Miraz - CyberVenom AI
