
# Email Security Checker

A script to perform a comprehensive check on your email security, including SPF, DKIM, DMARC, MX records, DNSSEC, and more. This tool helps identify potential issues in your email security setup and suggests corrective actions to enhance your protection against spoofing, phishing, and other email-based threats.

## Features

- SPF Check
- DKIM Check
- DMARC Check
- MX Records Check
- DNSSEC Validation
- MTA-STS Check
- TLS-RPT Check
- BIMI Check
- CAA Check

## Prerequisites

This script requires the following dependencies:
- `dig`
- `curl`
- `openssl`

Install the required tools on Ubuntu/Debian:

```bash
sudo apt install dnsutils curl openssl
```

Or on RHEL/CentOS:

```bash
sudo yum install bind-utils curl openssl
```

## How to Use

1. Clone this repository:

    ```bash
    git clone https://github.com/fawad0x0/email_security_checker.git
    ```

2. Navigate to the project directory:

    ```bash
    cd email_security_checker
    ```

3. Make the script executable:

    ```bash
    chmod +x email_security_checker.sh
    ```

4. Run the script:

    ```bash
    ./email_security_checker.sh
    ```

5. Enter the domain to check when prompted (e.g., example.com).

## Script Breakdown

### Dependency Check

The script checks for the necessary dependencies (`dig`, `curl`, `openssl`). If any are missing, it will inform you and provide installation instructions.

### Domain Validation

It ensures the domain is in a valid format before proceeding with checks.

### Individual Checks

- **SPF Check**: Ensures the domain has an SPF record and checks for any broken SPF redirects.
- **DKIM Check**: Looks for DKIM selectors and verifies their correctness.
- **DMARC Check**: Verifies the DMARC record and checks for valid policies.
- **MX Records Check**: Validates the MX records and checks for IPv6 handling.
- **DNSSEC Validation**: Verifies if DNSSEC is properly configured.
- **MTA-STS Check**: Validates the existence and correctness of MTA-STS records.
- **TLS-RPT Check**: Checks for TLS reporting records.
- **BIMI Check**: Verifies the existence of BIMI records.
- **CAA Check**: Ensures a CAA record exists to prevent unauthorized certificate issuances.

### Scoring System

The script assigns weights to each check, calculating an overall security score for the domain. The final score is displayed at the end, along with recommendations for improvement.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
