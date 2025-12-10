# Security Policy

## Supported Versions

We actively support the following versions of ScEntra with security updates:

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |

## Reporting a Vulnerability

The ScEntra team takes security vulnerabilities seriously. We appreciate your efforts to responsibly disclose your findings.

### How to Report

**Please do not report security vulnerabilities through public GitHub issues.**

Instead, please report security vulnerabilities by emailing the maintainers or using GitHub's private security vulnerability reporting feature:

1. **GitHub Security Advisory**: Go to the [Security tab](https://github.com/azurekid/Scentra/security) of this repository and click "Report a vulnerability"
2. **Email**: Contact the maintainers directly (check the repository for current contact information)

### What to Include

When reporting a vulnerability, please include the following information:

- **Type of vulnerability** (e.g., privilege escalation, information disclosure, etc.)
- **Location** of the vulnerability (file path, function name, etc.)
- **Step-by-step instructions** to reproduce the issue
- **Proof of concept** or exploit code (if applicable)
- **Impact assessment** - what could an attacker accomplish?
- **Suggested fix** (if you have one)

### Response Timeline

- **Acknowledgment**: We will acknowledge receipt of your vulnerability report within 48 hours
- **Initial Assessment**: We will provide an initial assessment within 5 business days
- **Status Updates**: We will keep you informed of our progress toward fixing the vulnerability
- **Resolution**: We aim to resolve critical vulnerabilities within 30 days

### Disclosure Policy

- We request that you give us adequate time to address the vulnerability before making it public
- We will credit you in the security advisory (unless you prefer to remain anonymous)
- We may ask you to participate in the validation of our fix

### Security Best Practices for ScEntra Users

When using ScEntra, please follow these security guidelines:

1. **Principle of Least Privilege**: Grant only the minimum Microsoft Graph permissions required
2. **Secure Report Storage**: Store generated reports in secure locations with appropriate access controls
3. **Data Anonymization**: Use the built-in anonymization features before sharing reports externally
4. **Service Principal Security**: 
   - Use certificate-based authentication when possible
   - Rotate client secrets regularly
   - Monitor service principal activity
   - Restrict network access with Conditional Access policies
5. **Environment Isolation**: Use dedicated service principals for different environments (dev/staging/prod)

### Known Security Considerations

- **Sensitive Data in Reports**: ScEntra reports contain sensitive identity information. Always secure these reports appropriately.
- **Graph API Permissions**: The tool requires read access to identity data. Ensure this access is justified and monitored.
- **Audit Logging**: Monitor the activity of accounts/service principals running ScEntra for unusual patterns.

### Security Features in ScEntra

- **Read-Only Operations**: ScEntra only reads data from Microsoft Graph, never modifies it
- **Encryption**: Generated reports use AES-256 encryption when the encryption feature is enabled
- **Anonymization**: Built-in data redaction capabilities for safe report sharing
- **No External Dependencies**: Uses only Microsoft Graph REST APIs, reducing supply chain risks

### Updates and Notifications

Security updates will be:
- Published as GitHub Security Advisories
- Included in release notes with clear security impact descriptions
- Communicated through the repository's release notifications

## Questions?

If you have questions about this security policy, please open a regular GitHub issue (for non-sensitive questions) or contact the maintainers directly.