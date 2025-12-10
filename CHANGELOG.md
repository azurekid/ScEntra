# Changelog

<p align="center">
  <img src="images/ScEntra-background.png" alt="ScEntra" width="300" style="max-width: 100%; height: auto;">
</p>

All notable changes to ScEntra will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.2] - 2025-12-10

### Fixed
- Missing `ConsistencyLevel: eventual` header in batch processing functions (`Invoke-GraphBatchRequest`)
- Graph API `/$count` queries now work correctly for both sequential and parallel batch processing paths
- Environment size determination (Step 1/5 of analysis) no longer fails with "Request_UnsupportedQuery" error
- Users installing from repository on December 10th or later will have this fix included

## [1.0.1] - 2025-12-15

### Added
- Service principal authentication support in `Connect-ScEntraGraph`
- Certificate-based authentication for service principals
- Client secret authentication for service principals
- Parameter sets for different authentication methods
- Enhanced service principal setup documentation

### Changed
- `New-ScEntraServicePrincipal` now uses direct Microsoft Graph REST API calls
- Removed dependency on Az PowerShell modules for service principal creation
- Updated documentation to remove Microsoft Graph PowerShell SDK references
- Improved error handling in Graph API calls
- Enhanced progress reporting during service principal setup

### Fixed
- Missing `ClientSecret` and `CertificateThumbprint` parameters in `Connect-ScEntraGraph`
- Inconsistent function references in service principal documentation
- Redaction of group names in escalation risk descriptions
- Documentation examples that referenced non-existent function parameters
- Corrected README.md to use `-ClientSecret` parameter instead of non-existent `-Credential` parameter

### Security
- Added comprehensive security best practices documentation
- Enhanced credential storage recommendations
- Improved monitoring and audit logging guidance

## [1.0.0] - 2025-12-10

### Added
- Initial release of ScEntra security analysis module
- Entra ID privilege escalation analysis
- Interactive HTML reports with D3.js visualizations
- Support for environment scaling (Small/Medium/Large/Enterprise)
- AES-256 encrypted report generation
- Comprehensive role assignment and PIM analysis
- Group membership and nested escalation path detection
- Service principal and application permission analysis

### Features
- Device code flow authentication
- Automated environment size detection
- Redaction capabilities for sensitive information
- Performance tuning for large environments
- Export capabilities for JSON and HTML formats