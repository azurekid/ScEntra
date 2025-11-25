<img width="1024" height="1024" alt="image" src="https://github.com/user-attachments/assets/fb04f6b4-b495-437c-bfb4-08869748f778" />

# ScEntra

**Scan Entra for Risk & Escalation Paths**

ScEntra is a PowerShell security analysis tool for Microsoft Entra ID (formerly Azure AD) that identifies privilege escalation risks, analyzes role assignments, and visualizes complex identity relationships through an interactive graph interface.

## 🎯 Key Features

- **Privilege Escalation Detection**: Identifies potential attack paths through group memberships, role assignments, ownership chains, and dangerous API permissions
- **Interactive Graph Visualization**: Explore identity relationships with vis-network powered graph with clustering, filtering, and auto-detangling
- **Comprehensive Reporting**: HTML reports with risk tables, statistics, and JSON exports for automation
- **PIM Analysis**: Detects eligible role assignments and time-limited privileges
- **Service Principal Risk Assessment**: Identifies dangerous permissions like `Domain.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`, and `Application.ReadWrite.All`
- **Zero Dependencies**: Uses direct Microsoft Graph REST API calls - no Microsoft.Graph PowerShell modules required

## 📋 Prerequisites

- **PowerShell 7.0+** (PowerShell Core)
- **Microsoft Graph API Permissions** (one of):
  - Azure PowerShell (`Connect-AzAccount`) with appropriate role
  - Azure CLI (`az login`)
  - Direct access token with required scopes

### Required Microsoft Graph Scopes

```
User.Read.All
Group.Read.All
GroupMember.Read.All
Application.Read.All
ServicePrincipalEndpoint.Read.All
RoleManagement.Read.Directory
PrivilegedAccess.Read.AzureAD
Directory.Read.All
```

## 🚀 Quick Start

### 1. Clone the Repository

```powershell
git clone https://github.com/azurekid/Scentra.git
cd Scentra
```

### 2. Import the Module

```powershell
Import-Module ./ScEntra.psd1
```

### 3. Connect to Microsoft Graph

```powershell
# Option 1: Using Azure PowerShell (recommended)
Connect-AzAccount
Connect-ScEntraGraph

# Option 2: Using Azure CLI
az login
Connect-ScEntraGraph

# Option 3: Using device code flow
Connect-ScEntraGraph -UseDeviceCode
```

### 4. Run Analysis

```powershell
# Interactive menu mode
Invoke-ScEntraAnalysis

# Direct analysis
Invoke-ScEntraAnalysis -OutputPath "./my-report.html"
```

## 📊 Example Output

The analysis generates:
- **HTML Report** (`ScEntra-Report-YYYYMMDD-HHmmss.html`) - Interactive visualization with:
  - Statistics dashboard
  - Escalation risk table with severity badges
  - Interactive network graph
  - Role distribution charts
- **JSON Export** (`ScEntra-Report-YYYYMMDD-HHmmss.json`) - Raw data for automation

## 🔍 What ScEntra Detects

### High-Risk Configurations

| Risk Type | Description |
|-----------|-------------|
| **Role Enabled Group** | Groups with highly privileged role assignments and members |
| **Role Assignable Group Membership** | Role-assignable groups that can inherit privileged roles |
| **Service Principal Dangerous Permissions** | Apps with critical permissions like `Domain.ReadWrite.All`, `RoleManagement.ReadWrite.Directory` |
| **Multiple PIM Roles** | Principals with excessive PIM eligible assignments |
| **Nested Group Escalation** | Complex group hierarchies leading to privilege elevation |
| **Cross-Tier Access** | Accounts bridging security tier boundaries |

### Highly Privileged Roles Monitored

- Global Administrator
- Privileged Role Administrator
- Security Administrator
- Cloud Application Administrator
- Application Administrator
- User Administrator
- Exchange Administrator
- SharePoint Administrator

## 🛠️ Advanced Usage

### Generate Sample Report

Test the tool with synthetic data:

```powershell
./Generate-SampleReport.ps1
```

### Regenerate from JSON

Update the HTML report without re-querying Graph API:

```powershell
./Generate-ReportFromJson.ps1 -JsonPath "./reports/ScEntra-Report-20251125-120523.json"
```

### Anonymize Reports for Sharing

```powershell
./Invoke-JsonAnonymizer.ps1 -InputPath "./reports/ScEntra-Report.json" -OutputPath "./reports/anonymized.json"
```

## 🎨 Interactive Features

### Graph Visualization
- **Click risks** in the table to filter and focus the graph
- **Auto-detangle** automatically reorganizes filtered nodes
- **Search & filter** by node type, assignment type, or escalation paths
- **Dark mode** optimized interface
- **Export** graph as PNG image

### Risk Analysis
- **Severity filtering**: Critical, High, Medium, Low
- **Deduplicated risks**: Groups similar risks with entity ID tracking
- **Member count filtering**: Excludes empty groups from risk table
- **Privilege-based filtering**: Only shows truly dangerous role assignments

## 📚 Documentation

- **[MAINTENANCE.md](./docs/MAINTENANCE.md)** - Architecture, data flow, and extension guide
- **[Directory-ReadWrite-All-Privilege-Escalation.md](./Directory-ReadWrite-All-Privilege-Escalation.md)** - Deep dive into federated domain attacks

## 🔐 Security Considerations

ScEntra requires **read-only** permissions and does not modify any Entra ID configuration. However:

- Generated reports contain **sensitive identity data**
- Use **anonymization** before sharing reports externally
- Store reports in **secure locations** with appropriate access controls
- Review **Graph API permissions** granted to the analyzing account

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Test with `./Generate-SampleReport.ps1`
4. Submit a pull request with clear description

## 📝 License

Copyright (c) 2025 ScEntra Contributors. All rights reserved.

## 🙏 Acknowledgments

Built with:
- [vis-network](https://visjs.github.io/vis-network/docs/network/) for graph visualization
- Microsoft Graph REST API for data collection
- PowerShell 7+ for cross-platform compatibility

---

**⚠️ Disclaimer**: This tool is for security assessment and auditing purposes. Always ensure you have proper authorization before analyzing any Entra ID tenant.
