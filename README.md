<p align="center">
  <img src="images/ScEntra-background.png" alt="ScEntra - Scan Entra for Risk & Escalation Paths" width="600" style="max-width: 100%; height: auto;">
</p>

# ScEntra

**Scan Entra for Risk & Escalation Paths**

ScEntra is a PowerShell security analysis tool for Microsoft Entra ID (formerly Azure AD) that identifies privilege escalation risks, analyzes role assignments, and visualizes complex identity relationships through an interactive graph interface.

<img width="1309" height="793" alt="image" src="https://github.com/user-attachments/assets/dc3d7158-686a-4e9e-b919-d0bea7c003fa" />


## Key Features

- **Privilege Escalation Detection**: Identifies potential attack paths through group memberships, role assignments, ownership chains, and dangerous API permissions
- **Interactive Graph Visualization**: Explore identity relationships with vis-network powered graph with clustering, filtering, and auto-detangling
- **Comprehensive Reporting**: HTML reports with risk tables, statistics, and JSON exports for automation
- **PIM Analysis**: Detects eligible role assignments and time-limited privileges
- **Service Principal Risk Assessment**: Identifies dangerous permissions like `Domain.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`, and `Application.ReadWrite.All`

  <img width="1309" height="799" alt="image" src="https://github.com/user-attachments/assets/6187fcde-982b-4e80-a2d5-f2973bc48851" />

- **Zero Dependencies**: Uses direct Microsoft Graph REST API calls - no Microsoft.Graph PowerShell modules required

## Prerequisites

- **PowerShell 7.0+** (PowerShell Core)
- **Microsoft Graph API Permissions** (one of):
  - Azure PowerShell (`Connect-AzAccount`) with appropriate role
  - Azure CLI (`az login`)
  - Direct access token with required scopes

### Required Microsoft Graph Permissions

ScEntra requires **9 specific Microsoft Graph Application permissions** (read-only). These permissions have been validated against all Graph API calls in the codebase:

| Permission | Purpose | Graph Endpoints Used |
|------------|---------|---------------------|
| `User.Read.All` | Read user accounts and profile information | `/users` |
| `Group.Read.All` | Read group properties and ownership | `/groups`, `/groups/{id}/owners` |
| `GroupMember.Read.All` | Read group membership details | `/groups/{id}/members`, `/groups/{id}/transitiveMembers` |
| `Application.Read.All` | Read applications and service principals | `/applications`, `/servicePrincipals`, `/servicePrincipals/{id}/appRoleAssignments` |
| `DelegatedPermissionGrant.Read.All` | Read OAuth2 permission grants | `/servicePrincipals/{id}/oauth2PermissionGrants` |
| `RoleManagement.Read.Directory` | Read directory role assignments | `/directoryRoles`, `/directoryRoles/{id}/members`, `/roleManagement/directory/roleDefinitions` |
| `RoleEligibilitySchedule.Read.Directory` | Read PIM eligible assignments | `/roleManagement/directory/roleEligibilitySchedules`, `/roleManagement/directory/roleEligibilityScheduleInstances` |
| `RoleAssignmentSchedule.Read.Directory` | Read PIM active assignments | `/roleManagement/directory/roleAssignmentSchedules` |
| `PrivilegedAccess.Read.AzureADGroup` | Read PIM for Groups | `/identityGovernance/privilegedAccess/group/eligibilityScheduleInstances`, `/identityGovernance/privilegedAccess/group/assignmentScheduleInstances` |

**Security Notes:**
- All permissions are **read-only** (no write/modify capabilities)
- Follows Microsoft's **least-privilege principle**
- Each permission is mapped to specific Graph API endpoints
- Alternative: `Directory.Read.All` grants all of the above but is broader than necessary

**For delegated (user) permissions**, use the equivalent delegated scopes with `.Read.All` suffix when authenticating interactively.

## Quick Start

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
# Option 1: Interactive authentication (recommended for manual analysis)
Connect-AzAccount
Connect-ScEntraGraph -UseDeviceCode

# Option 2: Using Azure CLI
az login
Connect-ScEntraGraph

# Option 3: Using Azure PowerShell
Connect-AzAccount
Connect-ScEntraGraph

# Option 4: Service Principal (recommended for automation)
# See "Automated/Production Setup" section below
```

![alt text](images/consent.png)
### 3a. Automated/Production Setup (Service Principal)

For automated scans or production environments, create a dedicated service principal:

```powershell
# Create service principal with required permissions
$sp = New-ScEntraServicePrincipal -DisplayName "ScEntra Production"

# Save the client secret (shown only once!)
$sp | Format-List

# Grant admin consent via Azure Portal
# Navigate to: Azure AD > App registrations > ScEntra Production > API permissions
# Click: "Grant admin consent for [Your Tenant]"

# Use the service principal
Connect-ScEntraGraph -TenantId '<tenant_id>' -ClientId '<application_id>' -ClientSecret '<client_secret>'
```

📖 **For detailed setup instructions, certificate authentication, and security best practices**, see:  
[SERVICE-PRINCIPAL-SETUP.md](docs/SERVICE-PRINCIPAL-SETUP.md)

### 4. Run Analysis

```powershell
# Interactive menu mode
Invoke-ScEntraAnalysis
```

<img width="502" height="361" alt="image" src="https://github.com/user-attachments/assets/18b0385c-bd77-4856-aa07-61b2239237c4" />


## Example Output

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

## 🔧 Performance & Scaling

### Microsoft Graph API Throttling Limits

ScEntra automatically adapts its API usage based on tenant size to prevent throttling. The tool uses Microsoft Graph's Resource Unit (RU) based throttling system.

#### Automatic Environment Detection

ScEntra automatically queries Microsoft Graph API count endpoints to determine tenant size:

```powershell
# Manual environment detection
$config = Get-ScEntraEnvironmentSize

# Manual configuration with specific counts
$config = Get-ScEntraEnvironmentConfig -UserCount 60000 -GroupCount 80000 -ServicePrincipalCount 120000 -AppRegistrationCount 260000
```

The automatic detection queries:
- `/users/$count` - User count
- `/groups/$count` - Group count  
- `/servicePrincipals/$count` - Service principal count
- `/applications/$count` - App registration count

#### Throttling Limits by Tenant Size

| Tenant Size | RU Limit per 10s | RU Limit per 20s | Request Limit per 5min |
|-------------|------------------|------------------|----------------------|
| **Small** (<50 users) | 3,500 RU | - | 3,000 requests |
| **Medium** (50-500 users) | 5,000 RU | - | 3,000 requests |
| **Large** (>500 users) | **8,000 RU** | 150,000 RU | 18,000 requests |

#### Resource Unit Costs for ScEntra Operations

| Microsoft Graph Endpoint | RU Cost | Used For |
|--------------------------|---------|----------|
| `GET /groups/{id}/members` | 3 RU | Group membership enumeration |
| `GET /groups/{id}/transitiveMembers` | 5 RU | Nested group analysis |
| `GET /groups/{id}/owners` | 1 RU | Group ownership checks |
| `GET /servicePrincipals/{id}/owners` | 1 RU | Service principal ownership |
| `GET /servicePrincipals/{id}/appRoleAssignedTo` | 1 RU | App role assignments |
| `GET /applications/{id}/owners` | 1 RU | App registration ownership |
| `GET /users` | 2 RU | User enumeration |
| `GET /servicePrincipals` | 1 RU | Service principal enumeration |
| `GET /applications` | 2 RU | App registration enumeration |

#### Adaptive Configuration by Environment

ScEntra automatically detects tenant size by querying Microsoft Graph API counts and applies optimal settings:

| Environment | Profile | Batch Size | Concurrency | Delay | RU Usage |
|-------------|---------|------------|-------------|-------|----------|
| **Small** (<10k objects) | Small | 20 requests | 5 parallel | 0ms | ~10-20% of limit |
| **Medium** (10k-50k objects) | Medium | 20 requests | 3 parallel | 100ms | ~15-25% of limit |
| **Large** (50k-200k objects) | Large | 15 requests | 2 parallel | 250ms | ~20-30% of limit |
| **Enterprise** (200k+ objects) | Enterprise | 20 requests | 1 sequential | 100ms | ~20-25% of limit |

#### Enterprise Environment Example

For a tenant with 60k users, 80k groups, 120k service principals, and 260k app registrations:
- **Profile**: Enterprise (200k+ objects)
- **Batch Size**: 20 requests per batch (Graph API maximum)
- **Concurrency**: 1 batch at a time (sequential processing)
- **Delay**: 100ms between batches
- **Estimated RU Usage**: ~1,800 RU per 10 seconds (22.5% of 8,000 RU limit)

### References

- [Microsoft Graph Throttling Limits](https://learn.microsoft.com/en-us/graph/throttling-limits)
- [Identity and Access Service Limits](https://learn.microsoft.com/en-us/graph/throttling-limits#identity-and-access-service-limits)
- [JSON Batching Best Practices](https://learn.microsoft.com/en-us/graph/json-batching)
- [Throttling Best Practices](https://learn.microsoft.com/en-us/graph/throttling#best-practices-to-handle-throttling)

## Interactive Features

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

## Documentation

- **[QUICKSTART.md](docs/QUICKSTART.md)** - Step-by-step guide to get started
- **[MAINTENANCE.md](docs/MAINTENANCE.md)** - Architecture, data flow, and extension guide
- **[SERVICE-PRINCIPAL-SETUP.md](docs/SERVICE-PRINCIPAL-SETUP.md)** - Detailed service principal creation and security best practices

## Security Considerations

ScEntra requires **read-only** permissions and does not modify any Entra ID configuration. However:

- Generated reports contain **sensitive identity data**
- Use **anonymization** before sharing reports externally
- Store reports in **secure locations** with appropriate access controls
- Review **Graph API permissions** granted to the analyzing account

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Test the changes thoroughly
4. Submit a pull request with clear description

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

MIT License allows commercial use, modification, distribution, and private use while requiring only attribution.

## Acknowledgments

Built with:
- [vis-network](https://visjs.github.io/vis-network/docs/network/) for graph visualization
- Microsoft Graph REST API for data collection
- PowerShell 7+ for cross-platform compatibility

---

**⚠️ Disclaimer**: This tool is for security assessment and auditing purposes. Always ensure you have proper authorization before analyzing any Entra ID tenant.
