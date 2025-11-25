#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Generate a comprehensive large sample report with realistic enterprise-scale data

.DESCRIPTION
    Creates a sample HTML report with 200-600 users, 40-60 groups, 70-100 service principals,
    and 50 applications to demonstrate full ScEntra visualization and attack path detection
#>

Write-Host "Generating Large-Scale Sample Report..." -ForegroundColor Cyan

# Import module
Import-Module ./ScEntra.psd1 -Force

# New-ScEntraGraphData is a private helper, so load it explicitly if it is not exported
if (-not (Get-Command -Name New-ScEntraGraphData -ErrorAction SilentlyContinue)) {
    . (Join-Path -Path $PSScriptRoot -ChildPath 'Private/New-ScEntraGraphData.ps1')
}

# Randomize dataset sizes within realistic enterprise ranges
$userCountTarget = Get-Random -Minimum 200 -Maximum 601    # inclusive upper bound by adding 1
$groupCountTarget = Get-Random -Minimum 40 -Maximum 61
$servicePrincipalCountTarget = Get-Random -Minimum 70 -Maximum 101

$graphAppId = "00000003-0000-0000-c000-000000000000"

# Real Microsoft Graph API permission IDs
$permissionIds = @{
    ApplicationReadWriteAll                  = "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9"
    DirectoryAccessAsUserAll                 = "0e263e50-5827-48a4-b97c-d940288653c7"
    RoleManagementReadWriteDirectory         = "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8"
    DirectoryReadWriteAll                    = "19dbc75e-c2e2-444c-a770-ec69d8559fc7"
    GroupReadWriteAll                        = "62a82d76-70ea-41e2-9197-370581804d09"
    DomainReadWriteAll                       = "dbb9058a-0e50-45d7-ae91-66909b5d4664"
    DeviceManagementConfigurationReadWriteAll = "9241abd9-d0e6-425a-bd4f-47ba86e767a4"
    UserReadWriteAll                         = "741f803b-c850-494e-b5df-cde7c675a1ca"
    AppRoleAssignmentReadWriteAll            = "06b708a9-e830-4db3-a914-8e69da51d44f"
    RoleManagementPolicyReadWriteDirectory   = "1ff1be21-34eb-448e-9d5c-a2df48323e8e"
}

# Real Microsoft first-party app IDs
$msApps = @(
    @{ Name = "Microsoft Graph"; AppId = "00000003-0000-0000-c000-000000000000" }
    @{ Name = "Azure Portal"; AppId = "c44b4083-3bb0-49c1-b47d-974e53cbdf3c" }
    @{ Name = "Microsoft Intune"; AppId = "0000000a-0000-0000-c000-000000000000" }
    @{ Name = "Office 365 Management APIs"; AppId = "c5393580-f805-4401-95e8-94b7a6ef2fc2" }
    @{ Name = "Microsoft Teams"; AppId = "1fec8e78-bce4-4aaf-ab1b-5451cc387264" }
    @{ Name = "SharePoint Online"; AppId = "00000003-0000-0ff1-ce00-000000000000" }
    @{ Name = "Exchange Online"; AppId = "00000002-0000-0ff1-ce00-000000000000" }
    @{ Name = "Microsoft Azure PowerShell"; AppId = "1950a258-227b-4e31-a9cf-717495945fc2" }
    @{ Name = "Microsoft Azure CLI"; AppId = "04b07795-8ddb-461a-bbee-02f9e1bf7b46" }
    @{ Name = "Azure AD PowerShell"; AppId = "1b730954-1685-4b74-9bfd-dac224a7b894" }
    @{ Name = "Microsoft To-Do"; AppId = "22098786-6e16-43cc-a27d-191a01a1e3b5" }
    @{ Name = "Power BI Service"; AppId = "00000009-0000-0000-c000-000000000000" }
)

# Enterprise application scenarios
$appScenarios = @(
    "Enterprise Automation Platform", "CI/CD Pipeline Runner", "Identity Governance System",
    "Backup and DR Solution", "Federated SSO Gateway", "Device Management Platform",
    "HR Integration Service", "Security Analytics Engine", "Compliance Monitoring Tool",
    "Cloud Cost Management", "Infrastructure as Code Platform", "Secret Management Vault",
    "API Gateway Service", "Data Lake Integration", "Business Intelligence Platform",
    "Customer Data Platform", "Marketing Automation Suite", "CRM Integration Hub",
    "ERP Connector Service", "Payment Processing Gateway", "Document Management System",
    "Workflow Automation Engine", "AI/ML Training Platform", "Container Registry Service",
    "Monitoring and Alerting System", "Log Aggregation Service", "Network Security Scanner",
    "Vulnerability Assessment Tool", "Endpoint Detection Response", "Email Security Gateway",
    "Data Loss Prevention System", "Privileged Access Management", "Certificate Management Service",
    "DNS Management Platform", "Load Balancer Controller", "Database Migration Tool",
    "ETL Processing Engine", "Real-time Analytics Service", "Message Queue Service",
    "Cache Management System", "Search Index Service", "Content Delivery Network",
    "Video Streaming Platform", "File Sync Service", "Collaboration Platform",
    "Project Management Tool", "Time Tracking System", "Asset Management Database",
    "Inventory Control System", "Supply Chain Platform", "Customer Support Portal",
    "Knowledge Base System", "Training LMS Platform", "Survey Feedback Tool",
    "Event Management System", "Booking Reservation System", "Digital Signature Service",
    "E-Discovery Platform", "Threat Intelligence Feed", "Incident Response Platform"
)

Write-Host ("Generating {0} users..." -f $userCountTarget) -ForegroundColor Yellow

# Generate a randomized user population with realistic distribution
$firstNames = @(
    "James", "Mary", "John", "Patricia", "Robert", "Jennifer", "Michael", "Linda",
    "William", "Barbara", "David", "Elizabeth", "Richard", "Susan", "Joseph", "Jessica",
    "Thomas", "Sarah", "Charles", "Karen", "Christopher", "Nancy", "Daniel", "Lisa",
    "Matthew", "Betty", "Anthony", "Margaret", "Mark", "Sandra", "Donald", "Ashley",
    "Steven", "Kimberly", "Paul", "Emily", "Andrew", "Donna", "Joshua", "Michelle",
    "Kenneth", "Dorothy", "Kevin", "Carol", "Brian", "Amanda", "George", "Melissa",
    "Edward", "Deborah", "Ronald", "Stephanie", "Timothy", "Rebecca", "Jason", "Sharon",
    "Jeffrey", "Laura", "Ryan", "Cynthia", "Jacob", "Kathleen", "Gary", "Amy",
    "Nicholas", "Shirley", "Eric", "Angela", "Jonathan", "Helen", "Stephen", "Anna",
    "Larry", "Brenda", "Justin", "Pamela", "Scott", "Nicole", "Brandon", "Emma",
    "Benjamin", "Samantha", "Samuel", "Katherine", "Raymond", "Christine", "Gregory", "Debra",
    "Frank", "Rachel", "Alexander", "Catherine", "Patrick", "Carolyn", "Raymond", "Janet",
    "Jack", "Ruth", "Dennis", "Maria", "Jerry", "Heather", "Tyler", "Diane",
    "Aaron", "Virginia", "Jose", "Julie", "Adam", "Joyce", "Henry", "Victoria",
    "Nathan", "Olivia", "Douglas", "Kelly", "Zachary", "Christina", "Peter", "Lauren",
    "Kyle", "Joan", "Walter", "Evelyn", "Ethan", "Judith", "Jeremy", "Megan",
    "Harold", "Cheryl", "Keith", "Andrea", "Christian", "Hannah", "Roger", "Martha",
    "Noah", "Jacqueline", "Gerald", "Frances", "Carl", "Gloria", "Terry", "Ann",
    "Sean", "Teresa", "Austin", "Kathryn", "Arthur", "Sara", "Lawrence", "Janice",
    "Jesse", "Jean", "Dylan", "Alice", "Bryan", "Madison", "Joe", "Doris",
    "Jordan", "Abigail", "Billy", "Julia", "Bruce", "Judy", "Albert", "Grace",
    "Willie", "Denise", "Gabriel", "Amber", "Logan", "Theresa", "Alan", "Marilyn",
    "Juan", "Beverly", "Wayne", "Danielle", "Roy", "Diana", "Ralph", "Brittany",
    "Randy", "Natalie", "Eugene", "Sophia", "Vincent", "Rose", "Russell", "Isabella"
)

$lastNames = @(
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis",
    "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson", "Thomas",
    "Taylor", "Moore", "Jackson", "Martin", "Lee", "Perez", "Thompson", "White",
    "Harris", "Sanchez", "Clark", "Ramirez", "Lewis", "Robinson", "Walker", "Young",
    "Allen", "King", "Wright", "Scott", "Torres", "Nguyen", "Hill", "Flores",
    "Green", "Adams", "Nelson", "Baker", "Hall", "Rivera", "Campbell", "Mitchell",
    "Carter", "Roberts", "Gomez", "Phillips", "Evans", "Turner", "Diaz", "Parker",
    "Cruz", "Edwards", "Collins", "Reyes", "Stewart", "Morris", "Morales", "Murphy",
    "Cook", "Rogers", "Gutierrez", "Ortiz", "Morgan", "Cooper", "Peterson", "Bailey",
    "Reed", "Kelly", "Howard", "Ramos", "Kim", "Cox", "Ward", "Richardson",
    "Watson", "Brooks", "Chavez", "Wood", "James", "Bennett", "Gray", "Mendoza",
    "Ruiz", "Hughes", "Price", "Alvarez", "Castillo", "Sanders", "Patel", "Myers",
    "Long", "Ross", "Foster", "Jimenez", "Powell", "Jenkins", "Perry", "Russell",
    "Sullivan", "Bell", "Coleman", "Butler", "Henderson", "Barnes", "Gonzales", "Fisher",
    "Vasquez", "Simmons", "Romero", "Jordan", "Patterson", "Alexander", "Hamilton", "Graham",
    "Reynolds", "Griffin", "Wallace", "Moreno", "West", "Cole", "Hayes", "Bryant",
    "Herrera", "Gibson", "Ellis", "Tran", "Medina", "Aguilar", "Stevens", "Murray",
    "Ford", "Castro", "Marshall", "Owens", "Harrison", "Fernandez", "McDonald", "Woods",
    "Washington", "Kennedy", "Wells", "Vargas", "Henry", "Chen", "Freeman", "Webb",
    "Tucker", "Guzman", "Burns", "Crawford", "Olson", "Simpson", "Porter", "Hunter",
    "Gordon", "Mendez", "Silva", "Shaw", "Snyder", "Mason", "Dixon", "Munoz",
    "Hunt", "Hicks", "Holmes", "Palmer", "Wagner", "Black", "Robertson", "Boyd",
    "Rose", "Stone", "Salazar", "Fox", "Warren", "Mills", "Meyer", "Rice",
    "Schmidt", "Garza", "Daniels", "Ferguson", "Nichols", "Stephens", "Soto", "Weaver"
)

$departments = @(
    "IT Operations", "Cloud Engineering", "Security Operations", "Development",
    "DevOps", "Infrastructure", "Identity & Access", "Compliance", "Risk Management",
    "Finance", "Human Resources", "Legal", "Marketing", "Sales", "Customer Success",
    "Product Management", "Data Analytics", "Business Intelligence", "Support", "Facilities"
)

$sampleUsers = @()

# Create 2 break-glass accounts with onmicrosoft.com domain
for ($i = 0; $i -lt 2; $i++) {
    $sampleUsers += [PSCustomObject]@{
        Id = [Guid]::NewGuid().ToString()
        DisplayName = "Break Glass Account $i"
        UserPrincipalName = "breakglass-$i@azurehacking.onmicrosoft.com"
        AccountEnabled = $true
        UserType = "Member"
        Mail = "breakglass-$i@azurehacking.onmicrosoft.com"
        Department = "IT Operations"
    }
}

# Create remaining regular users with azurehacking.com domain
for ($i = 2; $i -lt $userCountTarget; $i++) {
    $firstName = $firstNames[$i % $firstNames.Count]
    $lastName = $lastNames[($i * 7) % $lastNames.Count]  # Mix it up
    $dept = $departments[$i % $departments.Count]
    $isGuest = ($i % 10) -eq 0  # 10% guests
    $isDisabled = ($i % 20) -eq 0  # 5% disabled
    
    $sampleUsers += [PSCustomObject]@{
        Id = [Guid]::NewGuid().ToString()
        DisplayName = "$firstName $lastName"
        UserPrincipalName = "$($firstName.ToLower()).$($lastName.ToLower())@azurehacking.com"
        AccountEnabled = -not $isDisabled
        UserType = if ($isGuest) { "Guest" } else { "Member" }
        Mail = "$($firstName.ToLower()).$($lastName.ToLower())@azurehacking.com"
        Department = $dept
    }
}

# Generate comprehensive group structure
$sampleGroups = @(
    # Tier 0 - Highest Privilege (Domain/Forest control)
    [PSCustomObject]@{
        Id = [Guid]::NewGuid().ToString()
        DisplayName = "Global Administrators"
        Description = "Tier 0: Full tenant control - highest privilege"
        IsRoleAssignable = $true
        SecurityEnabled = $true
        MailEnabled = $false
    }
    [PSCustomObject]@{
        Id = [Guid]::NewGuid().ToString()
        DisplayName = "Privileged Role Administrators"
        Description = "Tier 0: Can manage all role assignments"
        IsRoleAssignable = $true
        SecurityEnabled = $true
        MailEnabled = $false
    }
    [PSCustomObject]@{
        Id = [Guid]::NewGuid().ToString()
        DisplayName = "Hybrid Identity Administrators"
        Description = "Tier 0: Controls on-premises sync - federation risk"
        IsRoleAssignable = $true
        SecurityEnabled = $true
        MailEnabled = $false
    }
    [PSCustomObject]@{
        Id = [Guid]::NewGuid().ToString()
        DisplayName = "Partner Tier Zero Access"
        Description = "Tier 0: External partner with privileged access - HIGH RISK"
        IsRoleAssignable = $true
        SecurityEnabled = $true
        MailEnabled = $false
    }
    # Tier 1 - High Privilege (Identity/Security control)
    [PSCustomObject]@{
        Id = [Guid]::NewGuid().ToString()
        DisplayName = "Application Administrators"
        Description = "Tier 1: Can create apps with Graph permissions"
        IsRoleAssignable = $true
        SecurityEnabled = $true
        MailEnabled = $false
    }
    [PSCustomObject]@{
        Id = [Guid]::NewGuid().ToString()
        DisplayName = "Cloud Application Administrators"
        Description = "Tier 1: Can manage enterprise applications"
        IsRoleAssignable = $true
        SecurityEnabled = $true
        MailEnabled = $false
    }
    [PSCustomObject]@{
        Id = [Guid]::NewGuid().ToString()
        DisplayName = "Authentication Administrators"
        Description = "Tier 1: Can reset MFA and passwords"
        IsRoleAssignable = $true
        SecurityEnabled = $true
        MailEnabled = $false
    }
    [PSCustomObject]@{
        Id = [Guid]::NewGuid().ToString()
        DisplayName = "User Administrators"
        Description = "Tier 1: Can create and manage users"
        IsRoleAssignable = $true
        SecurityEnabled = $true
        MailEnabled = $false
    }
    [PSCustomObject]@{
        Id = [Guid]::NewGuid().ToString()
        DisplayName = "Groups Administrators"
        Description = "Tier 1: Can manage all groups including role-assignable"
        IsRoleAssignable = $true
        SecurityEnabled = $true
        MailEnabled = $false
    }
    [PSCustomObject]@{
        Id = [Guid]::NewGuid().ToString()
        DisplayName = "Security Administrators"
        Description = "Tier 1: Can manage security settings and policies"
        IsRoleAssignable = $true
        SecurityEnabled = $true
        MailEnabled = $false
    }
    # Tier 2 - Workload-specific privilege
    [PSCustomObject]@{
        Id = [Guid]::NewGuid().ToString()
        DisplayName = "Exchange Administrators"
        Description = "Tier 2: Can manage Exchange Online"
        IsRoleAssignable = $true
        SecurityEnabled = $true
        MailEnabled = $false
    }
    [PSCustomObject]@{
        Id = [Guid]::NewGuid().ToString()
        DisplayName = "SharePoint Administrators"
        Description = "Tier 2: Can manage SharePoint Online"
        IsRoleAssignable = $true
        SecurityEnabled = $true
        MailEnabled = $false
    }
    [PSCustomObject]@{
        Id = [Guid]::NewGuid().ToString()
        DisplayName = "Teams Administrators"
        Description = "Tier 2: Can manage Microsoft Teams"
        IsRoleAssignable = $true
        SecurityEnabled = $true
        MailEnabled = $false
    }
    [PSCustomObject]@{
        Id = [Guid]::NewGuid().ToString()
        DisplayName = "Intune Administrators"
        Description = "Tier 2: Can manage Intune and device policies"
        IsRoleAssignable = $true
        SecurityEnabled = $true
        MailEnabled = $false
    }
    [PSCustomObject]@{
        Id = [Guid]::NewGuid().ToString()
        DisplayName = "Power Platform Administrators"
        Description = "Tier 2: Can manage Power Platform resources"
        IsRoleAssignable = $true
        SecurityEnabled = $true
        MailEnabled = $false
    }
    [PSCustomObject]@{
        Id = [Guid]::NewGuid().ToString()
        DisplayName = "Office Apps Administrators"
        Description = "Tier 1: Can manage Office 365 apps and services"
        IsRoleAssignable = $true
        SecurityEnabled = $true
        MailEnabled = $false
    }
    [PSCustomObject]@{
        Id = [Guid]::NewGuid().ToString()
        DisplayName = "Billing Administrators"
        Description = "Tier 1: Can manage billing and subscriptions"
        IsRoleAssignable = $true
        SecurityEnabled = $true
        MailEnabled = $false
    }
    [PSCustomObject]@{
        Id = [Guid]::NewGuid().ToString()
        DisplayName = "License Administrators"
        Description = "Tier 1: Can manage licenses and user assignments"
        IsRoleAssignable = $true
        SecurityEnabled = $true
        MailEnabled = $false
    }
    # Read-only privileged roles
    [PSCustomObject]@{
        Id = [Guid]::NewGuid().ToString()
        DisplayName = "Global Readers"
        Description = "Can read all tenant configuration but not modify"
        IsRoleAssignable = $true
        SecurityEnabled = $true
        MailEnabled = $false
    }
    [PSCustomObject]@{
        Id = [Guid]::NewGuid().ToString()
        DisplayName = "Security Readers"
        Description = "Can read security reports and settings"
        IsRoleAssignable = $true
        SecurityEnabled = $true
        MailEnabled = $false
    }
    # Operational groups
    [PSCustomObject]@{
        Id = [Guid]::NewGuid().ToString()
        DisplayName = "IT Operations Team"
        Description = "Standard IT operations staff"
        IsRoleAssignable = $false
        SecurityEnabled = $true
        MailEnabled = $false
    }
    [PSCustomObject]@{
        Id = [Guid]::NewGuid().ToString()
        DisplayName = "DevOps Engineers"
        Description = "Development and operations team"
        IsRoleAssignable = $false
        SecurityEnabled = $true
        MailEnabled = $false
    }
    [PSCustomObject]@{
        Id = [Guid]::NewGuid().ToString()
        DisplayName = "Security Operations Center"
        Description = "Security monitoring and incident response"
        IsRoleAssignable = $false
        SecurityEnabled = $true
        MailEnabled = $false
    }
    [PSCustomObject]@{
        Id = [Guid]::NewGuid().ToString()
        DisplayName = "Cloud Architects"
        Description = "Cloud infrastructure design and governance"
        IsRoleAssignable = $false
        SecurityEnabled = $true
        MailEnabled = $false
    }
    [PSCustomObject]@{
        Id = [Guid]::NewGuid().ToString()
        DisplayName = "Identity Team"
        Description = "Identity and access management team"
        IsRoleAssignable = $false
        SecurityEnabled = $true
        MailEnabled = $false
    }
    # Help desk tiers
    [PSCustomObject]@{
        Id = [Guid]::NewGuid().ToString()
        DisplayName = "Helpdesk Tier 1"
        Description = "First-line support team"
        IsRoleAssignable = $true
        SecurityEnabled = $true
        MailEnabled = $false
    }
    [PSCustomObject]@{
        Id = [Guid]::NewGuid().ToString()
        DisplayName = "Helpdesk Tier 2"
        Description = "Advanced support team"
        IsRoleAssignable = $true
        SecurityEnabled = $true
        MailEnabled = $false
    }
    [PSCustomObject]@{
        Id = [Guid]::NewGuid().ToString()
        DisplayName = "Helpdesk Managers"
        Description = "Support team managers with elevated access"
        IsRoleAssignable = $true
        SecurityEnabled = $true
        MailEnabled = $false
    }
    # External access groups
    [PSCustomObject]@{
        Id = [Guid]::NewGuid().ToString()
        DisplayName = "External Consultants"
        Description = "Third-party consultants - potential risk"
        IsRoleAssignable = $false
        SecurityEnabled = $true
        MailEnabled = $false
    }
    [PSCustomObject]@{
        Id = [Guid]::NewGuid().ToString()
        DisplayName = "Vendor Access - IT Services"
        Description = "External IT service provider access"
        IsRoleAssignable = $false
        SecurityEnabled = $true
        MailEnabled = $false
    }
    [PSCustomObject]@{
        Id = [Guid]::NewGuid().ToString()
        DisplayName = "Partner Developers"
        Description = "External development partners"
        IsRoleAssignable = $false
        SecurityEnabled = $true
        MailEnabled = $false
    }
    # Departmental groups
    [PSCustomObject]@{
        Id = [Guid]::NewGuid().ToString()
        DisplayName = "Finance Department"
        Description = "Finance team members"
        IsRoleAssignable = $false
        SecurityEnabled = $true
        MailEnabled = $true
    }
    [PSCustomObject]@{
        Id = [Guid]::NewGuid().ToString()
        DisplayName = "Human Resources"
        Description = "HR team with access to personnel data"
        IsRoleAssignable = $false
        SecurityEnabled = $true
        MailEnabled = $true
    }
    [PSCustomObject]@{
        Id = [Guid]::NewGuid().ToString()
        DisplayName = "Legal Department"
        Description = "Legal and compliance team"
        IsRoleAssignable = $false
        SecurityEnabled = $true
        MailEnabled = $true
    }
    [PSCustomObject]@{
        Id = [Guid]::NewGuid().ToString()
        DisplayName = "Executive Leadership"
        Description = "C-level executives and VPs"
        IsRoleAssignable = $false
        SecurityEnabled = $true
        MailEnabled = $true
    }
    [PSCustomObject]@{
        Id = [Guid]::NewGuid().ToString()
        DisplayName = "Sales Team"
        Description = "Sales and business development"
        IsRoleAssignable = $false
        SecurityEnabled = $true
        MailEnabled = $true
    }
    [PSCustomObject]@{
        Id = [Guid]::NewGuid().ToString()
        DisplayName = "Marketing Team"
        Description = "Marketing and communications"
        IsRoleAssignable = $false
        SecurityEnabled = $true
        MailEnabled = $true
    }
    [PSCustomObject]@{
        Id = [Guid]::NewGuid().ToString()
        DisplayName = "Engineering Team"
        Description = "Software engineering and development"
        IsRoleAssignable = $false
        SecurityEnabled = $true
        MailEnabled = $true
    }
    # Application-specific groups
    [PSCustomObject]@{
        Id = [Guid]::NewGuid().ToString()
        DisplayName = "App-CRM-Administrators"
        Description = "CRM application administrators"
        IsRoleAssignable = $false
        SecurityEnabled = $true
        MailEnabled = $false
    }
    [PSCustomObject]@{
        Id = [Guid]::NewGuid().ToString()
        DisplayName = "App-ERP-PowerUsers"
        Description = "ERP system power users"
        IsRoleAssignable = $false
        SecurityEnabled = $true
        MailEnabled = $false
    }
    # Nested group scenario
    [PSCustomObject]@{
        Id = [Guid]::NewGuid().ToString()
        DisplayName = "All IT Staff"
        Description = "Parent group containing all IT-related groups"
        IsRoleAssignable = $false
        SecurityEnabled = $true
        MailEnabled = $false
    }
    [PSCustomObject]@{
        Id = [Guid]::NewGuid().ToString()
        DisplayName = "Privileged IT Admins"
        Description = "Nested group for privileged IT administrators"
        IsRoleAssignable = $true
        SecurityEnabled = $true
        MailEnabled = $false
    }
)

if ($sampleGroups.Count -gt $groupCountTarget) {
    $groupCountTarget = $sampleGroups.Count
}

Write-Host ("Generating {0} groups with security tier classification..." -f $groupCountTarget) -ForegroundColor Yellow

if ($sampleGroups.Count -lt $groupCountTarget) {
    $additionalGroupNames = @(
        "Project Orion Squad",
        "Data Platform Guild",
        "Automation Chapter",
        "Cloud Migration Team",
        "Innovation Lab",
        "Endpoint Readiness Crew",
        "Zero Trust Taskforce",
        "Analytics Tiger Team",
        "SRE Operations Pod",
        "Customer Experience Council"
    )

    $newGroupIndex = 0
    while ($sampleGroups.Count -lt $groupCountTarget) {
        $name = $additionalGroupNames[$newGroupIndex % $additionalGroupNames.Count]
        if ($newGroupIndex -ge $additionalGroupNames.Count) {
            $suffix = [Math]::Floor($newGroupIndex / $additionalGroupNames.Count) + 2
            $name = "$name $suffix"
        }

        $sampleGroups += [PSCustomObject]@{
            Id = [Guid]::NewGuid().ToString()
            DisplayName = $name
            Description = "Auto-generated collaboration group"
            IsRoleAssignable = $false
            SecurityEnabled = $true
            MailEnabled = $false
        }

        $newGroupIndex++
    }
}

# Normalize group metadata for downstream processing
$groupLookup = @{}
for ($i = 0; $i -lt $sampleGroups.Count; $i++) {
    $group = $sampleGroups[$i]
    $groupLookup[$group.DisplayName] = $group

    if (-not ($group.PSObject.Properties.Name -contains 'isAssignableToRole')) {
        $group | Add-Member -NotePropertyName 'isAssignableToRole' -NotePropertyValue $group.IsRoleAssignable
    }
    else {
        $group.isAssignableToRole = $group.IsRoleAssignable
    }

    if (-not ($group.PSObject.Properties.Name -contains 'isPIMEnabled')) {
        $group | Add-Member -NotePropertyName 'isPIMEnabled' -NotePropertyValue $false
    }
    else {
        $group.isPIMEnabled = $false
    }

    if (-not ($group.PSObject.Properties.Name -contains 'memberCount')) {
        $group | Add-Member -NotePropertyName 'memberCount' -NotePropertyValue 0
    }
    else {
        $group.memberCount = 0
    }
}

function Get-GroupByName {
    param([Parameter(Mandatory = $true)][string]$Name)
    if ($groupLookup.ContainsKey($Name)) {
        return $groupLookup[$Name]
    }
    Write-Warning "Group '$Name' was not found in the generated sample set."
    return $null
}

$tier0RoleMap = @(
    @{ GroupName = "Global Administrators"; RoleId = "62e90394-69f5-4237-9190-012177145e10"; RoleName = "Global Administrator" }
    @{ GroupName = "Privileged Role Administrators"; RoleId = "e8611ab8-c189-46e8-94e1-60213ab1f814"; RoleName = "Privileged Role Administrator" }
    @{ GroupName = "Hybrid Identity Administrators"; RoleId = "8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2"; RoleName = "Hybrid Identity Administrator" }
    @{ GroupName = "Partner Tier Zero Access"; RoleId = "e8611ab8-c189-46e8-94e1-60213ab1f814"; RoleName = "Privileged Role Administrator" }
)

$tier1RoleMap = @(
    @{ GroupName = "Application Administrators"; RoleId = "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"; RoleName = "Application Administrator" }
    @{ GroupName = "Cloud Application Administrators"; RoleId = "158c047a-c907-4556-b7ef-446551a6b5f7"; RoleName = "Cloud Application Administrator" }
    @{ GroupName = "Authentication Administrators"; RoleId = "c4e39bd9-1100-46d3-8c65-fb160da0071f"; RoleName = "Authentication Administrator" }
    @{ GroupName = "User Administrators"; RoleId = "fe930be7-5e62-47db-91af-98c3a49a38b1"; RoleName = "User Administrator" }
    @{ GroupName = "Groups Administrators"; RoleId = "fdd7a751-b60b-444a-984c-02652fe8fa1c"; RoleName = "Groups Administrator" }
    @{ GroupName = "Security Administrators"; RoleId = "194ae4cb-b126-40b2-bd5b-6091b380977d"; RoleName = "Security Administrator" }
    @{ GroupName = "Exchange Administrators"; RoleId = "29232cdf-9323-42fd-ade2-1d097af3e4de"; RoleName = "Exchange Administrator" }
    @{ GroupName = "SharePoint Administrators"; RoleId = "f28a1f50-f6e7-4571-818b-6a12f2af6b6c"; RoleName = "SharePoint Administrator" }
    @{ GroupName = "Teams Administrators"; RoleId = "69091246-20e8-4a56-aa4d-066075b2a7a8"; RoleName = "Teams Administrator" }
    @{ GroupName = "Intune Administrators"; RoleId = "3a2c62db-5318-420d-8d74-23affee5d9d5"; RoleName = "Intune Administrator" }
    @{ GroupName = "Power Platform Administrators"; RoleId = "11648597-926c-4cf3-9c36-bcebb0ba8dcc"; RoleName = "Power Platform Administrator" }
    @{ GroupName = "Office Apps Administrators"; RoleId = "2b745bdf-0803-4d80-aa65-822c4493daac"; RoleName = "Office Apps Administrator" }
    @{ GroupName = "Billing Administrators"; RoleId = "b0f54661-2d74-4c50-afa3-1ec803f12efe"; RoleName = "Billing Administrator" }
    @{ GroupName = "License Administrators"; RoleId = "4d6ac14f-3453-41d0-bef9-a3e0c569773a"; RoleName = "License Administrator" }
)

$tier2RoleMap = @(
    @{ GroupName = "Global Readers"; RoleId = "f2ef992c-3afb-46b9-b7cf-a126ee74c451"; RoleName = "Global Reader" }
    @{ GroupName = "Security Readers"; RoleId = "5d6b6bb7-de71-4623-b4af-96380a352509"; RoleName = "Security Reader" }
    @{ GroupName = "Helpdesk Tier 1"; RoleId = "729827e3-9c14-49f7-bb1b-9608f156bbb8"; RoleName = "Helpdesk Administrator" }
    @{ GroupName = "Helpdesk Tier 2"; RoleId = "c4e39bd9-1100-46d3-8c65-fb160da0071f"; RoleName = "Authentication Administrator" }
    @{ GroupName = "Helpdesk Managers"; RoleId = "4a5d8f65-41da-4de4-8968-e035b65339cf"; RoleName = "Reports Reader" }
)

$crossTierRoleMap = @(
    @{ GroupName = "Partner Developers"; RoleId = "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"; RoleName = "Application Administrator" }
    @{ GroupName = "Finance Department"; RoleId = "194ae4cb-b126-40b2-bd5b-6091b380977d"; RoleName = "Security Administrator" }
    @{ GroupName = "Human Resources"; RoleId = "fe930be7-5e62-47db-91af-98c3a49a38b1"; RoleName = "User Administrator" }
    @{ GroupName = "Legal Department"; RoleId = "fdd7a751-b60b-444a-984c-02652fe8fa1c"; RoleName = "Groups Administrator" }
    @{ GroupName = "Executive Leadership"; RoleId = "f2ef992c-3afb-46b9-b7cf-a126ee74c451"; RoleName = "Global Reader" }
    @{ GroupName = "Sales Team"; RoleId = "f28a1f50-f6e7-4571-818b-6a12f2af6b6c"; RoleName = "SharePoint Administrator" }
    @{ GroupName = "Marketing Team"; RoleId = "158c047a-c907-4556-b7ef-446551a6b5f7"; RoleName = "Cloud Application Administrator" }
    @{ GroupName = "Engineering Team"; RoleId = "3a2c62db-5318-420d-8d74-23affee5d9d5"; RoleName = "Intune Administrator" }
    @{ GroupName = "App-CRM-Administrators"; RoleId = "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"; RoleName = "Application Administrator" }
    @{ GroupName = "App-ERP-PowerUsers"; RoleId = "158c047a-c907-4556-b7ef-446551a6b5f7"; RoleName = "Cloud Application Administrator" }
)

Write-Host ("Generating {0} service principals..." -f $servicePrincipalCountTarget) -ForegroundColor Yellow

$customServicePrincipalCount = [Math]::Max(0, $servicePrincipalCountTarget - $msApps.Count)

# Create Microsoft Graph SP with full roles
$sampleServicePrincipals = @()
$sampleServicePrincipals += [PSCustomObject]@{
    Id = [Guid]::NewGuid().ToString()
    DisplayName = "Microsoft Graph"
    AppId = $graphAppId
    AccountEnabled = $true
    oauth2PermissionScopes = @(
        [PSCustomObject]@{
            Id = $permissionIds.DirectoryAccessAsUserAll
            Value = "Directory.AccessAsUser.All"
            AdminConsentDisplayName = "Access directory as the signed-in user"
            AdminConsentDescription = "Allows the app to have the same access as the signed-in user."
        }
    )
    appRoles = @(
        [PSCustomObject]@{
            Id = $permissionIds.ApplicationReadWriteAll
            Value = "Application.ReadWrite.All"
            DisplayName = "Read and write all applications"
            Description = "Allows the app to create, update, delete, and read applications."
        }
        [PSCustomObject]@{
            Id = $permissionIds.RoleManagementReadWriteDirectory
            Value = "RoleManagement.ReadWrite.Directory"
            DisplayName = "Manage directory roles"
            Description = "Allows the app to read and write directory role assignments."
        }
        [PSCustomObject]@{
            Id = $permissionIds.DirectoryReadWriteAll
            Value = "Directory.ReadWrite.All"
            DisplayName = "Read and write directory data"
            Description = "Allows the app to write data in your directory."
        }
        [PSCustomObject]@{
            Id = $permissionIds.GroupReadWriteAll
            Value = "Group.ReadWrite.All"
            DisplayName = "Read and write all groups"
            Description = "Allows the app to create, read, update, and delete groups."
        }
    )
    GrantedApplicationPermissions = @()
    GrantedDelegatedPermissions = @()
}

# Add Microsoft first-party apps
for ($i = 1; $i -lt $msApps.Count; $i++) {
    $sampleServicePrincipals += [PSCustomObject]@{
        Id = [Guid]::NewGuid().ToString()
        DisplayName = $msApps[$i].Name
        AppId = $msApps[$i].AppId
        AccountEnabled = $true
        GrantedApplicationPermissions = @()
        GrantedDelegatedPermissions = @()
    }
}

# Add custom enterprise service principals to reach the target
$dangerousPermissions = @(
    @{ Id = $permissionIds.ApplicationReadWriteAll; Name = "Application.ReadWrite.All"; Desc = "Can create malicious applications" }
    @{ Id = $permissionIds.DirectoryReadWriteAll; Name = "Directory.ReadWrite.All"; Desc = "Can modify directory data" }
    @{ Id = $permissionIds.RoleManagementReadWriteDirectory; Name = "RoleManagement.ReadWrite.Directory"; Desc = "Can assign privileged roles" }
    @{ Id = $permissionIds.GroupReadWriteAll; Name = "Group.ReadWrite.All"; Desc = "Can modify role-assignable groups" }
    @{ Id = $permissionIds.DomainReadWriteAll; Name = "Domain.ReadWrite.All"; Desc = "Can configure federation - high risk" }
    @{ Id = $permissionIds.DeviceManagementConfigurationReadWriteAll; Name = "DeviceManagementConfiguration.ReadWrite.All"; Desc = "Can deploy scripts to devices" }
    @{ Id = $permissionIds.UserReadWriteAll; Name = "User.ReadWrite.All"; Desc = "Can create and modify users" }
    @{ Id = $permissionIds.AppRoleAssignmentReadWriteAll; Name = "AppRoleAssignment.ReadWrite.All"; Desc = "Can assign app roles" }
)

for ($i = 0; $i -lt $customServicePrincipalCount; $i++) {
    $grantedPerms = @()
    
    # Assign 1-3 dangerous permissions randomly
    $permCount = Get-Random -Minimum 1 -Maximum 4
    $selectedIndices = 0..($dangerousPermissions.Count - 1) | Get-Random -Count $permCount
    
    foreach ($idx in $selectedIndices) {
        $perm = $dangerousPermissions[$idx]
        $grantedPerms += [PSCustomObject]@{
            AssignmentId = [Guid]::NewGuid().ToString()
            ResourceId = $sampleServicePrincipals[0].Id  # Microsoft Graph
            ResourceDisplayName = "Microsoft Graph"
            AppRoleId = $perm.Id
            AppRoleValue = $perm.Name
            AppRoleDisplayName = $perm.Name
            AppRoleDescription = $perm.Desc
        }
    }
    
    $scenarioName = $appScenarios[$i % $appScenarios.Count]
    if ($i -ge $appScenarios.Count) {
        $scenarioName = "$scenarioName SP$([Math]::Floor($i / $appScenarios.Count) + 1)"
    }

    $sampleServicePrincipals += [PSCustomObject]@{
        Id = [Guid]::NewGuid().ToString()
        DisplayName = $scenarioName
        AppId = [Guid]::NewGuid().ToString()
        AccountEnabled = (($i % 15) -ne 0)  # 1 in 15 disabled
        GrantedApplicationPermissions = $grantedPerms
        GrantedDelegatedPermissions = @()
    }
}

Write-Host "Generating 50 application registrations..." -ForegroundColor Yellow

# Create 50 application registrations
$sampleApps = @()
for ($i = 0; $i -lt 50; $i++) {
    $scenarioName = $appScenarios[$i % $appScenarios.Count]
    if ($i -ge $appScenarios.Count) {
        $scenarioName = "$scenarioName V$(1 + [Math]::Floor($i / $appScenarios.Count))"
    }
    
    $apiPermissions = @()
    
    # 80% of apps have permissions
    if (($i % 10) -lt 8) {
        $permCount = Get-Random -Minimum 1 -Maximum 4
        $selectedIndices = 0..($dangerousPermissions.Count - 1) | Get-Random -Count $permCount
        
        $resourceAccess = @()
        foreach ($idx in $selectedIndices) {
            $resourceAccess += [PSCustomObject]@{
                Id = $dangerousPermissions[$idx].Id
                Type = "Role"
            }
        }
        
        $apiPermissions = @(
            [PSCustomObject]@{
                ResourceAppId = $graphAppId
                ResourceAccess = $resourceAccess
            }
        )
    }
    
    $sampleApps += [PSCustomObject]@{
        Id = [Guid]::NewGuid().ToString()
        DisplayName = $scenarioName
        AppId = [Guid]::NewGuid().ToString()
        ApiPermissions = $apiPermissions
    }
}

Write-Host "Assigning owners to application registrations..." -ForegroundColor Yellow

$appOwners = @{}
$privilegedOwnerCandidates = @(
    $sampleUsers[0],  # BreakGlass #1
    $sampleUsers[1],  # BreakGlass #2
    $sampleUsers[5],
    $sampleUsers[10],
    $sampleUsers[15],
    $sampleUsers[25]
) | Where-Object { $_ -ne $null }

$memberUserPool = $sampleUsers | Where-Object { $_.UserType -eq 'Member' }

foreach ($app in $sampleApps) {
    $ownerCount = if ($app.ApiPermissions -and $app.ApiPermissions.Count -gt 0) {
        Get-Random -Minimum 2 -Maximum 6  # 2-5 owners for privileged apps
    }
    else {
        Get-Random -Minimum 1 -Maximum 4  # 1-3 owners for standard apps
    }

    if ($ownerCount -gt $memberUserPool.Count) {
        $ownerCount = $memberUserPool.Count
    }

    $owners = @()

    if ($app.ApiPermissions -and $app.ApiPermissions.Count -gt 0 -and $privilegedOwnerCandidates.Count -gt 0) {
        $privilegedOwner = Get-Random -InputObject $privilegedOwnerCandidates
        $owners += [PSCustomObject]@{
            id = $privilegedOwner.Id
            displayName = $privilegedOwner.DisplayName
            userPrincipalName = $privilegedOwner.UserPrincipalName
        }
    }

    while ($owners.Count -lt $ownerCount) {
        $candidate = Get-Random -InputObject $memberUserPool
        $alreadyOwner = $owners | Where-Object { $_.id -eq $candidate.Id }
        if ($alreadyOwner) { continue }

        $owners += [PSCustomObject]@{
            id = $candidate.Id
            displayName = $candidate.DisplayName
            userPrincipalName = $candidate.UserPrincipalName
        }
    }

    $appOwners[$app.Id] = $owners
}

Write-Host "Generating role assignments..." -ForegroundColor Yellow

# Generate comprehensive role assignments
$roleAssignments = @()
$pimAssignments = @()  # Initialize PIM assignments array

# Define all Entra ID roles with comprehensive properties
$entraRoles = @(
    @{ Id = "62e90394-69f5-4237-9190-012177145e10"; TemplateId = "62e90394-69f5-4237-9190-012177145e10"; Name = "Global Administrator"; Description = "Can manage all aspects of Azure AD and Microsoft services that use Azure AD identities."; AllowedActionsCount = 245 }
    @{ Id = "e8611ab8-c189-46e8-94e1-60213ab1f814"; TemplateId = "e8611ab8-c189-46e8-94e1-60213ab1f814"; Name = "Privileged Role Administrator"; Description = "Can manage role assignments in Azure AD, and all aspects of Privileged Identity Management."; AllowedActionsCount = 87 }
    @{ Id = "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"; TemplateId = "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"; Name = "Application Administrator"; Description = "Can create and manage all aspects of app registrations and enterprise apps."; AllowedActionsCount = 56 }
    @{ Id = "c4e39bd9-1100-46d3-8c65-fb160da0071f"; TemplateId = "c4e39bd9-1100-46d3-8c65-fb160da0071f"; Name = "Authentication Administrator"; Description = "Can view, set and reset authentication method information for any non-admin user."; AllowedActionsCount = 42 }
    @{ Id = "729827e3-9c14-49f7-bb1b-9608f156bbb8"; TemplateId = "729827e3-9c14-49f7-bb1b-9608f156bbb8"; Name = "Helpdesk Administrator"; Description = "Can reset passwords for non-administrators and Helpdesk Administrators."; AllowedActionsCount = 28 }
    @{ Id = "194ae4cb-b126-40b2-bd5b-6091b380977d"; TemplateId = "194ae4cb-b126-40b2-bd5b-6091b380977d"; Name = "Security Administrator"; Description = "Can read security information and reports, and manage configuration in Azure AD and Office 365."; AllowedActionsCount = 93 }
    @{ Id = "fe930be7-5e62-47db-91af-98c3a49a38b1"; TemplateId = "fe930be7-5e62-47db-91af-98c3a49a38b1"; Name = "User Administrator"; Description = "Can manage all aspects of users and groups, including resetting passwords for limited admins."; AllowedActionsCount = 67 }
    @{ Id = "fdd7a751-b60b-444a-984c-02652fe8fa1c"; TemplateId = "fdd7a751-b60b-444a-984c-02652fe8fa1c"; Name = "Groups Administrator"; Description = "Members of this role can create/manage groups and its settings like naming and expiration policies."; AllowedActionsCount = 38 }
    @{ Id = "158c047a-c907-4556-b7ef-446551a6b5f7"; TemplateId = "158c047a-c907-4556-b7ef-446551a6b5f7"; Name = "Cloud Application Administrator"; Description = "Can create and manage all aspects of app registrations and enterprise apps except App Proxy."; AllowedActionsCount = 51 }
    @{ Id = "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9"; TemplateId = "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9"; Name = "Conditional Access Administrator"; Description = "Can manage Conditional Access capabilities."; AllowedActionsCount = 24 }
    @{ Id = "29232cdf-9323-42fd-ade2-1d097af3e4de"; TemplateId = "29232cdf-9323-42fd-ade2-1d097af3e4de"; Name = "Exchange Administrator"; Description = "Can manage all aspects of the Exchange product."; AllowedActionsCount = 45 }
    @{ Id = "f28a1f50-f6e7-4571-818b-6a12f2af6b6c"; TemplateId = "f28a1f50-f6e7-4571-818b-6a12f2af6b6c"; Name = "SharePoint Administrator"; Description = "Can manage all aspects of the SharePoint service."; AllowedActionsCount = 39 }
    @{ Id = "69091246-20e8-4a56-aa4d-066075b2a7a8"; TemplateId = "69091246-20e8-4a56-aa4d-066075b2a7a8"; Name = "Teams Administrator"; Description = "Can manage the Microsoft Teams service."; AllowedActionsCount = 41 }
    @{ Id = "3a2c62db-5318-420d-8d74-23affee5d9d5"; TemplateId = "3a2c62db-5318-420d-8d74-23affee5d9d5"; Name = "Intune Administrator"; Description = "Can manage all aspects of the Intune product."; AllowedActionsCount = 52 }
    @{ Id = "9360feb5-f418-4baa-8175-e2a00bac4301"; TemplateId = "9360feb5-f418-4baa-8175-e2a00bac4301"; Name = "Directory Writers"; Description = "Can read and write basic directory information."; AllowedActionsCount = 15 }
    @{ Id = "5d6b6bb7-de71-4623-b4af-96380a352509"; TemplateId = "5d6b6bb7-de71-4623-b4af-96380a352509"; Name = "Security Reader"; Description = "Can read security information and reports in Azure AD and Office 365."; AllowedActionsCount = 31 }
    @{ Id = "f2ef992c-3afb-46b9-b7cf-a126ee74c451"; TemplateId = "f2ef992c-3afb-46b9-b7cf-a126ee74c451"; Name = "Global Reader"; Description = "Can read everything that a Global Administrator can, but not update anything."; AllowedActionsCount = 189 }
)

$tier0GroupIds = @()
foreach ($mapping in $tier0RoleMap) {
    $group = Get-GroupByName -Name $mapping.GroupName
    if (-not $group) { continue }
    $tier0GroupIds += $group.Id
    $group.isAssignableToRole = $true
    $group.isPIMEnabled = $true

    $role = $entraRoles | Where-Object { $_.Id -eq $mapping.RoleId } | Select-Object -First 1

    $pimAssignments += [PSCustomObject]@{
        Id = [Guid]::NewGuid().ToString()
        RoleId = $mapping.RoleId
        RoleName = $mapping.RoleName
        RoleDescription = if ($role) { $role.Description } else { $mapping.RoleName }
        RoleDefinitionId = $mapping.RoleId
        RoleTemplateId = $mapping.RoleId
        RoleIsBuiltIn = $true
        RoleIsEnabled = $true
        RoleResourceScopes = @("/")
        RoleAllowedActionsCount = if ($role) { $role.AllowedActionsCount } else { 0 }
        PrincipalId = $group.Id
        PrincipalType = "group"
        AssignmentType = "PIM-Eligible"
        AssignmentState = "Eligible"
        StartDateTime = (Get-Date).AddDays(-90).ToString("yyyy-MM-ddTHH:mm:ssZ")
        EndDateTime = (Get-Date).AddDays(275).ToString("yyyy-MM-ddTHH:mm:ssZ")
    }
}

$tier1GroupIds = @()
foreach ($mapping in $tier1RoleMap) {
    $group = Get-GroupByName -Name $mapping.GroupName
    if (-not $group) { continue }
    $tier1GroupIds += $group.Id
    $group.isAssignableToRole = $true
    $group.isPIMEnabled = $true

    $role = $entraRoles | Where-Object { $_.Id -eq $mapping.RoleId } | Select-Object -First 1

    $pimAssignments += [PSCustomObject]@{
        Id = [Guid]::NewGuid().ToString()
        RoleId = $mapping.RoleId
        RoleName = $mapping.RoleName
        RoleDescription = $mapping.RoleName
        RoleDefinitionId = if ($role) { $role.Id } else { $mapping.RoleId }
        RoleTemplateId = if ($role) { $role.TemplateId } else { $mapping.RoleId }
        RoleIsBuiltIn = $true
        RoleIsEnabled = $true
        RoleResourceScopes = @("/")
        RoleAllowedActionsCount = if ($role) { $role.AllowedActionsCount } else { 0 }
        PrincipalId = $group.Id
        PrincipalType = "group"
        AssignmentType = "PIM-Eligible"
        AssignmentState = "Eligible"
        StartDateTime = (Get-Date).AddDays(-60).ToString("yyyy-MM-ddTHH:mm:ssZ")
        EndDateTime = (Get-Date).AddDays(305).ToString("yyyy-MM-ddTHH:mm:ssZ")
    }
}

$tier2GroupIds = @()
foreach ($mapping in $tier2RoleMap) {
    $group = Get-GroupByName -Name $mapping.GroupName
    if (-not $group) { continue }
    $tier2GroupIds += $group.Id
    $group.isAssignableToRole = $true
    $group.isPIMEnabled = $false

    $role = $entraRoles | Where-Object { $_.Id -eq $mapping.RoleId } | Select-Object -First 1

    $roleAssignments += [PSCustomObject]@{
        Id = [Guid]::NewGuid().ToString()
        RoleId = $mapping.RoleId
        RoleName = $mapping.RoleName
        RoleDescription = $mapping.RoleName
        RoleDefinitionId = if ($role) { $role.Id } else { $mapping.RoleId }
        RoleTemplateId = if ($role) { $role.TemplateId } else { $mapping.RoleId }
        RoleIsBuiltIn = $true
        RoleIsEnabled = $true
        RoleResourceScopes = @("/")
        RoleAllowedActionsCount = if ($role) { $role.AllowedActionsCount } else { 0 }
        MemberId = $group.Id
        MemberType = "group"
        AssignmentType = "Direct"
    }
}

$crossTierGroupIds = @()
foreach ($mapping in $crossTierRoleMap) {
    $group = Get-GroupByName -Name $mapping.GroupName
    if (-not $group) { continue }
    $crossTierGroupIds += $group.Id
    $group.isAssignableToRole = $true
    $group.isPIMEnabled = $true

    $role = $entraRoles | Where-Object { $_.Id -eq $mapping.RoleId } | Select-Object -First 1

    $pimAssignments += [PSCustomObject]@{
        Id = [Guid]::NewGuid().ToString()
        RoleId = $mapping.RoleId
        RoleName = $mapping.RoleName
        RoleDescription = $mapping.RoleName
        RoleDefinitionId = if ($role) { $role.Id } else { $mapping.RoleId }
        RoleTemplateId = if ($role) { $role.TemplateId } else { $mapping.RoleId }
        RoleIsBuiltIn = $true
        RoleIsEnabled = $true
        RoleResourceScopes = @("/")
        RoleAllowedActionsCount = if ($role) { $role.AllowedActionsCount } else { 0 }
        PrincipalId = $group.Id
        PrincipalType = "group"
        AssignmentType = "PIM-Eligible"
        AssignmentState = "Eligible"
        StartDateTime = (Get-Date).AddDays(-45).ToString("yyyy-MM-ddTHH:mm:ssZ")
        EndDateTime = (Get-Date).AddDays(320).ToString("yyyy-MM-ddTHH:mm:ssZ")
    }
}

# Assign helpdesk roles to helpdesk groups
$helpdeskRole = $entraRoles | Where-Object { $_.Id -eq "729827e3-9c14-49f7-bb1b-9608f156bbb8" } | Select-Object -First 1
$roleAssignments += [PSCustomObject]@{
    Id = [Guid]::NewGuid().ToString()
    RoleId = "729827e3-9c14-49f7-bb1b-9608f156bbb8"
    RoleName = "Helpdesk Administrator"
    RoleDescription = "Helpdesk Administrator"
    RoleDefinitionId = if ($helpdeskRole) { $helpdeskRole.Id } else { "729827e3-9c14-49f7-bb1b-9608f156bbb8" }
    RoleTemplateId = if ($helpdeskRole) { $helpdeskRole.TemplateId } else { "729827e3-9c14-49f7-bb1b-9608f156bbb8" }
    RoleIsBuiltIn = $true
    RoleIsEnabled = $true
    RoleResourceScopes = @("/")
    RoleAllowedActionsCount = if ($helpdeskRole) { $helpdeskRole.AllowedActionsCount } else { 0 }
    MemberId = $sampleGroups[23].Id  # Helpdesk Tier 1
    MemberType = "group"
    AssignmentType = "Direct"
}

$authRole = $entraRoles | Where-Object { $_.Id -eq "c4e39bd9-1100-46d3-8c65-fb160da0071f" } | Select-Object -First 1
$roleAssignments += [PSCustomObject]@{
    Id = [Guid]::NewGuid().ToString()
    RoleId = "c4e39bd9-1100-46d3-8c65-fb160da0071f"
    RoleName = "Authentication Administrator"
    RoleDescription = "Authentication Administrator"
    RoleDefinitionId = if ($authRole) { $authRole.Id } else { "c4e39bd9-1100-46d3-8c65-fb160da0071f" }
    RoleTemplateId = if ($authRole) { $authRole.TemplateId } else { "c4e39bd9-1100-46d3-8c65-fb160da0071f" }
    RoleIsBuiltIn = $true
    RoleIsEnabled = $true
    RoleResourceScopes = @("/")
    RoleAllowedActionsCount = if ($authRole) { $authRole.AllowedActionsCount } else { 0 }
    MemberId = $sampleGroups[24].Id  # Helpdesk Tier 2
    MemberType = "group"
    AssignmentType = "Direct"
}

# Assign multiple service principals with privileged roles (escalation risk)
for ($i = 13; $i -lt 25; $i++) {
    $role = $entraRoles[$i % $entraRoles.Count]
    $roleAssignments += [PSCustomObject]@{
        Id = [Guid]::NewGuid().ToString()
        RoleId = $role.Id
        RoleName = $role.Name
        RoleDescription = $role.Name
        RoleDefinitionId = $role.Id
        RoleTemplateId = $role.TemplateId
        RoleIsBuiltIn = $true
        RoleIsEnabled = $true
        RoleResourceScopes = @("/")
        RoleAllowedActionsCount = $role.AllowedActionsCount
        MemberId = $sampleServicePrincipals[$i].Id
        MemberType = "servicePrincipal"
        AssignmentType = "Direct"
    }
}

# ONLY a few users get DIRECT role assignments (break-glass and emergency accounts)
# Most users should get roles through GROUP membership to demonstrate escalation paths
$directUserRoles = @(
    @{ UserId = $sampleUsers[0].Id; RoleId = "62e90394-69f5-4237-9190-012177145e10"; RoleName = "Global Administrator" }  # BreakGlass #1
    @{ UserId = $sampleUsers[1].Id; RoleId = "62e90394-69f5-4237-9190-012177145e10"; RoleName = "Global Administrator" }  # BreakGlass #2
)

# Add a few misconfigurations (privilege escalation risks)
# User with Application Administrator can escalate to Global Admin
$directUserRoles += @{ UserId = $sampleUsers[5].Id; RoleId = "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"; RoleName = "Application Administrator" }  # Escalation risk
# User with Privileged Authentication Administrator can reset admin passwords
$directUserRoles += @{ UserId = $sampleUsers[10].Id; RoleId = "7be44c8a-adaf-4e2a-84d6-ab2649e08a13"; RoleName = "Privileged Authentication Administrator" }  # Escalation risk
# Regular user with Cloud App Admin (can create apps with permissions)
$directUserRoles += @{ UserId = $sampleUsers[15].Id; RoleId = "158c047a-c907-4556-b7ef-446551a6b5f7"; RoleName = "Cloud Application Administrator" }  # Escalation risk
# Helpdesk user who can reset some admin passwords
$directUserRoles += @{ UserId = $sampleUsers[25].Id; RoleId = "729827e3-9c14-49f7-bb1b-9608f156bbb8"; RoleName = "Helpdesk Administrator" }  # Lower risk

foreach ($assignment in $directUserRoles) {
    $role = $entraRoles | Where-Object { $_.Id -eq $assignment.RoleId } | Select-Object -First 1
    $roleAssignments += [PSCustomObject]@{
        Id = [Guid]::NewGuid().ToString()
        RoleId = $assignment.RoleId
        RoleName = $assignment.RoleName
        RoleDescription = $assignment.RoleName
        RoleDefinitionId = if ($role) { $role.Id } else { $assignment.RoleId }
        RoleTemplateId = if ($role) { $role.TemplateId } else { $assignment.RoleId }
        RoleIsBuiltIn = $true
        RoleIsEnabled = $true
        RoleResourceScopes = @("/")
        RoleAllowedActionsCount = if ($role) { $role.AllowedActionsCount } else { 0 }
        MemberId = $assignment.UserId
        MemberType = "user"
        AssignmentType = "Direct"
    }
}

Write-Host "Generating PIM assignments..." -ForegroundColor Yellow

# Generate PIM eligible assignments for individual users (20 users - not too many)
# Note: Admin groups already have PIM assignments created in the tier loops above
for ($i = 100; $i -lt 120; $i++) {
    $roles = @(
        @{ Id = "62e90394-69f5-4237-9190-012177145e10"; Name = "Global Administrator" }
        @{ Id = "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"; Name = "Application Administrator" }
        @{ Id = "e8611ab8-c189-46e8-94e1-60213ab1f814"; Name = "Privileged Role Administrator" }
        @{ Id = "729827e3-9c14-49f7-bb1b-9608f156bbb8"; Name = "Helpdesk Administrator" }
        @{ Id = "194ae4cb-b126-40b2-bd5b-6091b380977d"; Name = "Security Administrator" }
    )
    
    $selectedRole = $roles[$i % $roles.Count]
    $roleDetails = $entraRoles | Where-Object { $_.Id -eq $selectedRole.Id } | Select-Object -First 1
    
    $pimAssignments += [PSCustomObject]@{
        Id = [Guid]::NewGuid().ToString()
        RoleId = $selectedRole.Id
        RoleName = $selectedRole.Name
        RoleDescription = $selectedRole.Name
        RoleDefinitionId = if ($roleDetails) { $roleDetails.Id } else { $selectedRole.Id }
        RoleTemplateId = if ($roleDetails) { $roleDetails.TemplateId } else { $selectedRole.Id }
        RoleIsBuiltIn = $true
        RoleIsEnabled = $true
        RoleResourceScopes = @("/")
        RoleAllowedActionsCount = if ($roleDetails) { $roleDetails.AllowedActionsCount } else { 0 }
        PrincipalId = $sampleUsers[$i].Id
        PrincipalType = "user"
        AssignmentType = "PIM-Eligible"
        AssignmentState = "Eligible"
        StartDateTime = (Get-Date).AddDays(-30).ToString("yyyy-MM-ddTHH:mm:ssZ")
        EndDateTime = (Get-Date).AddDays(335).ToString("yyyy-MM-ddTHH:mm:ssZ")
    }
}

Write-Host "Generating group memberships with nested structures..." -ForegroundColor Yellow

# Generate complex group membership patterns (hashtable format)
# Key = GroupId, Value = Array of members
$groupMemberships = @{}

# First, ensure ALL role-assigned and PIM-enabled groups have members (priority assignment)
$roledGroupIds = ($roleAssignments | Where-Object { $_.MemberType -eq 'group' }).MemberId | Select-Object -Unique
$pimGroupIds = ($pimAssignments | Where-Object { $_.PrincipalType -eq 'group' }).PrincipalId | Select-Object -Unique
$allPrivilegedGroupIds = @($roledGroupIds; $pimGroupIds) | Select-Object -Unique

Write-Host "  Assigning users to $($allPrivilegedGroupIds.Count) privileged groups..." -ForegroundColor Gray

# Assign users to privileged groups based on tier - realistic for a 200-600 employee company
# In a typical 200-600 person org: ~5-10% have some admin rights, ~1-2% have high privileges
# Use consistent member counts but random user selection

# Create a pool of users to randomly assign (excluding break-glass accounts 0-1)
$assignableUsers = $sampleUsers | Select-Object -Skip 2

foreach ($groupId in $allPrivilegedGroupIds) {
    if (-not $groupMemberships.ContainsKey($groupId)) {
        $groupMemberships[$groupId] = @()
    }

    $group = $sampleGroups | Where-Object { $_.Id -eq $groupId }
    if (-not $group) { continue }

    if ($tier0GroupIds -contains $groupId -or $tier1GroupIds -contains $groupId) {
        $memberCount = Get-Random -Minimum 2 -Maximum 5  # 2-4 members
    }
    elseif ($tier2GroupIds -contains $groupId) {
        $memberCount = Get-Random -Minimum 2 -Maximum 6  # 2-5 members
    }
    elseif ($crossTierGroupIds -contains $groupId) {
        $memberCount = Get-Random -Minimum 2 -Maximum 5
    }
    else {
        $memberCount = Get-Random -Minimum 2 -Maximum 4
    }

    if ($memberCount -gt $assignableUsers.Count) {
        $memberCount = $assignableUsers.Count
    }

    $selectedUsers = Get-Random -InputObject $assignableUsers -Count $memberCount
    if ($selectedUsers -isnot [System.Array]) {
        $selectedUsers = @($selectedUsers)
    }

    foreach ($user in $selectedUsers) {
        $alreadyMember = $groupMemberships[$groupId] | Where-Object { $_.id -eq $user.Id }
        if (-not $alreadyMember) {
            $groupMemberships[$groupId] += [PSCustomObject]@{
                id = $user.Id
                displayName = $user.DisplayName
                '@odata.type' = '#microsoft.graph.user'
                Type = 'User'
            }
        }
    }
}

Write-Host "  Distributing remaining users across all groups..." -ForegroundColor Gray

# Now distribute remaining users across ALL groups (including non-privileged ones)
# But DO NOT add more members to privileged groups that already have carefully assigned counts
for ($i = 0; $i -lt $sampleUsers.Count; $i++) {
    # Each user in 2-5 groups (creating realistic membership patterns)
    $groupCount = Get-Random -Minimum 2 -Maximum 6
    $selectedGroups = $sampleGroups | Get-Random -Count $groupCount
    
    foreach ($group in $selectedGroups) {
        # Skip if this is a privileged group that already has members assigned
        if ($allPrivilegedGroupIds -contains $group.Id) {
            continue  # Don't add random users to privileged groups
        }
        
        if (-not $groupMemberships.ContainsKey($group.Id)) {
            $groupMemberships[$group.Id] = @()
        }
        
        # Check if user already in this group
        $alreadyMember = $groupMemberships[$group.Id] | Where-Object { $_.id -eq $sampleUsers[$i].Id }
        if (-not $alreadyMember) {
            $groupMemberships[$group.Id] += [PSCustomObject]@{
                id = $sampleUsers[$i].Id
                displayName = $sampleUsers[$i].DisplayName
                '@odata.type' = '#microsoft.graph.user'
                Type = 'User'
            }
        }
    }
}

# Nested group memberships (create privilege escalation paths through nested groups)
Write-Host "  Creating nested group structures..." -ForegroundColor Gray

$appCrmAdmins = Get-GroupByName -Name "App-CRM-Administrators"
$appErpPowerUsers = Get-GroupByName -Name "App-ERP-PowerUsers"
$globalReadersGroup = Get-GroupByName -Name "Global Readers"
$securityReadersGroup = Get-GroupByName -Name "Security Readers"
$applicationAdminsGroup = Get-GroupByName -Name "Application Administrators"

if ($appCrmAdmins) {
    if (-not $groupMemberships.ContainsKey($appCrmAdmins.Id)) {
        $groupMemberships[$appCrmAdmins.Id] = @()
    }
    if ($globalReadersGroup) {
        $groupMemberships[$appCrmAdmins.Id] += [PSCustomObject]@{
            id = $globalReadersGroup.Id
            displayName = $globalReadersGroup.DisplayName
            '@odata.type' = '#microsoft.graph.group'
            Type = 'Group'
        }
    }
    if ($securityReadersGroup) {
        $groupMemberships[$appCrmAdmins.Id] += [PSCustomObject]@{
            id = $securityReadersGroup.Id
            displayName = $securityReadersGroup.DisplayName
            '@odata.type' = '#microsoft.graph.group'
            Type = 'Group'
        }
    }
}

if ($appErpPowerUsers -and $applicationAdminsGroup) {
    if (-not $groupMemberships.ContainsKey($appErpPowerUsers.Id)) {
        $groupMemberships[$appErpPowerUsers.Id] = @()
    }
    $groupMemberships[$appErpPowerUsers.Id] += [PSCustomObject]@{
        id = $applicationAdminsGroup.Id
        displayName = $applicationAdminsGroup.DisplayName
        '@odata.type' = '#microsoft.graph.group'
        Type = 'Group'
    }
}

# Add external users to privileged groups (risk scenario)
$guestUsers = $sampleUsers | Where-Object { $_.UserType -eq "Guest" } | Select-Object -First 3
$helpdeskTier2 = Get-GroupByName -Name "Helpdesk Tier 2"
if ($helpdeskTier2) {
    if (-not $groupMemberships.ContainsKey($helpdeskTier2.Id)) {
        $groupMemberships[$helpdeskTier2.Id] = @()
    }
    foreach ($guest in $guestUsers) {
        $groupMemberships[$helpdeskTier2.Id] += [PSCustomObject]@{
            id = $guest.Id
            displayName = $guest.DisplayName
            '@odata.type' = '#microsoft.graph.user'
            Type = 'User'
        }
    }
}

Write-Host "  Total group memberships created: $($groupMemberships.Keys.Count) groups with members" -ForegroundColor Gray

Write-Host "Generating escalation risks and attack paths..." -ForegroundColor Yellow

# Generate comprehensive escalation risks
$escalationRisks = @()

# Role-enabled group risks (ALL role-assignable groups)
for ($i = 0; $i -lt $sampleGroups.Count; $i++) {
    $group = $sampleGroups[$i]
    if ($group.IsRoleAssignable) {
        # Find members of this group
        $memberCount = if ($groupMemberships.ContainsKey($group.Id)) { $groupMemberships[$group.Id].Count } else { 0 }
        
        $escalationRisks += [PSCustomObject]@{
            Id = [Guid]::NewGuid().ToString()
            RiskType = "RoleAssignableGroupMembership"
            Severity = if ($i -lt 4) { "Critical" } else { "High" }
            Title = "Role-Assignable Group: $($group.DisplayName)"
            Description = "Group '$($group.DisplayName)' is role-assignable with $memberCount members. All members can inherit privileged role assignments."
            AffectedEntity = $group.Id
            AffectedEntityType = "Group"
            AffectedEntityName = $group.DisplayName
            EscalationPath = @("Add user to group", "User inherits role assignment", "Elevate privileges")
        }
    }
}

# Service principal with dangerous permissions (expanded)
for ($i = 13; $i -lt $sampleServicePrincipals.Count; $i++) {
    $sp = $sampleServicePrincipals[$i]
    if ($sp.GrantedApplicationPermissions.Count -gt 0) {
        $permissions = ($sp.GrantedApplicationPermissions | ForEach-Object { $_.AppRoleValue }) -join ", "
        $escalationRisks += [PSCustomObject]@{
            Id = [Guid]::NewGuid().ToString()
            RiskType = "ServicePrincipalDangerousPermissions"
            Severity = "Critical"
            Title = "Service Principal with High-Risk Permissions: $($sp.DisplayName)"
            Description = "Service principal has dangerous permissions: $permissions. Can be used for privilege escalation."
            AffectedEntity = $sp.Id
            AffectedEntityType = "ServicePrincipal"
            AffectedEntityName = $sp.DisplayName
            EscalationPath = @("Compromise SP credentials", "Use Graph API with dangerous permissions", "Elevate privileges")
        }
    }
}

# User with direct role assignment risks
for ($i = 0; $i -lt 50; $i++) {
    $user = $sampleUsers[$i]
    $userRoles = $roleAssignments | Where-Object { $_.MemberId -eq $user.Id }
    if ($userRoles.Count -gt 0) {
        $roleNames = ($userRoles | ForEach-Object { $_.RoleName }) -join ", "
        $escalationRisks += [PSCustomObject]@{
            Id = [Guid]::NewGuid().ToString()
            RiskType = "UserDirectRoleAssignment"
            Severity = "High"
            Title = "User with Direct Privileged Role: $($user.DisplayName)"
            Description = "User '$($user.DisplayName)' has direct role assignment(s): $roleNames. Compromise of this account leads to immediate privilege escalation."
            AffectedEntity = $user.Id
            AffectedEntityType = "User"
            AffectedEntityName = $user.DisplayName
            EscalationPath = @("Compromise user credentials", "Access privileged role", "Execute privileged operations")
        }
    }
}

# Group membership escalation paths
for ($i = 0; $i -lt 10; $i++) {
    $group = $sampleGroups[$i]
    if ($groupMemberships.ContainsKey($group.Id)) {
        $members = $groupMemberships[$group.Id]
        $userMembers = $members | Where-Object { $_.Type -eq "User" }
        if ($userMembers.Count -gt 0) {
            $sampleUser = $userMembers | Select-Object -First 1
            $escalationRisks += [PSCustomObject]@{
                Id = [Guid]::NewGuid().ToString()
                RiskType = "GroupMembershipEscalation"
                Severity = "High"
                Title = "Escalation via Group Membership: $($group.DisplayName)"
                Description = "Users in '$($group.DisplayName)' can escalate privileges through group role assignments. Example: $($sampleUser.DisplayName)"
                AffectedEntity = $group.Id
                AffectedEntityType = "Group"
                AffectedEntityName = $group.DisplayName
                EscalationPath = @("Compromise group member account", "Inherit group's role assignments", "Access privileged resources")
            }
        }
    }
}

# Nested group escalation (multiple paths)
$escalationRisks += [PSCustomObject]@{
    Id = [Guid]::NewGuid().ToString()
    RiskType = "NestedGroupEscalation"
    Severity = "High"
    Title = "Nested Group Membership Chain: All IT Staff"
    Description = "Group 'All IT Staff' contains privileged sub-groups (IT Operations, DevOps Engineers), creating indirect privilege escalation paths."
    AffectedEntity = $sampleGroups[38].Id
    AffectedEntityType = "Group"
    AffectedEntityName = $sampleGroups[38].DisplayName
    EscalationPath = @("Join parent group", "Inherit nested group memberships", "Access privileged resources")
}

$escalationRisks += [PSCustomObject]@{
    Id = [Guid]::NewGuid().ToString()
    RiskType = "NestedGroupEscalation"
    Severity = "Critical"
    Title = "Nested Role-Assignable Group: Privileged IT Admins"
    Description = "Group 'Privileged IT Admins' contains 'Application Administrators' group, creating nested privilege escalation."
    AffectedEntity = $sampleGroups[39].Id
    AffectedEntityType = "Group"
    AffectedEntityName = $sampleGroups[39].DisplayName
    EscalationPath = @("Join parent group", "Inherit Application Administrator role", "Create malicious apps", "Escalate to Global Admin")
}

# Application administrator escalation
$escalationRisks += [PSCustomObject]@{
    Id = [Guid]::NewGuid().ToString()
    RiskType = "ApplicationAdministratorEscalation"
    Severity = "Critical"
    Title = "Application Administrator Can Create Apps with Graph Permissions"
    Description = "Members of 'Application Administrators' can create apps with dangerous Graph permissions and escalate to Global Admin."
    AffectedEntity = $sampleGroups[4].Id
    AffectedEntityType = "Group"
    AffectedEntityName = $sampleGroups[4].DisplayName
    EscalationPath = @("Create new application", "Grant Application.ReadWrite.All permission", "Create app with credentials", "Use app to modify directory")
}

# Cloud Application Administrator escalation
$escalationRisks += [PSCustomObject]@{
    Id = [Guid]::NewGuid().ToString()
    RiskType = "CloudApplicationAdministratorEscalation"
    Severity = "Critical"
    Title = "Cloud Application Administrator Can Modify Service Principals"
    Description = "Members of 'Cloud Application Administrators' can modify service principal permissions, adding dangerous Graph permissions."
    AffectedEntity = $sampleGroups[5].Id
    AffectedEntityType = "Group"
    AffectedEntityName = $sampleGroups[5].DisplayName
    EscalationPath = @("Modify existing service principal", "Add RoleManagement.ReadWrite.Directory permission", "Use SP to assign roles", "Escalate privileges")
}

# PIM concentration risk
$escalationRisks += [PSCustomObject]@{
    Id = [Guid]::NewGuid().ToString()
    RiskType = "PIMConcentrationRisk"
    Severity = "Medium"
    Title = "Multiple Users Eligible for Global Administrator"
    Description = "40+ users have PIM-eligible assignments to privileged roles, increasing attack surface."
    AffectedEntity = "PIM"
    AffectedEntityType = "PIM"
    AffectedEntityName = "Privileged Identity Management"
    EscalationPath = @("Compromise eligible user", "Activate PIM role", "Access privileged resources")
}

# External user in privileged group
$escalationRisks += [PSCustomObject]@{
    Id = [Guid]::NewGuid().ToString()
    RiskType = "ExternalUserPrivilegedAccess"
    Severity = "Critical"
    Title = "Guest Users in Privileged Groups"
    Description = "External/guest users have been granted access to groups with privileged permissions."
    AffectedEntity = $sampleGroups[26].Id
    AffectedEntityType = "Group"
    AffectedEntityName = $sampleGroups[26].DisplayName
    EscalationPath = @("Compromise guest account", "Access privileged group resources", "Lateral movement")
}

# Helpdesk password reset escalation
$escalationRisks += [PSCustomObject]@{
    Id = [Guid]::NewGuid().ToString()
    RiskType = "HelpdeskPasswordResetEscalation"
    Severity = "High"
    Title = "Helpdesk Can Reset Passwords of Privileged Users"
    Description = "Helpdesk administrators can reset passwords, potentially targeting privileged accounts."
    AffectedEntity = $sampleGroups[23].Id
    AffectedEntityType = "Group"
    AffectedEntityName = $sampleGroups[23].DisplayName
    EscalationPath = @("Reset privileged user password", "Authenticate as privileged user", "Access privileged resources")
}

# Service principal with Entra role (double privilege)
for ($i = 13; $i -lt 20; $i++) {
    $sp = $sampleServicePrincipals[$i]
    $spRoles = $roleAssignments | Where-Object { $_.MemberId -eq $sp.Id }
    if ($spRoles.Count -gt 0 -and $sp.GrantedApplicationPermissions.Count -gt 0) {
        $roleName = $spRoles[0].RoleName
        $permissions = ($sp.GrantedApplicationPermissions | ForEach-Object { $_.AppRoleValue }) -join ", "
        $escalationRisks += [PSCustomObject]@{
            Id = [Guid]::NewGuid().ToString()
            RiskType = "ServicePrincipalDoublePrivilege"
            Severity = "Critical"
            Title = "Service Principal with Role AND Graph Permissions: $($sp.DisplayName)"
            Description = "SP has both Entra role ($roleName) and dangerous Graph permissions ($permissions). Double escalation path."
            AffectedEntity = $sp.Id
            AffectedEntityType = "ServicePrincipal"
            AffectedEntityName = $sp.DisplayName
            EscalationPath = @("Compromise SP credentials", "Use role + Graph permissions", "Full tenant compromise")
        }
    }
}

# App registration ownership and identity risks
if ($appOwners.Count -gt 0) {
    $permissionLookup = @{}
    foreach ($perm in $dangerousPermissions) {
        if (-not $permissionLookup.ContainsKey($perm.Id)) {
            $permissionLookup[$perm.Id] = $perm.Name
        }
    }

    $dangerousApps = $sampleApps | Where-Object { $_.ApiPermissions -and $_.ApiPermissions.Count -gt 0 }
    $highRiskApps = $dangerousApps | Select-Object -First 8

    foreach ($app in $highRiskApps) {
        if (-not $appOwners.ContainsKey($app.Id)) { continue }
        $owners = $appOwners[$app.Id]
        if (-not $owners -or $owners.Count -lt 1) { continue }

        $permissionNames = @()
        foreach ($apiPermission in $app.ApiPermissions) {
            foreach ($access in $apiPermission.ResourceAccess) {
                if ($permissionLookup.ContainsKey($access.Id)) {
                    $permissionNames += $permissionLookup[$access.Id]
                }
            }
        }
        $permissionNames = ($permissionNames | Select-Object -Unique) -join ", "
        if ([string]::IsNullOrWhiteSpace($permissionNames)) {
            $permissionNames = "Application.ReadWrite.All"
        }

        $sampleOwners = ($owners | Select-Object -First 3 | ForEach-Object { $_.displayName }) -join ", "

        $escalationRisks += [PSCustomObject]@{
            Id = [Guid]::NewGuid().ToString()
            RiskType = "AppRegistrationOwnership"
            Severity = if ($owners.Count -ge 4) { "Critical" } else { "High" }
            Title = "Privileged App Registration Owners: $($app.DisplayName)"
            Description = "App registration '$($app.DisplayName)' has $($owners.Count) owners ($sampleOwners) and permissions: $permissionNames. Owners can mint new secrets and abuse Graph scopes."
            AffectedEntity = $app.Id
            AffectedEntityType = "AppRegistration"
            AffectedEntityName = $app.DisplayName
            OwnerCount = $owners.Count
            EscalationPath = @(
                "Target app owner credentials",
                "Create new client secret/certificate",
                "Invoke Graph with $permissionNames",
                "Modify privileged resources"
            )
        }
    }

    $ownerDangerousAppMap = @{}
    foreach ($app in $dangerousApps) {
        if (-not $appOwners.ContainsKey($app.Id)) { continue }
        foreach ($owner in $appOwners[$app.Id]) {
            if (-not $ownerDangerousAppMap.ContainsKey($owner.id)) {
                $ownerDangerousAppMap[$owner.id] = [PSCustomObject]@{
                    Owner = $owner
                    AppNames = @($app.DisplayName)
                }
            }
            else {
                $ownerDangerousAppMap[$owner.id].AppNames += $app.DisplayName
            }
        }
    }

    $identityAppRisks = $ownerDangerousAppMap.Values | ForEach-Object {
        $uniqueApps = $_.AppNames | Select-Object -Unique
        [PSCustomObject]@{
            Owner = $_.Owner
            UniqueAppNames = $uniqueApps
            Count = $uniqueApps.Count
        }
    } | Where-Object { $_.Count -gt 2 } | Sort-Object -Property Count -Descending | Select-Object -First 5

    foreach ($riskOwner in $identityAppRisks) {
        $appList = ($riskOwner.UniqueAppNames | Select-Object -First 4) -join ", "
        $escalationRisks += [PSCustomObject]@{
            Id = [Guid]::NewGuid().ToString()
            RiskType = "IdentityAppOwnershipEscalation"
            Severity = "Critical"
            Title = "Identity owns $($riskOwner.Count) privileged apps: $($riskOwner.Owner.displayName)"
            Description = "User '$($riskOwner.Owner.displayName)' is an owner on $($riskOwner.Count) app registrations with Graph permissions (examples: $appList). Compromise enables direct identity-to-app privilege escalation."
            AffectedEntity = $riskOwner.Owner.id
            AffectedEntityType = "User"
            AffectedEntityName = $riskOwner.Owner.displayName
            EscalationPath = @(
                "Compromise privileged identity",
                "Update app credentials across owned registrations",
                "Use app permissions to grant roles",
                "Achieve tenant-wide access"
            )
        }
    }
}

Write-Host "`nDataset Summary:" -ForegroundColor Cyan
Write-Host "  Users:               $($sampleUsers.Count)" -ForegroundColor White
Write-Host "  Groups:              $($sampleGroups.Count)" -ForegroundColor White
Write-Host "  Service Principals:  $($sampleServicePrincipals.Count)" -ForegroundColor White
Write-Host "  Applications:        $($sampleApps.Count)" -ForegroundColor White
Write-Host "  Role Assignments:    $($roleAssignments.Count)" -ForegroundColor White
Write-Host "  PIM Assignments:     $($pimAssignments.Count)" -ForegroundColor White
Write-Host "  Group Memberships:   $(($groupMemberships.Values | ForEach-Object { $_.Count } | Measure-Object -Sum).Sum)" -ForegroundColor White
Write-Host "  Escalation Risks:    $($escalationRisks.Count)" -ForegroundColor White

# Build the graph data structure
Write-Host "`nBuilding graph data structure..." -ForegroundColor Yellow
$graphData = New-ScEntraGraphData `
    -Users $sampleUsers `
    -Groups $sampleGroups `
    -ServicePrincipals $sampleServicePrincipals `
    -AppRegistrations $sampleApps `
    -RoleAssignments $roleAssignments `
    -PIMAssignments $pimAssignments `
    -SPAppRoleAssignments @{} `
    -AppOwners $appOwners `
    -GroupMemberships $groupMemberships

Write-Host "Calling Export-ScEntraReport..." -ForegroundColor Yellow
Export-ScEntraReport `
    -Users $sampleUsers `
    -Groups $sampleGroups `
    -ServicePrincipals $sampleServicePrincipals `
    -AppRegistrations $sampleApps `
    -RoleAssignments $roleAssignments `
    -PIMAssignments $pimAssignments `
    -EscalationRisks $escalationRisks `
    -GraphData $graphData `
    -GroupMemberships $groupMemberships `
    -OutputPath "./ScEntra-Large-Sample-Report.html"

Write-Host "`n✓ Large sample report generated: ScEntra-Large-Sample-Report.html" -ForegroundColor Green
Write-Host "Open it in a web browser to see the comprehensive visualization" -ForegroundColor Cyan
Write-Host "./ScEntra-Large-Sample-Report.html" -ForegroundColor White
