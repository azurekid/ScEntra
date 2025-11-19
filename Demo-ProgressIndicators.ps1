#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Demonstrates the progress indicators added to ScEntra module

.DESCRIPTION
    This script simulates the progress indicators that will be shown when 
    running ScEntra functions against a real Entra ID tenant.
#>

Write-Host @"

╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   Progress Indicator Demonstration for ScEntra           ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan

Write-Host "This demonstration shows the progress indicators that have been added to ScEntra." -ForegroundColor Yellow
Write-Host "When running against a real Entra ID tenant, you will see these progress bars:" -ForegroundColor Yellow
Write-Host ""

# Simulate Get-ScEntraUsers with pagination
Write-Host "[1] Retrieving Users" -ForegroundColor Cyan
Write-Host "=" * 60
for ($i = 1; $i -le 5; $i++) {
    Write-Progress -Activity "Retrieving users from Entra ID" -Status "Fetching page $i (retrieved $($i * 100) items so far)" -PercentComplete ($i * 20) -Id 1
    Start-Sleep -Milliseconds 300
}
Write-Progress -Activity "Retrieving users from Entra ID" -Completed -Id 1
Write-Host "Retrieved 500 users" -ForegroundColor Green

Start-Sleep -Milliseconds 500

# Simulate Get-ScEntraGroups with member counts
Write-Host "`n[2] Retrieving Groups and Member Counts" -ForegroundColor Cyan
Write-Host "=" * 60
$groups = @("Finance Team", "Engineering", "HR Department", "Security Admins", "Global Readers")
for ($i = 0; $i -lt $groups.Count; $i++) {
    $percentComplete = [math]::Round((($i + 1) / $groups.Count) * 100)
    Write-Progress -Activity "Fetching group member counts" -Status "Processing group $($i + 1) of $($groups.Count) - $($groups[$i])" -PercentComplete $percentComplete -Id 2
    Start-Sleep -Milliseconds 400
}
Write-Progress -Activity "Fetching group member counts" -Completed -Id 2
Write-Host "Retrieved 45 groups with member counts" -ForegroundColor Green

Start-Sleep -Milliseconds 500

# Simulate Get-ScEntraRoleAssignments
Write-Host "`n[3] Enumerating Role Assignments" -ForegroundColor Cyan
Write-Host "=" * 60
$roles = @("Global Administrator", "User Administrator", "Security Reader", "Application Administrator")
for ($i = 0; $i -lt $roles.Count; $i++) {
    $percentComplete = [math]::Round((($i + 1) / $roles.Count) * 100)
    Write-Progress -Activity "Enumerating role assignments" -Status "Processing role $($i + 1) of $($roles.Count) - $($roles[$i])" -PercentComplete $percentComplete -Id 3
    Start-Sleep -Milliseconds 400
}
Write-Progress -Activity "Enumerating role assignments" -Completed -Id 3
Write-Host "Retrieved 28 direct role assignments across 12 roles" -ForegroundColor Green

Start-Sleep -Milliseconds 500

# Simulate Get-ScEntraPIMAssignments
Write-Host "`n[4] Checking PIM Assignments" -ForegroundColor Cyan
Write-Host "=" * 60
Write-Progress -Activity "Retrieving PIM assignments" -Status "Fetching eligible role assignments" -PercentComplete 25 -Id 4
Start-Sleep -Milliseconds 500
Write-Progress -Activity "Retrieving PIM assignments" -Status "Fetching active role assignments" -PercentComplete 75 -Id 4
Start-Sleep -Milliseconds 500
Write-Progress -Activity "Retrieving PIM assignments" -Completed -Id 4
Write-Host "Retrieved 15 PIM assignments (10 eligible, 5 active)" -ForegroundColor Green

Start-Sleep -Milliseconds 500

# Simulate Get-ScEntraEscalationPaths
Write-Host "`n[5] Analyzing Escalation Paths" -ForegroundColor Cyan
Write-Host "=" * 60
Write-Host "Found 5 role-enabled groups" -ForegroundColor Yellow

# Analyze role-enabled groups
for ($i = 1; $i -le 3; $i++) {
    $percentComplete = [math]::Round(($i / 3) * 100)
    Write-Progress -Activity "Analyzing escalation paths" -Status "Analyzing role-enabled group $i of 3" -PercentComplete $percentComplete -Id 5
    Start-Sleep -Milliseconds 400
}

# Analyze nested groups
for ($i = 1; $i -le 4; $i++) {
    $percentComplete = [math]::Round(($i / 4) * 100)
    Write-Progress -Activity "Analyzing nested group memberships" -Status "Processing group $i of 4" -PercentComplete $percentComplete -Id 6
    Start-Sleep -Milliseconds 300
}
Write-Progress -Activity "Analyzing nested group memberships" -Completed -Id 6

# Analyze service principals
for ($i = 10; $i -le 30; $i += 10) {
    $percentComplete = [math]::Round(($i / 30) * 100)
    Write-Progress -Activity "Analyzing service principal ownership" -Status "Processing service principal $i of 30" -PercentComplete $percentComplete -Id 7
    Start-Sleep -Milliseconds 300
}
Write-Progress -Activity "Analyzing service principal ownership" -Completed -Id 7

# Analyze app registrations
for ($i = 10; $i -le 25; $i += 10) {
    $percentComplete = [math]::Round(($i / 25) * 100)
    Write-Progress -Activity "Analyzing app registration ownership" -Status "Processing app registration $i of 25" -PercentComplete $percentComplete -Id 8
    Start-Sleep -Milliseconds 300
}
Write-Progress -Activity "Analyzing app registration ownership" -Completed -Id 8

# Analyze PIM patterns
Write-Progress -Activity "Analyzing PIM assignment patterns" -Status "Grouping PIM assignments by principal" -PercentComplete 50 -Id 9
Start-Sleep -Milliseconds 400
Write-Progress -Activity "Analyzing PIM assignment patterns" -Completed -Id 9

Write-Progress -Activity "Analyzing escalation paths" -Completed -Id 5

Write-Host "Identified 8 potential escalation risks" -ForegroundColor Yellow

Write-Host "`n" + ("=" * 60) -ForegroundColor Green
Write-Host "✓ Progress Indicators Demonstration Complete!" -ForegroundColor Green
Write-Host ("=" * 60) -ForegroundColor Green

Write-Host "`nKey Features Added:" -ForegroundColor Cyan
Write-Host "  • Real-time pagination progress showing page numbers and item counts" -ForegroundColor White
Write-Host "  • Individual group processing with group names displayed" -ForegroundColor White
Write-Host "  • Role assignment enumeration with role names" -ForegroundColor White
Write-Host "  • Separate progress bars for each analysis phase (using unique IDs)" -ForegroundColor White
Write-Host "  • All progress bars properly complete when done" -ForegroundColor White

Write-Host "`nImpact:" -ForegroundColor Cyan
Write-Host "  Users can now see exactly what the module is doing during long operations" -ForegroundColor White
Write-Host "  Progress percentages help estimate remaining time" -ForegroundColor White
Write-Host "  Clear status messages provide insight into current processing step" -ForegroundColor White

Write-Host "`nTo see these in action with real data, run:" -ForegroundColor Yellow
Write-Host "  Import-Module ./ScEntra.psd1" -ForegroundColor White
Write-Host "  Invoke-ScEntraAnalysis" -ForegroundColor White
Write-Host ""
