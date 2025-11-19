#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Tests for progress indicator functionality in ScEntra module

.DESCRIPTION
    Validates that progress indicators are properly integrated into long-running functions
#>

Write-Host "ScEntra Progress Indicator Tests" -ForegroundColor Cyan
Write-Host "=" * 60

# Import the module
Import-Module ./ScEntra.psd1 -Force

# Test 1: Verify Get-AllGraphItems has ProgressActivity parameter
Write-Host "`nTest 1: Get-AllGraphItems Progress Support" -ForegroundColor Yellow
try {
    # Get-AllGraphItems is a private helper function, so check the source code instead
    $moduleContent = Get-Content ./ScEntra.psm1 -Raw
    $functionMatch = [regex]::Match($moduleContent, 'function Get-AllGraphItems\s*{[\s\S]*?(?=\nfunction|\n#endregion|\z)')
    
    if ($functionMatch.Success) {
        $functionContent = $functionMatch.Value
        $hasProgressParam = $functionContent -match '\[Parameter.*\]\s*\[string\]\$ProgressActivity'
        
        if ($hasProgressParam) {
            Write-Host "  ✓ Get-AllGraphItems has ProgressActivity parameter" -ForegroundColor Green
            $test1 = $true
        }
        else {
            Write-Host "  ✗ Get-AllGraphItems missing ProgressActivity parameter" -ForegroundColor Red
            $test1 = $false
        }
    }
    else {
        Write-Host "  ✗ Could not find Get-AllGraphItems function" -ForegroundColor Red
        $test1 = $false
    }
}
catch {
    Write-Host "  ✗ Failed to verify function: $_" -ForegroundColor Red
    $test1 = $false
}

# Test 2: Check for Write-Progress calls in the module
Write-Host "`nTest 2: Progress Indicators in Module Code" -ForegroundColor Yellow
try {
    $moduleContent = Get-Content ./ScEntra.psm1 -Raw
    $progressCalls = ([regex]::Matches($moduleContent, 'Write-Progress')).Count
    
    if ($progressCalls -ge 10) {
        Write-Host "  ✓ Found $progressCalls Write-Progress calls in module" -ForegroundColor Green
        $test2 = $true
    }
    else {
        Write-Host "  ✗ Only found $progressCalls Write-Progress calls (expected at least 10)" -ForegroundColor Red
        $test2 = $false
    }
}
catch {
    Write-Host "  ✗ Failed to analyze module content: $_" -ForegroundColor Red
    $test2 = $false
}

# Test 3: Verify progress indicators use unique IDs
Write-Host "`nTest 3: Progress Bar ID Uniqueness" -ForegroundColor Yellow
try {
    $moduleContent = Get-Content ./ScEntra.psm1 -Raw
    
    # Extract all progress IDs
    $progressMatches = [regex]::Matches($moduleContent, 'Write-Progress.*-Id\s+(\d+)')
    $progressIds = $progressMatches | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique
    
    if ($progressIds.Count -ge 5) {
        Write-Host "  ✓ Found $($progressIds.Count) unique progress bar IDs" -ForegroundColor Green
        Write-Host "    IDs used: $($progressIds -join ', ')" -ForegroundColor Gray
        $test3 = $true
    }
    else {
        Write-Host "  ✗ Only found $($progressIds.Count) unique progress bar IDs" -ForegroundColor Red
        $test3 = $false
    }
}
catch {
    Write-Host "  ✗ Failed to analyze progress IDs: $_" -ForegroundColor Red
    $test3 = $false
}

# Test 4: Verify progress bars are properly completed
Write-Host "`nTest 4: Progress Bar Completion" -ForegroundColor Yellow
try {
    $moduleContent = Get-Content ./ScEntra.psm1 -Raw
    
    # Count progress starts and completions
    $progressStarts = ([regex]::Matches($moduleContent, 'Write-Progress\s+-Activity')).Count
    $progressCompletes = ([regex]::Matches($moduleContent, 'Write-Progress.*-Completed')).Count
    
    if ($progressCompletes -ge 8) {
        Write-Host "  ✓ Found $progressCompletes progress completions" -ForegroundColor Green
        Write-Host "    Progress starts: $progressStarts, Completions: $progressCompletes" -ForegroundColor Gray
        $test4 = $true
    }
    else {
        Write-Host "  ✗ Only found $progressCompletes progress completions (expected at least 8)" -ForegroundColor Red
        $test4 = $false
    }
}
catch {
    Write-Host "  ✗ Failed to analyze progress completions: $_" -ForegroundColor Red
    $test4 = $false
}

# Test 5: Verify key functions have progress support
Write-Host "`nTest 5: Progress Support in Key Functions" -ForegroundColor Yellow
$functionsToCheck = @(
    @{Name='Get-ScEntraGroups'; Expected='Fetching group member counts'}
    @{Name='Get-ScEntraRoleAssignments'; Expected='Enumerating role assignments'}
    @{Name='Get-ScEntraEscalationPaths'; Expected='Analyzing escalation paths'}
    @{Name='Get-ScEntraPIMAssignments'; Expected='Retrieving PIM assignments'}
)

$test5 = $true
$moduleContent = Get-Content ./ScEntra.psm1 -Raw

foreach ($func in $functionsToCheck) {
    if ($moduleContent -match $func.Expected) {
        Write-Host "  ✓ $($func.Name): Found progress indicator" -ForegroundColor Green
    }
    else {
        Write-Host "  ✗ $($func.Name): Missing expected progress indicator" -ForegroundColor Red
        $test5 = $false
    }
}

# Test 6: Verify pagination progress in Get-AllGraphItems
Write-Host "`nTest 6: Pagination Progress Tracking" -ForegroundColor Yellow
try {
    $moduleContent = Get-Content ./ScEntra.psm1 -Raw
    
    # Check for page count tracking
    $hasPageCount = $moduleContent -match '\$pageCount\+\+'
    $hasPageStatus = $moduleContent -match 'Fetching page.*pageCount'
    
    if ($hasPageCount -and $hasPageStatus) {
        Write-Host "  ✓ Pagination progress tracking implemented" -ForegroundColor Green
        $test6 = $true
    }
    else {
        Write-Host "  ✗ Pagination progress tracking not found" -ForegroundColor Red
        $test6 = $false
    }
}
catch {
    Write-Host "  ✗ Failed to verify pagination tracking: $_" -ForegroundColor Red
    $test6 = $false
}

# Summary
Write-Host "`n" + ("=" * 60)
Write-Host "Test Summary" -ForegroundColor Cyan
Write-Host ("=" * 60)

$tests = @{
    "Get-AllGraphItems Progress Support" = $test1
    "Progress Indicators in Module Code" = $test2
    "Progress Bar ID Uniqueness" = $test3
    "Progress Bar Completion" = $test4
    "Progress Support in Key Functions" = $test5
    "Pagination Progress Tracking" = $test6
}

$passed = 0
$failed = 0

foreach ($test in $tests.GetEnumerator() | Sort-Object Name) {
    if ($test.Value) {
        Write-Host "  ✓ $($test.Key)" -ForegroundColor Green
        $passed++
    }
    else {
        Write-Host "  ✗ $($test.Key)" -ForegroundColor Red
        $failed++
    }
}

Write-Host "`nResults: $passed passed, $failed failed" -ForegroundColor $(if ($failed -eq 0) { "Green" } else { "Yellow" })

if ($failed -eq 0) {
    Write-Host "`n🎉 All progress indicator tests passed!" -ForegroundColor Green
    Write-Host "`nNote: These tests verify that progress indicators are integrated into the code." -ForegroundColor Cyan
    Write-Host "To see progress indicators in action, run the module against an actual Entra ID tenant." -ForegroundColor Cyan
    exit 0
}
else {
    Write-Host "`n⚠️ Some progress indicator tests failed" -ForegroundColor Yellow
    exit 1
}
