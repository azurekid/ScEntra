#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Basic tests for ScEntra module

.DESCRIPTION
    Tests module loading and basic function availability
#>

Write-Host "ScEntra Module Tests" -ForegroundColor Cyan
Write-Host "=" * 60

# Test 1: Module loads successfully
Write-Host "`nTest 1: Module Loading" -ForegroundColor Yellow
try {
    Import-Module ./ScEntra.psd1 -Force -ErrorAction Stop
    Write-Host "  ✓ Module loaded successfully" -ForegroundColor Green
    $test1 = $true
}
catch {
    Write-Host "  ✗ Failed to load module: $_" -ForegroundColor Red
    $test1 = $false
}

# Test 2: All expected functions are exported
Write-Host "`nTest 2: Function Export" -ForegroundColor Yellow
$expectedFunctions = @(
    'Invoke-ScEntraAnalysis'
    'Get-ScEntraUsers'
    'Get-ScEntraGroups'
    'Get-ScEntraServicePrincipals'
    'Get-ScEntraAppRegistrations'
    'Get-ScEntraRoleAssignments'
    'Get-ScEntraPIMAssignments'
    'Get-ScEntraEscalationPaths'
    'Export-ScEntraReport'
)

$exportedFunctions = Get-Command -Module ScEntra | Select-Object -ExpandProperty Name
$test2 = $true

foreach ($func in $expectedFunctions) {
    if ($exportedFunctions -contains $func) {
        Write-Host "  ✓ $func" -ForegroundColor Green
    }
    else {
        Write-Host "  ✗ $func (missing)" -ForegroundColor Red
        $test2 = $false
    }
}

# Test 3: Module manifest is valid
Write-Host "`nTest 3: Module Manifest" -ForegroundColor Yellow
try {
    $manifest = Test-ModuleManifest ./ScEntra.psd1 -ErrorAction Stop
    Write-Host "  ✓ Module manifest is valid" -ForegroundColor Green
    Write-Host "    Version: $($manifest.Version)" -ForegroundColor Gray
    Write-Host "    Author: $($manifest.Author)" -ForegroundColor Gray
    $test3 = $true
}
catch {
    Write-Host "  ✗ Module manifest validation failed: $_" -ForegroundColor Red
    $test3 = $false
}

# Test 4: Help content exists for main function
Write-Host "`nTest 4: Help Documentation" -ForegroundColor Yellow
try {
    $help = Get-Help Invoke-ScEntraAnalysis -ErrorAction Stop
    if ($help.Synopsis -and $help.Description) {
        Write-Host "  ✓ Help documentation exists" -ForegroundColor Green
        Write-Host "    Synopsis: $($help.Synopsis)" -ForegroundColor Gray
    }
    else {
        Write-Host "  ✗ Help documentation incomplete" -ForegroundColor Red
        $test4 = $false
    }
    $test4 = $true
}
catch {
    Write-Host "  ✗ Failed to retrieve help: $_" -ForegroundColor Red
    $test4 = $false
}

# Test 5: Required modules are specified
Write-Host "`nTest 5: Required Modules" -ForegroundColor Yellow
$requiredModules = $manifest.RequiredModules
$expectedModules = @(
    'Microsoft.Graph.Authentication'
    'Microsoft.Graph.Users'
    'Microsoft.Graph.Groups'
    'Microsoft.Graph.Applications'
    'Microsoft.Graph.Identity.DirectoryManagement'
    'Microsoft.Graph.Identity.Governance'
)

$test5 = $true
foreach ($module in $expectedModules) {
    $found = $requiredModules | Where-Object { $_.ModuleName -eq $module }
    if ($found) {
        Write-Host "  ✓ $module" -ForegroundColor Green
    }
    else {
        Write-Host "  ✗ $module (missing)" -ForegroundColor Red
        $test5 = $false
    }
}

# Test 6: Module file has no syntax errors
Write-Host "`nTest 6: Syntax Validation" -ForegroundColor Yellow
try {
    $errors = $null
    $tokens = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseFile(
        "./ScEntra.psm1",
        [ref]$tokens,
        [ref]$errors
    )
    
    if ($errors -and $errors.Count -gt 0) {
        Write-Host "  ✗ Syntax errors found:" -ForegroundColor Red
        foreach ($error in $errors) {
            Write-Host "    Line $($error.Extent.StartLineNumber): $($error.Message)" -ForegroundColor Red
        }
        $test6 = $false
    }
    else {
        Write-Host "  ✓ No syntax errors found" -ForegroundColor Green
        $test6 = $true
    }
}
catch {
    Write-Host "  ✗ Syntax validation failed: $_" -ForegroundColor Red
    $test6 = $false
}

# Summary
Write-Host "`n" + ("=" * 60)
Write-Host "Test Summary" -ForegroundColor Cyan
Write-Host ("=" * 60)

$tests = @{
    "Module Loading" = $test1
    "Function Export" = $test2
    "Module Manifest" = $test3
    "Help Documentation" = $test4
    "Required Modules" = $test5
    "Syntax Validation" = $test6
}

$passed = 0
$failed = 0

foreach ($test in $tests.GetEnumerator()) {
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
    Write-Host "`n🎉 All tests passed!" -ForegroundColor Green
    exit 0
}
else {
    Write-Host "`n⚠️ Some tests failed" -ForegroundColor Yellow
    exit 1
}
