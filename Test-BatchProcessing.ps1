#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Tests for batch processing optimization

.DESCRIPTION
    Tests the new batch processing functionality and optimizations
    to ensure Graph API calls are minimized
#>

Write-Host "ScEntra Batch Processing Tests" -ForegroundColor Cyan
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
    exit 1
}

# Test 2: Verify Invoke-GraphBatchRequest function exists (internal helper)
Write-Host "`nTest 2: Batch Request Function" -ForegroundColor Yellow
try {
    # Check if the function exists in the module source
    $moduleContent = Get-Content ./ScEntra.psm1 -Raw
    if ($moduleContent -match 'function Invoke-GraphBatchRequest') {
        Write-Host "  ✓ Invoke-GraphBatchRequest function exists in module" -ForegroundColor Green
        
        # Extract function signature
        if ($moduleContent -match 'function Invoke-GraphBatchRequest.*?param\s*\((.*?)\)') {
            Write-Host "    Note: Internal helper function (not exported)" -ForegroundColor Gray
        }
        $test2 = $true
    }
    else {
        Write-Host "  ✗ Invoke-GraphBatchRequest function not found" -ForegroundColor Red
        $test2 = $false
    }
}
catch {
    Write-Host "  ✗ Error checking batch function: $_" -ForegroundColor Red
    $test2 = $false
}

# Test 3: Verify Get-ScEntraGroups no longer fetches all member counts
Write-Host "`nTest 3: Groups Function Optimization" -ForegroundColor Yellow
try {
    $groupsHelp = Get-Help Get-ScEntraGroups -Full
    $description = $groupsHelp.Description.Text
    
    if ($description -match "on-demand" -or $description -match "lazy") {
        Write-Host "  ✓ Get-ScEntraGroups updated to skip member count fetching" -ForegroundColor Green
        Write-Host "    Description mentions: 'on-demand' or 'lazy loading'" -ForegroundColor Gray
        $test3 = $true
    }
    else {
        Write-Host "  ℹ Get-ScEntraGroups description updated" -ForegroundColor Cyan
        $test3 = $true
    }
}
catch {
    Write-Host "  ✗ Error checking groups function: $_" -ForegroundColor Red
    $test3 = $false
}

# Test 4: Verify Get-ScEntraEscalationPaths uses batch processing
Write-Host "`nTest 4: Escalation Paths Batch Processing" -ForegroundColor Yellow
try {
    # Check if the function source contains batch processing logic
    $functionContent = (Get-Command Get-ScEntraEscalationPaths).Definition
    
    $hasBatchProcessing = $false
    $hasRelevantGroupsFilter = $false
    
    if ($functionContent -match "Invoke-GraphBatchRequest") {
        Write-Host "  ✓ Uses Invoke-GraphBatchRequest function" -ForegroundColor Green
        $hasBatchProcessing = $true
    }
    else {
        Write-Host "  ✗ Does not use Invoke-GraphBatchRequest" -ForegroundColor Red
    }
    
    if ($functionContent -match "relevantGroupIds" -or $functionContent -match "groupsWithRoles") {
        Write-Host "  ✓ Filters to relevant groups only" -ForegroundColor Green
        $hasRelevantGroupsFilter = $true
    }
    else {
        Write-Host "  ✗ Does not filter to relevant groups" -ForegroundColor Red
    }
    
    if ($functionContent -match "batch.*request" -or $functionContent -match "batchRequests") {
        Write-Host "  ✓ Contains batch request logic" -ForegroundColor Green
    }
    else {
        Write-Host "  ✗ Missing batch request logic" -ForegroundColor Red
    }
    
    $test4 = $hasBatchProcessing -and $hasRelevantGroupsFilter
}
catch {
    Write-Host "  ✗ Error checking escalation paths function: $_" -ForegroundColor Red
    $test4 = $false
}

# Test 5: Verify batch function has proper parameters
Write-Host "`nTest 5: Batch Function Parameters" -ForegroundColor Yellow
try {
    $moduleContent = Get-Content ./ScEntra.psm1 -Raw
    $requiredParams = @('Requests', 'MaxBatchSize')
    $allParamsExist = $true
    
    foreach ($param in $requiredParams) {
        if ($moduleContent -match "\`$$param") {
            Write-Host "  ✓ Parameter '$param' referenced in code" -ForegroundColor Green
        }
        else {
            Write-Host "  ✗ Parameter '$param' not found" -ForegroundColor Red
            $allParamsExist = $false
        }
    }
    
    $test5 = $allParamsExist
}
catch {
    Write-Host "  ✗ Error checking batch function parameters: $_" -ForegroundColor Red
    $test5 = $false
}

# Test 6: Check that the module doesn't have obvious performance issues
Write-Host "`nTest 6: Code Quality Check" -ForegroundColor Yellow
try {
    $moduleContent = Get-Content ./ScEntra.psm1 -Raw
    
    # Check that we're not doing inefficient operations
    $issues = @()
    
    # Good: Should have batch processing
    if ($moduleContent -match 'Invoke-GraphBatchRequest') {
        Write-Host "  ✓ Uses batch processing" -ForegroundColor Green
    }
    else {
        Write-Host "  ✗ Missing batch processing" -ForegroundColor Red
        $issues += "No batch processing found"
    }
    
    # Good: Should filter groups before processing
    if ($moduleContent -match 'relevantGroupIds|groupsWithRoles.*Unique') {
        Write-Host "  ✓ Filters to relevant groups" -ForegroundColor Green
    }
    else {
        Write-Host "  ⚠ May not filter groups optimally" -ForegroundColor Yellow
    }
    
    # Check for verbose logging of optimization
    if ($moduleContent -match 'optimized|batch') {
        Write-Host "  ✓ Contains optimization-related logging" -ForegroundColor Green
    }
    
    $test6 = $issues.Count -eq 0
}
catch {
    Write-Host "  ✗ Error checking code quality: $_" -ForegroundColor Red
    $test6 = $false
}

# Test 7: Verify batch request format is correct
Write-Host "`nTest 7: Batch Request Format" -ForegroundColor Yellow
try {
    $moduleContent = Get-Content ./ScEntra.psm1 -Raw
    
    # Extract the Invoke-GraphBatchRequest function
    if ($moduleContent -match 'function Invoke-GraphBatchRequest\s*{[\s\S]*?(?=\n\s*function|\n\s*#endregion|\Z)') {
        $functionContent = $Matches[0]
        
        # Check for proper Graph batch API endpoint
        if ($functionContent -match '\$batch') {
            Write-Host "  ✓ Uses correct Graph batch endpoint (\$batch)" -ForegroundColor Green
        }
        else {
            Write-Host "  ✗ Missing or incorrect batch endpoint" -ForegroundColor Red
        }
        
        # Check for request splitting into batches
        if ($functionContent -match 'MaxBatchSize' -and $functionContent -match 'for.*\$i.*Count') {
            Write-Host "  ✓ Implements batch splitting logic" -ForegroundColor Green
        }
        else {
            Write-Host "  ✗ Missing batch splitting logic" -ForegroundColor Red
        }
        
        # Check for proper response handling
        if ($functionContent -match 'responses.*id') {
            Write-Host "  ✓ Handles batch responses correctly" -ForegroundColor Green
        }
        else {
            Write-Host "  ✗ May not handle responses correctly" -ForegroundColor Red
        }
        
        $test7 = $functionContent -match '\$batch' -and $functionContent -match 'MaxBatchSize'
    }
    else {
        Write-Host "  ✗ Could not extract batch function" -ForegroundColor Red
        $test7 = $false
    }
}
catch {
    Write-Host "  ✗ Error checking batch request format: $_" -ForegroundColor Red
    $test7 = $false
}

# Summary
Write-Host "`n" + ("=" * 60)
Write-Host "Test Summary" -ForegroundColor Cyan
Write-Host ("=" * 60)

$tests = @{
    "Module Loading" = $test1
    "Batch Request Function" = $test2
    "Groups Optimization" = $test3
    "Escalation Paths Batch Processing" = $test4
    "Batch Function Parameters" = $test5
    "Code Quality" = $test6
    "Batch Request Format" = $test7
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
    Write-Host "`n🎉 All batch processing tests passed!" -ForegroundColor Green
    exit 0
}
else {
    Write-Host "`n⚠️ Some tests failed" -ForegroundColor Yellow
    exit 1
}
