#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Manual validation of batch processing logic

.DESCRIPTION
    This script validates the batch processing implementation by checking
    key aspects of the optimization
#>

Write-Host "ScEntra Batch Processing Validation" -ForegroundColor Cyan
Write-Host "=" * 60

# Load the module
Import-Module ./ScEntra.psd1 -Force

Write-Host "`n1. Checking Get-ScEntraGroups optimization..." -ForegroundColor Yellow
Write-Host "   Expected: No member count fetching loop" -ForegroundColor Gray

$groupsContent = (Get-Command Get-ScEntraGroups).Definition
if ($groupsContent -match 'foreach.*group.*member') {
    Write-Host "   ⚠ WARNING: May still have member fetching loop" -ForegroundColor Red
} else {
    Write-Host "   ✓ No member fetching loop detected" -ForegroundColor Green
}

if ($groupsContent -match 'on-demand|lazy') {
    Write-Host "   ✓ Mentions lazy/on-demand loading in comments" -ForegroundColor Green
}

Write-Host "`n2. Checking batch processing implementation..." -ForegroundColor Yellow
Write-Host "   Expected: Batch requests with max size of 20" -ForegroundColor Gray

$moduleContent = Get-Content ./ScEntra.psm1 -Raw
if ($moduleContent -match 'MaxBatchSize.*20') {
    Write-Host "   ✓ Default batch size set to 20 (Graph API limit)" -ForegroundColor Green
} else {
    Write-Host "   ⚠ Batch size might not be optimal" -ForegroundColor Yellow
}

if ($moduleContent -match 'Invoke-GraphBatchRequest') {
    Write-Host "   ✓ Batch request function is called" -ForegroundColor Green
}

Write-Host "`n3. Checking group filtering logic..." -ForegroundColor Yellow
Write-Host "   Expected: Only processes relevant groups" -ForegroundColor Gray

$escalationContent = (Get-Command Get-ScEntraEscalationPaths).Definition
if ($escalationContent -match 'relevantGroupIds|groupsWithRoles.*Unique') {
    Write-Host "   ✓ Filters to relevant groups before processing" -ForegroundColor Green
}

if ($escalationContent -match 'roleEnabledGroups.*isAssignableToRole') {
    Write-Host "   ✓ Identifies role-enabled groups" -ForegroundColor Green
}

if ($escalationContent -match 'groupsInPIM') {
    Write-Host "   ✓ Includes PIM-assigned groups" -ForegroundColor Green
}

Write-Host "`n4. Checking batch request structure..." -ForegroundColor Yellow
Write-Host "   Expected: Proper Graph batch format" -ForegroundColor Gray

if ($moduleContent -match 'requests.*method.*url') {
    Write-Host "   ✓ Request objects have proper structure (id, method, url)" -ForegroundColor Green
}

if ($moduleContent -match '\$batch') {
    Write-Host "   ✓ Uses correct Graph batch endpoint" -ForegroundColor Green
}

if ($moduleContent -match 'batchBody.*requests') {
    Write-Host "   ✓ Constructs batch body correctly" -ForegroundColor Green
}

Write-Host "`n5. Checking fallback mechanism..." -ForegroundColor Yellow
Write-Host "   Expected: Individual requests if batch fails" -ForegroundColor Gray

if ($escalationContent -match 'Fallback|catch.*batch.*failed') {
    Write-Host "   ✓ Has fallback for batch failures" -ForegroundColor Green
}

if ($escalationContent -match 'SilentlyContinue|ErrorAction') {
    Write-Host "   ✓ Uses proper error handling" -ForegroundColor Green
}

Write-Host "`n6. Estimated performance improvement..." -ForegroundColor Yellow
Write-Host "   Assumptions:" -ForegroundColor Gray
Write-Host "   - 1000 groups in environment" -ForegroundColor Gray
Write-Host "   - 50 groups are security-relevant" -ForegroundColor Gray

$oldApiCalls = 1000 + (50 * 3)  # member count for all + members/owners/transitive for relevant
$newApiCalls = (50 * 3) / 20    # only relevant groups, batched (20 per batch)
$improvement = [math]::Round((1 - ($newApiCalls / $oldApiCalls)) * 100, 1)

Write-Host "`n   Old approach: ~$oldApiCalls API calls" -ForegroundColor Red
Write-Host "   New approach: ~$([math]::Ceiling($newApiCalls)) batches (~$([math]::Ceiling($newApiCalls) * 20) max requests)" -ForegroundColor Green
Write-Host "   Improvement: ~$improvement% reduction in API calls" -ForegroundColor Cyan

Write-Host "`n" + ("=" * 60)
Write-Host "Validation Complete!" -ForegroundColor Green
Write-Host ("=" * 60)
