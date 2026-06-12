# Test script to verify graph data generation
Import-Module ./ScEntra.psd1 -Force

# Test with empty input
$result = Get-ScEntraEscalationPaths -Users @() -Groups @() -RoleAssignments @() -PIMAssignments @() -ServicePrincipals @() -AppRegistrations @() -AzureRoleAssignments @() -AzureEligibleRoleAssignments @() -IncludeAllUsersInGraph:$false

# Check if graph data was generated
if ($result.GraphData) {
    Write-Host "GraphData generated successfully!" -ForegroundColor Green
    Write-Host "Nodes count: $($result.GraphData.nodes.Count)" -ForegroundColor Cyan
    Write-Host "Edges count: $($result.GraphData.edges.Count)" -ForegroundColor Cyan
    
    # List the nodes
    Write-Host "Nodes:" -ForegroundColor Yellow
    foreach ($node in $result.GraphData.nodes) {
        Write-Host "  - $($node.label) ($($node.type))" -ForegroundColor White
    }
} else {
    Write-Host "GraphData is null!" -ForegroundColor Red
}