function Get-ScEntraReportStatistics {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)][array]$Users = @(),
        [Parameter(Mandatory = $false)][array]$Groups = @(),
        [Parameter(Mandatory = $false)][array]$ServicePrincipals = @(),
        [Parameter(Mandatory = $false)][array]$AppRegistrations = @(),
        [Parameter(Mandatory = $false)][array]$RoleAssignments = @(),
        [Parameter(Mandatory = $false)][array]$PIMAssignments = @(),
        [Parameter(Mandatory = $false)][array]$EscalationRisks = @()
    )

    return @{
        TotalUsers               = $Users.Count
        EnabledUsers             = ($Users | Where-Object { $_.accountEnabled -eq $true }).Count
        TotalGroups              = $Groups.Count
        RoleEnabledGroups        = ($Groups | Where-Object { $_.isAssignableToRole -eq $true }).Count
        PIMEnabledGroups         = ($Groups | Where-Object { $_.isPIMEnabled -eq $true }).Count
        SecurityGroups           = ($Groups | Where-Object { $_.securityEnabled -eq $true }).Count
        TotalServicePrincipals   = $ServicePrincipals.Count
        EnabledServicePrincipals = ($ServicePrincipals | Where-Object { $_.accountEnabled -eq $true }).Count
        TotalAppRegistrations    = $AppRegistrations.Count
        TotalRoleAssignments     = $RoleAssignments.Count
        TotalPIMAssignments      = $PIMAssignments.Count
        TotalEscalationRisks     = $EscalationRisks.Count
        HighSeverityRisks        = ($EscalationRisks | Where-Object { $_.Severity -eq 'High' }).Count
        MediumSeverityRisks      = ($EscalationRisks | Where-Object { $_.Severity -eq 'Medium' }).Count
    }
}

function Get-ScEntraRoleDistribution {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)][array]$RoleAssignments = @(),
        [int]$Top = 10
    )

    if (-not $RoleAssignments -or $RoleAssignments.Count -eq 0) {
        return @()
    }

    return $RoleAssignments |
    Group-Object -Property RoleName |
    Select-Object @{N = 'Role'; E = { $_.Name } }, Count |
    Sort-Object -Property Count -Descending |
    Select-Object -First $Top
}

function Get-ScEntraRiskDistribution {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $false)][array]$EscalationRisks = @()
    )

    if (-not $EscalationRisks -or $EscalationRisks.Count -eq 0) {
        return @()
    }

    return $EscalationRisks |
    Group-Object -Property RiskType |
    Select-Object @{N = 'RiskType'; E = { $_.Name } }, Count
}

function New-ScEntraReportHeaderSection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][hashtable]$Stats,
        [Parameter(Mandatory = $true)][string]$GeneratedOn
    )

    return @"
        <header>
            <h1>🔐 ScEntra Analysis Report</h1>
            <p>Entra ID Security Analysis - Generated on $GeneratedOn</p>
        </header>

        <div class="stats-grid">
            <div class="stat-card">
                <h3>Total Users</h3>
                <div class="number">$($Stats.TotalUsers)</div>
            </div>
            <div class="stat-card">
                <h3>Enabled Users</h3>
                <div class="number">$($Stats.EnabledUsers)</div>
            </div>
            <div class="stat-card">
                <h3>Total Groups</h3>
                <div class="number">$($Stats.TotalGroups)</div>
            </div>
            <div class="stat-card">
                <h3>Role-Enabled Groups</h3>
                <div class="number">$($Stats.RoleEnabledGroups)</div>
            </div>
            <div class="stat-card">
                <h3>PIM-Enabled Groups</h3>
                <div class="number">$($Stats.PIMEnabledGroups)</div>
            </div>
            <div class="stat-card">
                <h3>Service Principals</h3>
                <div class="number">$($Stats.TotalServicePrincipals)</div>
            </div>
            <div class="stat-card">
                <h3>App Registrations</h3>
                <div class="number">$($Stats.TotalAppRegistrations)</div>
            </div>
            <div class="stat-card">
                <h3>Role Assignments</h3>
                <div class="number">$($Stats.TotalRoleAssignments)</div>
            </div>
            <div class="stat-card">
                <h3>PIM Assignments</h3>
                <div class="number">$($Stats.TotalPIMAssignments)</div>
            </div>
            <div class="stat-card warning">
                <h3>Escalation Risks</h3>
                <div class="number">$($Stats.TotalEscalationRisks)</div>
            </div>
            <div class="stat-card warning">
                <h3>High Severity</h3>
                <div class="number">$($Stats.HighSeverityRisks)</div>
            </div>
            <div class="stat-card warning">
                <h3>Medium Severity</h3>
                <div class="number">$($Stats.MediumSeverityRisks)</div>
            </div>
        </div>
"@
}

function New-ScEntraReportChartSection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][array]$RoleDistribution,
        [Parameter(Mandatory = $true)][array]$RiskDistribution
    )

    $roleLabels = $RoleDistribution | ForEach-Object { "'$(($_.Role) -replace '"', '\"')'" } | Join-String -Separator ', '
    $roleCounts = $RoleDistribution | ForEach-Object { $_.Count } | Join-String -Separator ', '
    $riskLabels = $RiskDistribution | ForEach-Object { "'$(($_.RiskType) -replace '"', '\"')'" } | Join-String -Separator ', '
    $riskCounts = $RiskDistribution | ForEach-Object { $_.Count } | Join-String -Separator ', '

    return @"
        <div class="section">
            <h2>📊 Distribution Charts</h2>
            <div class="chart-container">
                <div class="chart-box">
                    <h3>Top 10 Role Assignments</h3>
                    <canvas id="roleChart"></canvas>
                </div>
                <div class="chart-box">
                    <h3>Escalation Risk Types</h3>
                    <canvas id="riskChart"></canvas>
                </div>
            </div>
        </div>

        <script>
            const roleCtx = document.getElementById('roleChart');
            new Chart(roleCtx, {
                type: 'bar',
                data: {
                    labels: [$roleLabels],
                    datasets: [{
                        label: 'Number of Assignments',
                        data: [$roleCounts],
                        backgroundColor: 'rgba(102, 126, 234, 0.7)',
                        borderColor: 'rgba(102, 126, 234, 1)',
                        borderWidth: 2
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: true,
                    plugins: {
                        legend: { display: false }
                    },
                    scales: {
                        y: {
                            beginAtZero: true,
                            ticks: { precision: 0 }
                        }
                    }
                }
            });

            const riskCtx = document.getElementById('riskChart');
            new Chart(riskCtx, {
                type: 'doughnut',
                data: {
                    labels: [$riskLabels],
                    datasets: [{
                        data: [$riskCounts],
                        backgroundColor: [
                            'rgba(220, 53, 69, 0.7)',
                            'rgba(255, 193, 7, 0.7)',
                            'rgba(40, 167, 69, 0.7)',
                            'rgba(102, 126, 234, 0.7)',
                            'rgba(118, 75, 162, 0.7)'
                        ],
                        borderWidth: 2
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: true,
                    plugins: { legend: { position: 'bottom' } }
                }
            });
        </script>
"@
}

function New-ScEntraGraphSection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][hashtable]$GraphData
    )

    if (-not $GraphData -or -not $GraphData.nodes -or $GraphData.nodes.Count -eq 0) {
        return ''
    }

    $nodesJson = $GraphData.nodes | ConvertTo-Json -Compress -Depth 10
    $edgesJson = $GraphData.edges | ConvertTo-Json -Compress -Depth 10

    return @"
        <div class="section">
            <h2>🕸️ Escalation Path Graph</h2>
            <p style="margin-bottom: 20px; color: #666;">Interactive graph showing relationships between users, groups, service principals, app registrations, and role assignments. <strong>Escalation paths to critical roles (Global Admin, Privileged Role Admin, Application Admin, Cloud Application Admin) are highlighted in red.</strong> Click on a node to highlight its escalation path.</p>

            <div style="margin-bottom: 20px; display: flex; gap: 15px; align-items: center; flex-wrap: wrap;">
                <div style="flex: 1; min-width: 300px;">
                    <label for="nodeFilter" style="font-weight: 600; margin-right: 10px;">Filter by entity:</label>
                    <input type="text" id="nodeFilter" placeholder="Search by name..." style="padding: 8px 12px; border: 1px solid #ddd; border-radius: 4px; width: 100%; max-width: 400px; font-size: 14px;">
                </div>
                <div>
                    <label for="typeFilter" style="font-weight: 600; margin-right: 10px;">Type:</label>
                    <select id="typeFilter" style="padding: 8px 12px; border: 1px solid #ddd; border-radius: 4px; font-size: 14px;">
                        <option value="">All Types</option>
                        <option value="user">Users</option>
                        <option value="group">Groups</option>
                        <option value="role">Roles</option>
                        <option value="servicePrincipal">Service Principals</option>
                        <option value="application">Applications</option>
                    </select>
                </div>
                <div>
                    <label for="assignmentFilter" style="font-weight: 600; margin-right: 10px;">Assignment:</label>
                    <select id="assignmentFilter" style="padding: 8px 12px; border: 1px solid #ddd; border-radius: 4px; font-size: 14px;">
                        <option value="">All Assignments</option>
                        <option value="member">Member</option>
                        <option value="active">Active</option>
                        <option value="eligible">Eligible</option>
                    </select>
                </div>
                <div>
                    <label for="escalationFilter" style="font-weight: 600; margin-right: 10px;">
                        <input type="checkbox" id="escalationFilter" style="margin-right: 5px;">
                        Show Only Critical Escalation Paths
                    </label>
                </div>
                <button id="resetGraph" style="padding: 8px 16px; background: #667eea; color: white; border: none; border-radius: 4px; cursor: pointer; font-size: 14px; font-weight: 600;">Reset View</button>
            </div>

            <div id="selectedNodeInfo" style="display: none; margin-bottom: 15px; padding: 12px; background: #f8f9fa; border-left: 4px solid #667eea; border-radius: 4px; cursor: pointer; transition: all 0.2s;" onmouseover="this.style.background='#e8eaf6'; this.style.borderLeftColor='#5e6ad2';" onmouseout="this.style.background='#f8f9fa'; this.style.borderLeftColor='#667eea';">
                <strong>Selected:</strong> <span id="selectedNodeName"></span> <span id="selectedNodeType" style="color: #666; font-size: 0.9em;"></span>
                <div style="margin-top: 8px; font-size: 0.85em; color: #667eea; font-weight: 600;">🔍 Click here for detailed information</div>
            </div>

            <div id="nodeDetailsModal" style="display: none; position: fixed; top: 50%; left: 50%; transform: translate(-50%, -50%); background: white; padding: 0; border-radius: 8px; box-shadow: 0 4px 20px rgba(0,0,0,0.3); z-index: 1000; max-width: 600px; width: 90%; max-height: 80vh; overflow: hidden;">
                <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 20px; display: flex; justify-content: space-between; align-items: center;">
                    <h3 style="margin: 0; font-size: 1.3em;" id="modalTitle">Node Details</h3>
                    <button id="closeModal" style="background: rgba(255,255,255,0.2); border: none; color: white; font-size: 24px; cursor: pointer; width: 32px; height: 32px; border-radius: 4px; display: flex; align-items: center; justify-content: center;">&times;</button>
                </div>
                <div id="modalContent" style="padding: 20px; overflow-y: auto; max-height: calc(80vh - 80px);"></div>
            </div>
            <div id="modalOverlay" style="display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.5); z-index: 999;"></div>

            <div id="escalationGraph"></div>

            <div class="graph-controls">
                <button id="zoomIn" class="control-btn" title="Zoom In">🔍+</button>
                <button id="zoomOut" class="control-btn" title="Zoom Out">🔍−</button>
                <button id="fitGraph" class="control-btn" title="Fit to Screen">⊡</button>
                <button id="resetView" class="control-btn" title="Reset View">↻</button>
            </div>

            <div class="graph-legend">
                <div class="legend-item">
                    <img class="legend-icon" data-icon-type="user" alt="User icon" />
                    <span>User</span>
                </div>
                <div class="legend-item">
                    <img class="legend-icon" data-icon-type="pimEnabledGroup" alt="PIM-enabled group icon" />
                    <span>PIM-Enabled Group</span>
                </div>
                <div class="legend-item">
                    <img class="legend-icon" data-icon-type="securityGroup" alt="Security group icon" />
                    <span>Security Group</span>
                </div>
                <div class="legend-item">
                    <svg width="24" height="24" style="margin-right: 8px;">
                        <rect x="4" y="4" width="16" height="16" fill="#2196F3" stroke="#333" stroke-width="1.5"/>
                    </svg>
                    <span>Other Group</span>
                </div>
                <div class="legend-item">
                    <img class="legend-icon" data-icon-type="role" alt="Role icon" />
                    <span>Role</span>
                </div>
                <div class="legend-item">
                    <img class="legend-icon" data-icon-type="servicePrincipal" alt="Service principal icon" />
                    <span>Service Principal</span>
                </div>
                <div class="legend-item">
                    <img class="legend-icon" data-icon-type="application" alt="Application icon" />
                    <span>Application</span>
                </div>
                <div class="legend-item">
                    <div style="width: 30px; height: 3px; background: #dc3545; margin-right: 8px;"></div>
                    <span>Critical Escalation Path</span>
                </div>
            </div>
        </div>

        <script>
            const graphNodes = $nodesJson;
            const graphEdges = $edgesJson;

            // Create a lookup map for original node data
            const originalNodeData = {};
            graphNodes.forEach(node => {
                originalNodeData[node.id] = node;
            });
            const svgIcon = function(svg) { return 'data:image/svg+xml;utf8,' + encodeURIComponent(svg); };
            const defaultUserIconSvg = '<svg id="e24671f6-f501-4952-a2db-8b0b1d329c17" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 18 18"><defs><linearGradient id="be92901b-ec33-4c65-adf1-9b0eed06d677" x1="9" y1="6.88" x2="9" y2="20.45" gradientUnits="userSpaceOnUse"><stop offset="0.22" stop-color="#32d4f5"/><stop offset="1" stop-color="#198ab3"/></linearGradient><linearGradient id="b46fc246-25d8-4398-8779-1042e8cacae7" x1="8.61" y1="-0.4" x2="9.6" y2="11.92" gradientUnits="userSpaceOnUse"><stop offset="0.22" stop-color="#32d4f5"/><stop offset="1" stop-color="#198ab3"/></linearGradient></defs><title>Icon-identity-230</title><path d="M15.72,18a1.45,1.45,0,0,0,1.45-1.45.47.47,0,0,0,0-.17C16.59,11.81,14,8.09,9,8.09S1.34,11.24.83,16.39A1.46,1.46,0,0,0,2.14,18H15.72Z" fill="url(#be92901b-ec33-4c65-adf1-9b0eed06d677)"/><path d="M9,9.17a4.59,4.59,0,0,1-2.48-.73L9,14.86l2.44-6.38A4.53,4.53,0,0,1,9,9.17Z" fill="#fff" opacity="0.8"/><circle cx="9.01" cy="4.58" r="4.58" fill="url(#b46fc246-25d8-4398-8779-1042e8cacae7)"/></svg>';
            const userIconOverride = 'data:image/svg+xml;base64,PHN2ZyBpZD0iZTI0NjcxZjYtZjUwMS00OTUyLWEyZGItOGIwYjFkMzI5YzE3IiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAxOCAxOCI+PGRlZnM+PGxpbmVhckdyYWRpZW50IGlkPSJiZTkyOTAxYi1lYzMzLTRjNjUtYWRmMS05YjBlZWQwNmQ2NzciIHgxPSI5IiB5MT0iNi44OCIgeDI9IjkiIHkyPSIyMC40NSIgZ3JhZGllbnRVbml0cz0idXNlclNwYWNlT25Vc2UiPjxzdG9wIG9mZnNldD0iMC4yMiIgc3RvcC1jb2xvcj0iIzMyZDRmNSIvPjxzdG9wIG9mZnNldD0iMSIgc3RvcC1jb2xvcj0iIzE5OGFiMyIvPjwvbGluZWFyR3JhZGllbnQ+PGxpbmVhckdyYWRpZW50IGlkPSJiNDZmYzI0Ni0yNWQ4LTQzOTgtODc3OS0xMDQyZThjYWNhZTciIHgxPSI4LjYxIiB5MT0iLTAuNCIgeDI9IjkuNiIgeTI9IjExLjkyIiBncmFkaWVudFVuaXRzPSJ1c2VyU3BhY2VPblVzZSI+PHN0b3Agb2Zmc2V0PSIwLjIyIiBzdG9wLWNvbG9yPSIjMzJkNGY1Ii8+PHN0b3Agb2Zmc2V0PSIxIiBzdG9wLWNvbG9yPSIjMTk4YWIzIi8+PC9saW5lYXJHcmFkaWVudD48L2RlZnM+PHRpdGxlPkljb24taWRlbnRpdHktMjMwPC90aXRsZT48cGF0aCBkPSJNMTUuNzIsMThhMS40NSwxLjQ1LDAsMCwwLDEuNDUtMS40NS40Ny40NywwLDAsMCwwLS4xN0MxNi41OSwxMS44MSwxNCw4LjA5LDksOC4wOVMxLjM0LDExLjI0LjgzLDE2LjM5QTEuNDYsMS40NiwwLDAsMCwyLjE0LDE4SDE1LjcyWiIgZmlsbD0idXJsKCNiZTkyOTAxYi1lYzMzLTRjNjUtYWRmMS05YjBlZWQwNmQ2NzcpIi8+PHBhdGggZD0iTTksOS4xN2E0LjU5LDQuNTksMCwwLDEtMi40OC0uNzNMOSwxNC44NmwyLjQ0LTYuMzhBNC41Myw0LjUzLDAsMCwxLDksOS4xN1oiIGZpbGw9IiNmZmYiIG9wYWNpdHk9IjAuOCIvPjxjaXJjbGUgY3g9IjkuMDEiIGN5PSI0LjU4IiByPSI0LjU4IiBmaWxsPSJ1cmwoI2I0NmZjMjQ2LTI1ZDgtNDM5OC04Nzc5LTEwNDJlOGNhY2FlNykiLz48L3N2Zz4=';
            const userIconDataUri = (userIconOverride && !userIconOverride.includes('…')) ? userIconOverride : svgIcon(defaultUserIconSvg);

            const nodeIcons = {
                user: svgIcon('<svg id="ed8fbe5c-618b-47ce-8d68-3dbd1e10f81a" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 18 18"><defs><linearGradient id="e78519cd-36d2-4ee5-987f-be84be24d95e" x1="7.93" y1="17.95" x2="7.93" y2="5.62" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#5e9624"/><stop offset="1" stop-color="#b4ec36"/></linearGradient><linearGradient id="ac3f95ec-6391-4f34-b431-9534d4cdf013" x1="7.95" y1="9.21" x2="7.95" y2="-2.02" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#5e9624"/><stop offset="1" stop-color="#b4ec36"/></linearGradient></defs><path d="M14,16.85a1.3,1.3,0,0,0,1.32-1.31.81.81,0,0,0,0-.16c-.52-4.15-2.88-7.53-7.4-7.53S1,10.71.51,15.39A1.34,1.34,0,0,0,1.7,16.85H14Z" fill="url(#e78519cd-36d2-4ee5-987f-be84be24d95e)"/><path d="M8,8.83a4.16,4.16,0,0,1-2.26-.66L7.92,14l2.22-5.79A4.2,4.2,0,0,1,8,8.83Z" fill="#fff"/><circle cx="7.95" cy="4.67" r="4.17" fill="url(#ac3f95ec-6391-4f34-b431-9534d4cdf013)"/></svg>'),
                pimEnabledGroup: svgIcon('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 18 18"><defs><linearGradient id="b0670cdb-9407-42e5-ae8f-f3558902da1a" x1="7.89" y1="6.9" x2="7.89" y2="19.35" gradientUnits="userSpaceOnUse"><stop offset="0.22" stop-color="#32d4f5"/><stop offset="1" stop-color="#198ab3"/></linearGradient><linearGradient id="fd04ffc0-49c3-4a18-9b27-999b23712bcb" x1="7.53" y1="0.22" x2="8.44" y2="11.53" gradientUnits="userSpaceOnUse"><stop offset="0.22" stop-color="#32d4f5"/><stop offset="1" stop-color="#198ab3"/></linearGradient><radialGradient id="aa3ecbb1-1061-42c8-aaf2-d5c01a3fcfd9" cx="-19.24" cy="6.51" r="6.13" gradientTransform="matrix(0.94, 0.01, -0.01, 0.94, 32.03, 6.26)" gradientUnits="userSpaceOnUse"><stop offset="0.27" stop-color="#ffd70f"/><stop offset="1" stop-color="#fea11b"/></radialGradient></defs><g id="b245b541-7d80-40be-a5d7-51667bcba1b3"><g><g><title>Icon-identity-223</title><path d="M17.22,13.92a.79.79,0,0,0,.8-.79A.28.28,0,0,0,18,13c-.31-2.5-1.74-4.54-4.46-4.54S9.35,10.22,9.07,13a.81.81,0,0,0,.72.88h7.43Z" fill="#0078d4"/><path d="M13.55,9.09a2.44,2.44,0,0,1-1.36-.4l1.35,3.52,1.33-3.49A2.54,2.54,0,0,1,13.55,9.09Z" fill="#fff" opacity="0.8"/><circle cx="13.55" cy="6.58" r="2.51" fill="#1078d4"/><path d="M14.05,17.11a1.34,1.34,0,0,0,1.34-1.33.81.81,0,0,0,0-.16C14.86,11.42,12.47,8,7.9,8S.86,10.9.4,15.63A1.34,1.34,0,0,0,1.59,17.1H14.05Z" fill="url(#b0670cdb-9407-42e5-ae8f-f3558902da1a)"/><path d="M7.9,9a4.09,4.09,0,0,1-2.27-.67l2.25,5.89,2.24-5.85A4.17,4.17,0,0,1,7.9,9Z" fill="#fff" opacity="0.8"/><circle cx="7.9" cy="4.8" r="4.21" fill="url(#fd04ffc0-49c3-4a18-9b27-999b23712bcb)"/></g><g><path id="f2ddd4d7-46fc-4e48-ae24-8fde036c39bb" d="M17.27,11.45a1.13,1.13,0,0,0,0-1.6h0l-1.94-2a1.12,1.12,0,0,0-1.6,0h0l-2,1.94a1.14,1.14,0,0,0,0,1.61l1.61,1.64a.31.31,0,0,1,.09.22l0,3a.36.36,0,0,0,.12.28l.73.75a.27.27,0,0,0,.37,0l.72-.72h0l.42-.43a.14.14,0,0,0,0-.2l-.31-.31a.17.17,0,0,1,0-.23l.31-.31a.13.13,0,0,0,0-.2l-.3-.31a.17.17,0,0,1,0-.23l.31-.31a.14.14,0,0,0,0-.2l-.42-.43V13.3ZM14.54,8.34a.66.66,0,0,1,.64.65.63.63,0,0,1-.65.64.65.65,0,0,1,0-1.29Z" fill="url(#aa3ecbb1-1061-42c8-aaf2-d5c01a3fcfd9)"/><path id="e15034b6-eebb-4253-ac69-86068a1d4276" d="M14,16.38h0a.14.14,0,0,0,.24-.1V13.83a.16.16,0,0,0-.06-.13h0a.14.14,0,0,0-.22.12v2.46A.13.13,0,0,0,14,16.38Z" fill="#ff9300" opacity="0.75"/><rect id="f3d2a589-08f4-4e99-9635-cc67abadc8f4" x="14.38" y="9.07" width="0.38" height="3.21" rx="0.17" transform="translate(3.8 25.17) rotate(-89.65)" fill="#ff9300" opacity="0.75"/><rect id="bc7793e0-f7bc-4cc4-abb0-181c6c62350c" x="14.37" y="9.68" width="0.38" height="3.21" rx="0.17" transform="translate(3.18 25.78) rotate(-89.65)" fill="#ff9300" opacity="0.75"/></g></g></g></svg>'),
                securityGroup: svgIcon('<svg id="a5c2c34a-a5f9-4043-a084-e51b74497895" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 18 18"><defs><linearGradient id="f97360fa-fd13-420b-9b43-74b8dde83a11" x1="6.7" y1="7.26" x2="6.7" y2="18.36" gradientUnits="userSpaceOnUse"><stop offset="0.22" stop-color="#32d4f5"/><stop offset="1" stop-color="#198ab3"/></linearGradient><linearGradient id="b2ab4071-529d-4450-9443-e6dc0939cc4e" x1="6.42" y1="1.32" x2="7.23" y2="11.39" gradientUnits="userSpaceOnUse"><stop offset="0.22" stop-color="#32d4f5"/><stop offset="1" stop-color="#198ab3"/></linearGradient></defs><title>Icon-identity-223</title><path d="M17.22,13.92a.79.79,0,0,0,.8-.79.28.28,0,0,0,0-.15c-.31-2.5-1.74-4.54-4.46-4.54S9.35,10.22,9.07,13a.81.81,0,0,0,.72.88h7.43Z" fill="#0078d4"/><path d="M13.55,9.09a2.44,2.44,0,0,1-1.36-.4l1.35,3.52,1.33-3.49A2.54,2.54,0,0,1,13.55,9.09Z" fill="#fff" opacity="0.8"/><circle cx="13.55" cy="6.58" r="2.51" fill="#0078d4"/><path d="M12.19,16.36a1.19,1.19,0,0,0,1.19-1.19.66.66,0,0,0,0-.14c-.47-3.74-2.6-6.78-6.66-6.78S.44,10.83,0,15a1.2,1.2,0,0,0,1.07,1.31h11.1Z" fill="url(#f97360fa-fd13-420b-9b43-74b8dde83a11)"/><path d="M6.77,9.14a3.72,3.72,0,0,1-2-.6l2,5.25,2-5.21A3.81,3.81,0,0,1,6.77,9.14Z" fill="#fff" opacity="0.8"/><circle cx="6.74" cy="5.39" r="3.75" fill="url(#b2ab4071-529d-4450-9443-e6dc0939cc4e)"/></svg>'),
                group: svgIcon('<svg id="a5c2c34a-a5f9-4043-a084-e51b74497895" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 18 18"><defs><linearGradient id="f97360fa-fd13-420b-9b43-74b8dde83a11" x1="6.7" y1="7.26" x2="6.7" y2="18.36" gradientUnits="userSpaceOnUse"><stop offset="0.22" stop-color="#32d4f5"/><stop offset="1" stop-color="#198ab3"/></linearGradient><linearGradient id="b2ab4071-529d-4450-9443-e6dc0939cc4e" x1="6.42" y1="1.32" x2="7.23" y2="11.39" gradientUnits="userSpaceOnUse"><stop offset="0.22" stop-color="#32d4f5"/><stop offset="1" stop-color="#198ab3"/></linearGradient></defs><title>Icon-identity-223</title><path d="M17.22,13.92a.79.79,0,0,0,.8-.79.28.28,0,0,0,0-.15c-.31-2.5-1.74-4.54-4.46-4.54S9.35,10.22,9.07,13a.81.81,0,0,0,.72.88h7.43Z" fill="#0078d4"/><path d="M13.55,9.09a2.44,2.44,0,0,1-1.36-.4l1.35,3.52,1.33-3.49A2.54,2.54,0,0,1,13.55,9.09Z" fill="#fff" opacity="0.8"/><circle cx="13.55" cy="6.58" r="2.51" fill="#0078d4"/><path d="M12.19,16.36a1.19,1.19,0,0,0,1.19-1.19.66.66,0,0,0,0-.14c-.47-3.74-2.6-6.78-6.66-6.78S.44,10.83,0,15a1.2,1.2,0,0,0,1.07,1.31h11.1Z" fill="url(#f97360fa-fd13-420b-9b43-74b8dde83a11)"/><path d="M6.77,9.14a3.72,3.72,0,0,1-2-.6l2,5.25,2-5.21A3.81,3.81,0,0,1,6.77,9.14Z" fill="#fff" opacity="0.8"/><circle cx="6.74" cy="5.39" r="3.75" fill="url(#b2ab4071-529d-4450-9443-e6dc0939cc4e)"/></svg>'),
                role: svgIcon('<svg id="a12d75ea-cbb6-44fa-832a-e54cce009101" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 18 18"><defs><linearGradient id="e2b13d81-97e0-465a-b9ed-b7f57e1b3f8c" x1="9" y1="16.79" x2="9" y2="1.21" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#0078d4"/><stop offset="0.06" stop-color="#0a7cd7"/><stop offset="0.34" stop-color="#2e8ce1"/><stop offset="0.59" stop-color="#4897e9"/><stop offset="0.82" stop-color="#589eed"/><stop offset="1" stop-color="#5ea0ef"/></linearGradient></defs><title>Icon-identity-233</title><path d="M16.08,8.44c0,4.57-5.62,8.25-6.85,9a.43.43,0,0,1-.46,0c-1.23-.74-6.85-4.42-6.85-9V2.94a.44.44,0,0,1,.43-.44C6.73,2.39,5.72.5,9,.5s2.27,1.89,6.65,2a.44.44,0,0,1,.43.44Z" fill="#0078d4"/><path d="M15.5,8.48c0,4.2-5.16,7.57-6.29,8.25a.4.4,0,0,1-.42,0C7.66,16.05,2.5,12.68,2.5,8.48v-5A.41.41,0,0,1,2.9,3C6.92,2.93,6,1.21,9,1.21S11.08,2.93,15.1,3a.41.41,0,0,1,.4.4Z" fill="url(#e2b13d81-97e0-465a-b9ed-b7f57e1b3f8c)"/><path d="M11.85,7.66h-.4V6.24a2.62,2.62,0,0,0-.7-1.81,2.37,2.37,0,0,0-3.48,0,2.61,2.61,0,0,0-.7,1.81V7.66h-.4A.32.32,0,0,0,5.82,8v3.68a.32.32,0,0,0,.33.32h5.7a.32.32,0,0,0,.33-.32V8A.32.32,0,0,0,11.85,7.66Zm-1.55,0H7.7V6.22a1.43,1.43,0,0,1,.41-1,1.19,1.19,0,0,1,1.78,0,1.56,1.56,0,0,1,.16.2h0a1.4,1.4,0,0,1,.25.79Z" fill="#ffbd02"/><path d="M6.15,7.66h5.7a.32.32,0,0,1,.21.08L5.94,11.9a.33.33,0,0,1-.12-.24V8A.32.32,0,0,1,6.15,7.66Z" fill="#ffe452"/><path d="M11.85,7.66H6.15a.32.32,0,0,0-.21.08l6.12,4.16a.3.3,0,0,0,.12-.24V8A.32.32,0,0,0,11.85,7.66Z" fill="#ffd400" opacity="0.5"/></svg>'),
                servicePrincipal: svgIcon('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 18 18"><defs><linearGradient id="b05ecef1-bdba-47cb-a2a6-665a5bf9ae79" x1="9" y1="19.049" x2="9" y2="1.048" gradientUnits="userSpaceOnUse"><stop offset="0.2" stop-color="#0078d4"/><stop offset="0.287" stop-color="#1380da"/><stop offset="0.495" stop-color="#3c91e5"/><stop offset="0.659" stop-color="#559cec"/><stop offset="0.759" stop-color="#5ea0ef"/></linearGradient></defs><g id="adc593fc-9575-4f0f-b9cc-4803103092a4"><g><rect x="1" y="1" width="16" height="16" rx="0.534" fill="url(#b05ecef1-bdba-47cb-a2a6-665a5bf9ae79)"/><g><g opacity="0.95"><rect x="2.361" y="2.777" width="3.617" height="3.368" rx="0.14" fill="#fff"/><rect x="7.192" y="2.777" width="3.617" height="3.368" rx="0.14" fill="#fff"/><rect x="12.023" y="2.777" width="3.617" height="3.368" rx="0.14" fill="#fff"/></g><rect x="2.361" y="7.28" width="8.394" height="3.368" rx="0.14" fill="#fff" opacity="0.45"/><rect x="12.009" y="7.28" width="3.617" height="3.368" rx="0.14" fill="#fff" opacity="0.9"/><rect x="2.361" y="11.854" width="13.186" height="3.368" rx="0.14" fill="#fff" opacity="0.75"/></g></g></g></svg>'),
                application: svgIcon('<svg id="a76a0103-ce03-4d58-859d-4c27e02925d2" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 18 18"><defs><linearGradient id="efeb8e96-2af0-4681-9a6a-45f9b0262f19" x1="-6518.78" y1="1118.86" x2="-6518.78" y2="1090.06" gradientTransform="matrix(0.5, 0, 0, -0.5, 3267.42, 559.99)" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#5ea0ef"/><stop offset="0.18" stop-color="#589eed"/><stop offset="0.41" stop-color="#4897e9"/><stop offset="0.66" stop-color="#2e8ce1"/><stop offset="0.94" stop-color="#0a7cd7"/><stop offset="1" stop-color="#0078d4"/></linearGradient></defs><path d="M5.67,10.61H10v4.32H5.67Zm-5-5.76H5V.53H1.23a.6.6,0,0,0-.6.6Zm.6,10.08H5V10.61H.63v3.72A.6.6,0,0,0,1.23,14.93Zm-.6-5H5V5.57H.63Zm10.08,5h3.72a.6.6,0,0,0,.6-.6V10.61H10.71Zm-5-5H10V5.57H5.67Zm5,0H15V5.57H10.71Zm0-9.36V4.85H15V1.13a.6.6,0,0,0-.6-.6Zm-5,4.32H10V.53H5.67Z" fill="url(#efeb8e96-2af0-4681-9a6a-45f9b0262f19)"/><polygon points="17.37 10.7 17.37 15.21 13.5 17.47 13.5 12.96 17.37 10.7" fill="#32bedd"/><polygon points="17.37 10.7 13.5 12.97 9.63 10.7 13.5 8.44 17.37 10.7" fill="#9cebff"/><polygon points="13.5 12.97 13.5 17.47 9.63 15.21 9.63 10.7 13.5 12.97" fill="#50e6ff"/><polygon points="9.63 15.21 13.5 12.96 13.5 17.47 9.63 15.21" fill="#9cebff"/><polygon points="17.37 15.21 13.5 12.96 13.5 17.47 17.37 15.21" fill="#50e6ff"/></svg>')
            };

            const nodes = new vis.DataSet(graphNodes.map(node => {
                // Use icons for PIM-enabled and security groups
                let icon = null;
                if (node.type === 'group' && node.shape === 'diamond') {
                    icon = nodeIcons.pimEnabledGroup;
                } else if (node.type === 'group' && node.shape === 'triangle') {
                    icon = nodeIcons.securityGroup;
                } else if (node.type !== 'group') {
                    icon = nodeIcons[node.type];
                }
                const hasIcon = Boolean(icon);
                const baseColor = node.type === 'user' ? '#4CAF50' :
                                  node.type === 'group' ? '#2196F3' :
                                  node.type === 'role' ? '#FF5722' :
                                  node.type === 'servicePrincipal' ? '#9C27B0' :
                                  node.type === 'application' ? '#FF9800' : '#999';
                const fallbackShape = node.shape || (node.type === 'role' ? 'diamond' : (node.type === 'group' ? 'box' : 'dot'));
                const detailTags = [];
                if (node.type === 'group') {
                    if (node.isPIMEnabled) detailTags.push('PIM enabled');
                    if (node.isAssignableToRole) detailTags.push('Role-assignable');
                    if (node.securityEnabled) detailTags.push('Security group');
                }

                const config = {
                    id: node.id,
                    label: node.label,
                    group: node.type,
                    title: node.label + ' (' + node.type + ')',
                    shape: hasIcon ? 'image' : fallbackShape,
                    borderWidth: hasIcon ? 0 : 2,
                    font: { color: '#333', size: 14 }
                };
                if (detailTags.length) {
                    config.title += ' • ' + detailTags.join(', ');
                }
                if (hasIcon) {
                    config.image = icon;
                } else {
                    config.color = {
                        background: baseColor,
                        border: '#333'
                    };
                }
                return config;
            }));

            document.querySelectorAll('.legend-icon').forEach(el => {
                const type = el.getAttribute('data-icon-type');
                if (type && nodeIcons[type]) {
                    el.src = nodeIcons[type];
                }
            });

            const edges = new vis.DataSet(graphEdges.map((edge, idx) => {
                // Determine color based on escalation path status
                let edgeColor = edge.isEscalationPath ? '#dc3545' : (
                    edge.type === 'has_role' ? '#FF5722' :
                    edge.type === 'member_of' ? '#2196F3' :
                    edge.type === 'owns' ? '#FF9800' :
                    edge.type === 'assigned_to' ? '#00BCD4' :
                    edge.type === 'can_manage' ? '#E91E63' :
                    edge.isPIM ? '#9C27B0' : '#999'
                );
                
                let edgeWidth = edge.isEscalationPath ? 4 : (
                    edge.type === 'has_role' ? 3 : 
                    (edge.type === 'can_manage' ? 2 : 1.5)
                );
                
                return {
                    id: edge.from + '-' + edge.to + '-' + idx,
                    from: edge.from,
                    to: edge.to,
                    label: edge.label || edge.type,
                    arrows: 'to',
                    color: {
                        color: edgeColor,
                        opacity: edge.isEscalationPath ? 0.9 : 0.7
                    },
                    dashes: edge.isPIM || edge.type === 'owns' || edge.type === 'can_manage',
                    width: edgeWidth,
                    font: { size: 10, color: '#666', align: 'middle' },
                    edgeType: edge.type,
                    isPIM: edge.isPIM || false,
                    isEscalationPath: edge.isEscalationPath || false
                };
            }));

            const container = document.getElementById('escalationGraph');
            const data = { nodes: nodes, edges: edges };
            const options = {
                nodes: {
                    borderWidth: 2,
                    size: 25,
                    font: { size: 14, color: '#333' },
                    scaling: { min: 20, max: 40 }
                },
                edges: {
                    smooth: { type: 'continuous', roundness: 0.5 },
                    width: 2
                },
                physics: {
                    enabled: true,
                    barnesHut: {
                        gravitationalConstant: -15000,
                        centralGravity: 0.2,
                        springLength: 250,
                        springConstant: 0.02,
                        damping: 0.15,
                        avoidOverlap: 0.8
                    },
                    minVelocity: 0.75,
                    solver: 'barnesHut',
                    stabilization: { enabled: true, iterations: 300, updateInterval: 25 }
                },
                interaction: {
                    hover: true,
                    tooltipDelay: 100,
                    zoomView: true,
                    dragView: true
                },
                layout: {
                    improvedLayout: true,
                    hierarchical: { enabled: false }
                }
            };

            const network = new vis.Network(container, data, options);
            network.once('stabilizationIterationsDone', function() {
                network.setOptions({ physics: false });
            });

            // Setup modal event listeners
            document.getElementById('closeModal').addEventListener('click', function() {
                document.getElementById('nodeDetailsModal').style.display = 'none';
                document.getElementById('modalOverlay').style.display = 'none';
            });

            document.getElementById('modalOverlay').addEventListener('click', function() {
                document.getElementById('nodeDetailsModal').style.display = 'none';
                document.getElementById('modalOverlay').style.display = 'none';
            });

            // Variable to store currently selected node for detail view
            let currentSelectedNode = null;

            const originalNodeStyles = {};
            graphNodes.forEach(node => {
                const hasIcon = Boolean(nodeIcons[node.type]);
                const baseColor = node.type === 'user' ? '#4CAF50' :
                                  node.type === 'group' ? '#2196F3' :
                                  node.type === 'role' ? '#FF5722' :
                                  node.type === 'servicePrincipal' ? '#9C27B0' :
                                  node.type === 'application' ? '#FF9800' : '#999';
                originalNodeStyles[node.id] = {
                    hasIcon,
                    color: hasIcon ? null : {
                        background: baseColor,
                        border: '#333'
                    }
                };
            });

            const selectedNodes = new Set();

            function getConnectedNodes(nodeId, visited = new Set(), excludeOtherPrincipals = false, originNodeId = null, originNodeType = null, depth = 0) {
                if (visited.has(nodeId)) return visited;
                visited.add(nodeId);
                if (originNodeId === null) {
                    originNodeId = nodeId;
                    const originNode = nodes.get(nodeId);
                    originNodeType = originNode ? originNode.type : null;
                }

                const currentNode = nodes.get(nodeId);
                const currentType = currentNode ? currentNode.type : null;

                const allEdges = edges.get();
                const connectedNodes = [];
                allEdges.forEach(edge => {
                    if (edge.from === nodeId && !visited.has(edge.to)) {
                        connectedNodes.push(edge.to);
                    } else if (edge.to === nodeId && !visited.has(edge.from)) {
                        connectedNodes.push(edge.from);
                    }
                });

                connectedNodes.forEach(connId => {
                    if (!visited.has(connId)) {
                        const connNode = nodes.get(connId);
                        if (!connNode) return;

                        let shouldSkip = false;
                        let shouldRecurse = true;

                        if (excludeOtherPrincipals) {
                            if (connNode.type === 'user' && connId !== originNodeId) {
                                shouldSkip = true;
                            }

                            if ((originNodeType === 'user' || originNodeType === 'group') && !shouldSkip) {
                                if (originNodeType === 'user') {
                                    if (depth === 0) {
                                        if (connNode.type === 'role' || connNode.type === 'servicePrincipal' || connNode.type === 'application') {
                                            shouldRecurse = false;
                                        } else if (connNode.type === 'group') {
                                            shouldRecurse = true;
                                        }
                                    } else if (depth >= 1 && depth <= 2) {
                                        if (connNode.type === 'role' || connNode.type === 'servicePrincipal' || connNode.type === 'application') {
                                            shouldRecurse = false;
                                        } else if (connNode.type === 'group' && connId !== originNodeId) {
                                            shouldRecurse = true;
                                        } else {
                                            shouldSkip = true;
                                        }
                                    } else {
                                        shouldSkip = true;
                                    }
                                } else if (originNodeType === 'group') {
                                    if (depth === 0) {
                                        if (connNode.type === 'role' || connNode.type === 'servicePrincipal' || connNode.type === 'application') {
                                            shouldRecurse = false;
                                        } else if (connNode.type === 'group' && connId !== originNodeId) {
                                            shouldRecurse = true;
                                        } else if (connNode.type === 'user' && connId !== originNodeId) {
                                            shouldRecurse = false;
                                        }
                                    } else if (depth === 1) {
                                        if (connNode.type === 'role' || connNode.type === 'servicePrincipal' || connNode.type === 'application') {
                                            shouldRecurse = false;
                                        } else {
                                            shouldSkip = true;
                                        }
                                    } else {
                                        shouldSkip = true;
                                    }
                                }
                            }
                        }

                        if (!shouldSkip) {
                            visited.add(connId);
                            if (shouldRecurse) {
                                getConnectedNodes(connId, visited, excludeOtherPrincipals, originNodeId, originNodeType, depth + 1);
                            }
                        }
                    }
                });

                return visited;
            }

            function highlightPath(nodeId, additive = false) {
                if (!additive) {
                    selectedNodes.clear();
                }

                selectedNodes.add(nodeId);
                const allPathNodes = new Set();
                const allPathEdges = new Set();

                selectedNodes.forEach(selectedId => {
                    const selectedNode = nodes.get(selectedId);
                    const isPrincipalSelected = selectedNode && (selectedNode.type === 'user' || selectedNode.type === 'group');
                    const pathNodes = getConnectedNodes(selectedId, new Set(), isPrincipalSelected);
                    pathNodes.forEach(nId => allPathNodes.add(nId));
                    pathNodes.forEach(nId => {
                        const connEdges = network.getConnectedEdges(nId);
                        connEdges.forEach(edgeId => {
                            const edge = edges.get(edgeId);
                            if (edge && pathNodes.has(edge.from) && pathNodes.has(edge.to)) {
                                allPathEdges.add(edgeId);
                            }
                        });
                    });
                });

                const updates = [];
                const allNodes = nodes.get();
                allNodes.forEach(node => {
                    const baseStyle = originalNodeStyles[node.id] || {};
                    if (allPathNodes.has(node.id)) {
                        const isSelected = selectedNodes.has(node.id);
                        const update = {
                            id: node.id,
                            borderWidth: baseStyle.hasIcon ? (isSelected ? 4 : 0) : (isSelected ? 6 : 4),
                            font: { color: '#000', size: isSelected ? 18 : 16, bold: true },
                            hidden: false,
                            shadow: baseStyle.hasIcon && isSelected,
                            shadowColor: 'rgba(0,0,0,0.4)',
                            shadowSize: baseStyle.hasIcon && isSelected ? 12 : 0
                        };
                        if (baseStyle.color) {
                            update.color = {
                                background: baseStyle.color.background,
                                border: isSelected ? '#FFD700' : '#000',
                                highlight: {
                                    background: baseStyle.color.background,
                                    border: isSelected ? '#FFD700' : '#000'
                                }
                            };
                        }
                        updates.push(update);
                    } else {
                        updates.push({
                            id: node.id,
                            hidden: true,
                            shadow: false,
                            shadowSize: 0
                        });
                    }
                });
                nodes.update(updates);

                const edgeUpdates = [];
                const allEdges = edges.get();
                allEdges.forEach(edge => {
                    if (allPathEdges.has(edge.id)) {
                        let edgeColor = '#999';
                        let edgeWidth = 2;
                        let isDashed = false;
                        const edgeLabel = (edge.label || '').toLowerCase();

                        if (edgeLabel.includes('member')) {
                            edgeColor = '#2196F3';
                            edgeWidth = 2.5;
                        } else if (edgeLabel.includes('owner')) {
                            edgeColor = '#FF9800';
                            edgeWidth = 2.5;
                        } else if (edgeLabel.includes('eligible')) {
                            edgeColor = '#9C27B0';
                            edgeWidth = 2;
                            isDashed = true;
                        } else if (edgeLabel.includes('pim active') || edgeLabel.includes('active')) {
                            edgeColor = '#4CAF50';
                            edgeWidth = 2.5;
                        } else if (edgeLabel.includes('direct')) {
                            edgeColor = '#FF5722';
                            edgeWidth = 3;
                        } else if (edge.edgeType === 'has_role') {
                            edgeColor = '#FF5722';
                            edgeWidth = 2.5;
                        }

                        edgeUpdates.push({
                            id: edge.id,
                            width: edgeWidth,
                            color: { color: edgeColor, opacity: 1 },
                            hidden: false,
                            dashes: isDashed
                        });
                    } else {
                        edgeUpdates.push({ id: edge.id, hidden: true });
                    }
                });
                edges.update(edgeUpdates);

                filterRiskTable(Array.from(allPathNodes));
            }

            function filterRiskTable(nodeIds) {
                const riskRows = document.querySelectorAll('.risk-row');
                let visibleCount = 0;

                riskRows.forEach(row => {
                    const entityIds = row.getAttribute('data-entity-ids');
                    if (!entityIds) {
                        row.style.display = '';
                        visibleCount++;
                        return;
                    }

                    const rowEntityIds = entityIds.split(',').filter(id => id.trim());
                    const hasMatch = rowEntityIds.some(entityId => nodeIds.includes(entityId));

                    if (hasMatch) {
                        row.style.display = '';
                        visibleCount++;
                    } else {
                        row.style.display = 'none';
                    }
                });

                const risksSection = document.querySelector('.section h2');
                if (risksSection && risksSection.textContent.includes('Escalation Risks')) {
                    const existingMsg = document.getElementById('risk-filter-msg');
                    if (existingMsg) existingMsg.remove();

                    if (visibleCount === 0 && riskRows.length > 0) {
                        const msg = document.createElement('p');
                        msg.id = 'risk-filter-msg';
                        msg.style.cssText = 'color: #666; font-style: italic; margin-top: 10px;';
                        msg.textContent = 'No escalation risks found for the selected entity.';
                        risksSection.parentNode.insertBefore(msg, risksSection.nextSibling);
                    }
                }
            }

            function resetHighlight() {
                selectedNodes.clear();

                const updates = [];
                graphNodes.forEach(node => {
                    const baseStyle = originalNodeStyles[node.id] || {};
                    const update = {
                        id: node.id,
                        borderWidth: baseStyle.hasIcon ? 0 : 2,
                        font: { color: '#333', size: 14 },
                        hidden: false,
                        shadow: false,
                        shadowSize: 0
                    };
                    if (baseStyle.color) {
                        update.color = baseStyle.color;
                    }
                    updates.push(update);
                });
                nodes.update(updates);

                const edgeUpdates = [];
                const allEdges = edges.get();
                allEdges.forEach(edge => {
                    edgeUpdates.push({
                        id: edge.id,
                        width: edge.edgeType === 'has_role' ? 3 : (edge.edgeType === 'can_manage' ? 2 : 1.5),
                        color: {
                            color: edge.edgeType === 'has_role' ? '#FF5722' :
                                   edge.edgeType === 'member_of' ? '#2196F3' :
                                   edge.edgeType === 'owns' ? '#FF9800' :
                                   edge.edgeType === 'assigned_to' ? '#00BCD4' :
                                   edge.edgeType === 'can_manage' ? '#E91E63' :
                                   edge.isPIM ? '#9C27B0' : '#999',
                            opacity: 0.7
                        },
                        hidden: false
                    });
                });
                edges.update(edgeUpdates);

                document.getElementById('selectedNodeInfo').style.display = 'none';
                const riskRows = document.querySelectorAll('.risk-row');
                riskRows.forEach(row => { row.style.display = ''; });
                const riskMsg = document.getElementById('risk-filter-msg');
                if (riskMsg) riskMsg.remove();
            }

            function groupVisibleNodesByType() {
                // Get all visible nodes
                const allNodes = nodes.get();
                const visibleNodes = allNodes.filter(node => !node.hidden);
                
                if (visibleNodes.length === 0) return;
                
                // Group nodes by type
                const nodesByType = {};
                visibleNodes.forEach(node => {
                    if (!nodesByType[node.type]) {
                        nodesByType[node.type] = [];
                    }
                    nodesByType[node.type].push(node);
                });
                
                // Calculate group positions in a circular arrangement
                const types = Object.keys(nodesByType);
                const centerX = 0;
                const centerY = 0;
                const groupRadius = 400; // Distance from center for each type group
                const angleStep = (2 * Math.PI) / types.length;
                
                // Position each type group
                types.forEach((type, typeIndex) => {
                    const typeNodes = nodesByType[type];
                    const groupAngle = angleStep * typeIndex;
                    const groupCenterX = centerX + groupRadius * Math.cos(groupAngle);
                    const groupCenterY = centerY + groupRadius * Math.sin(groupAngle);
                    
                    // Arrange nodes within the group in a circle or grid
                    const nodeCount = typeNodes.length;
                    const innerRadius = Math.min(150, 50 + nodeCount * 5); // Scale based on count
                    
                    typeNodes.forEach((node, nodeIndex) => {
                        let x, y;
                        if (nodeCount === 1) {
                            x = groupCenterX;
                            y = groupCenterY;
                        } else if (nodeCount <= 8) {
                            // Circular arrangement for small groups
                            const nodeAngle = (2 * Math.PI / nodeCount) * nodeIndex;
                            x = groupCenterX + innerRadius * Math.cos(nodeAngle);
                            y = groupCenterY + innerRadius * Math.sin(nodeAngle);
                        } else {
                            // Grid arrangement for larger groups
                            const cols = Math.ceil(Math.sqrt(nodeCount));
                            const col = nodeIndex % cols;
                            const row = Math.floor(nodeIndex / cols);
                            const spacing = 80;
                            const offsetX = (cols - 1) * spacing / 2;
                            const offsetY = (Math.ceil(nodeCount / cols) - 1) * spacing / 2;
                            x = groupCenterX + col * spacing - offsetX;
                            y = groupCenterY + row * spacing - offsetY;
                        }
                        
                        nodes.update({ id: node.id, x: x, y: y });
                    });
                });
                
                // Re-enable physics briefly to smooth out the layout
                network.setOptions({ physics: { enabled: true } });
                setTimeout(() => {
                    network.setOptions({ physics: { enabled: false } });
                    network.fit({ animation: { duration: 800, easingFunction: 'easeInOutQuad' } });
                }, 500);
            }

            network.on('click', function(params) {
                if (params.nodes.length > 0) {
                    const nodeId = params.nodes[0];
                    const node = originalNodeData[nodeId];
                    const isAdditive = params.event.srcEvent.ctrlKey || params.event.srcEvent.metaKey;
                    
                    console.log('Node clicked:', nodeId);
                    console.log('Node data from originalNodeData:', node);
                    console.log('Node type:', node ? node.type : 'undefined');

                    // Store the currently selected node for the info panel click handler
                    currentSelectedNode = node;

                    // Check if escalation filter is enabled
                    const escalationFilter = document.getElementById('escalationFilter').checked;
                    
                    if (escalationFilter) {
                        // Show path from selected node to critical roles
                        highlightEscalationPathFromNode(nodeId);
                    } else {
                        // Normal highlight behavior
                        highlightPath(nodeId, isAdditive);
                    }
                    
                    document.getElementById('selectedNodeName').textContent = node.label;
                    document.getElementById('selectedNodeType').textContent = '(' + node.type + ')';
                    document.getElementById('selectedNodeInfo').style.display = 'block';
                    
                    // Focus on node and fit to screen
                    network.focus(nodeId, {
                        scale: 1.5,
                        animation: { duration: 500, easingFunction: 'easeInOutQuad' }
                    });
                    
                    // Fit the graph to show the selected node and its connections
                    setTimeout(() => {
                        network.fit({
                            nodes: [nodeId, ...getConnectedNodes(nodeId)],
                            animation: { duration: 500, easingFunction: 'easeInOutQuad' }
                        });
                    }, 100);
                }
            });

            function showNodeDetails(node) {
                console.log('showNodeDetails called with:', node);
                console.log('Node properties:', Object.keys(node || {}));
                console.log('Node type:', node ? node.type : 'NO NODE');

                if (!node || !node.type) {
                    console.error('Invalid node object:', node);
                    alert('Error: Invalid node data. Please try selecting the node again.');
                    return;
                }

                const modal = document.getElementById('nodeDetailsModal');
                const overlay = document.getElementById('modalOverlay');
                const modalTitle = document.getElementById('modalTitle');
                const modalContent = document.getElementById('modalContent');

                console.log('Modal elements:', { modal, overlay, modalTitle, modalContent });

                if (!modal || !overlay || !modalTitle || !modalContent) {
                    console.error('Modal elements not found!');
                    return;
                }

                modalTitle.textContent = node.label || node.id || 'Unknown';

                let detailsHtml = '<div style="display: flex; flex-direction: column; gap: 15px;">';

                // Add type badge
                const typeColors = {
                    'user': '#4CAF50',
                    'group': '#2196F3',
                    'role': '#FF5722',
                    'servicePrincipal': '#9C27B0',
                    'application': '#FF9800'
                };
                const typeColor = typeColors[node.type] || '#999';
                detailsHtml += '<div><span style="background: ' + typeColor + '; color: white; padding: 4px 12px; border-radius: 12px; font-size: 0.85em; font-weight: 600;">' + node.type.toUpperCase() + '</span></div>';

                // Common properties
                detailsHtml += '<div style="background: #f8f9fa; padding: 15px; border-radius: 6px;">';
                detailsHtml += '<h4 style="margin: 0 0 10px 0; color: #333;">Basic Information</h4>';
                detailsHtml += '<table style="width: 100%; border-collapse: collapse;">';

                if (node.id) {
                    detailsHtml += '<tr><td style="padding: 6px 0; color: #666; font-weight: 600; width: 40%;">ID:</td><td style="padding: 6px 0; word-break: break-all; font-family: monospace; font-size: 0.9em;">' + node.id + '</td></tr>';
                }

                // Type-specific properties
                if (node.type === 'user') {
                    if (node.userPrincipalName) {
                        detailsHtml += '<tr><td style="padding: 6px 0; color: #666; font-weight: 600;">UPN:</td><td style="padding: 6px 0; word-break: break-all;">' + node.userPrincipalName + '</td></tr>';
                    }
                    if (node.accountEnabled !== undefined) {
                        const statusColor = node.accountEnabled ? '#4CAF50' : '#f44336';
                        const statusText = node.accountEnabled ? 'Enabled' : 'Disabled';
                        detailsHtml += '<tr><td style="padding: 6px 0; color: #666; font-weight: 600;">Account Status:</td><td style="padding: 6px 0;"><span style="color: ' + statusColor + '; font-weight: 600;">' + statusText + '</span></td></tr>';
                    }
                    if (node.mail) {
                        detailsHtml += '<tr><td style="padding: 6px 0; color: #666; font-weight: 600;">Email:</td><td style="padding: 6px 0;">' + node.mail + '</td></tr>';
                    }
                    if (node.userType) {
                        detailsHtml += '<tr><td style="padding: 6px 0; color: #666; font-weight: 600;">User Type:</td><td style="padding: 6px 0;">' + node.userType + '</td></tr>';
                    }
                } else if (node.type === 'group') {
                    if (node.isAssignableToRole !== undefined) {
                        const roleAssignable = node.isAssignableToRole ? 'Yes' : 'No';
                        const roleColor = node.isAssignableToRole ? '#4CAF50' : '#999';
                        detailsHtml += '<tr><td style="padding: 6px 0; color: #666; font-weight: 600;">Role Assignable:</td><td style="padding: 6px 0;"><span style="color: ' + roleColor + '; font-weight: 600;">' + roleAssignable + '</span></td></tr>';
                    }
                    if (node.isPIMEnabled !== undefined) {
                        const pimEnabled = node.isPIMEnabled ? 'Yes' : 'No';
                        const pimColor = node.isPIMEnabled ? '#9C27B0' : '#999';
                        detailsHtml += '<tr><td style="padding: 6px 0; color: #666; font-weight: 600;">PIM Enabled:</td><td style="padding: 6px 0;"><span style="color: ' + pimColor + '; font-weight: 600;">' + pimEnabled + '</span></td></tr>';
                    }
                    if (node.securityEnabled !== undefined) {
                        const secEnabled = node.securityEnabled ? 'Yes' : 'No';
                        detailsHtml += '<tr><td style="padding: 6px 0; color: #666; font-weight: 600;">Security Enabled:</td><td style="padding: 6px 0;">' + secEnabled + '</td></tr>';
                    }
                    if (node.memberCount !== undefined) {
                        detailsHtml += '<tr><td style="padding: 6px 0; color: #666; font-weight: 600;">Member Count:</td><td style="padding: 6px 0;">' + node.memberCount + '</td></tr>';
                    }
                    if (node.description) {
                        detailsHtml += '<tr><td style="padding: 6px 0; color: #666; font-weight: 600;">Description:</td><td style="padding: 6px 0;">' + node.description + '</td></tr>';
                    }
                } else if (node.type === 'servicePrincipal' || node.type === 'application') {
                    if (node.appId) {
                        detailsHtml += '<tr><td style="padding: 6px 0; color: #666; font-weight: 600;">App ID:</td><td style="padding: 6px 0; word-break: break-all; font-family: monospace; font-size: 0.9em;">' + node.appId + '</td></tr>';
                    }
                    if (node.accountEnabled !== undefined) {
                        const statusColor = node.accountEnabled ? '#4CAF50' : '#f44336';
                        const statusText = node.accountEnabled ? 'Enabled' : 'Disabled';
                        detailsHtml += '<tr><td style="padding: 6px 0; color: #666; font-weight: 600;">Status:</td><td style="padding: 6px 0;"><span style="color: ' + statusColor + '; font-weight: 600;">' + statusText + '</span></td></tr>';
                    }
                } else if (node.type === 'role') {
                    if (node.isPrivileged !== undefined) {
                        const privText = node.isPrivileged ? 'Yes' : 'No';
                        const privColor = node.isPrivileged ? '#FF5722' : '#999';
                        detailsHtml += '<tr><td style="padding: 6px 0; color: #666; font-weight: 600;">Privileged:</td><td style="padding: 6px 0;"><span style="color: ' + privColor + '; font-weight: 600;">' + privText + '</span></td></tr>';
                    }
                    if (node.description) {
                        detailsHtml += '<tr><td style="padding: 6px 0; color: #666; font-weight: 600;">Description:</td><td style="padding: 6px 0;">' + node.description + '</td></tr>';
                    }
                }

                detailsHtml += '</table></div>';

                // Connection statistics
                const connectedEdges = network.getConnectedEdges(node.id);
                const connectedNodes = network.getConnectedNodes(node.id);

                detailsHtml += '<div style="background: #f8f9fa; padding: 15px; border-radius: 6px;">';
                detailsHtml += '<h4 style="margin: 0 0 10px 0; color: #333;">Connections</h4>';
                detailsHtml += '<div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">';
                detailsHtml += '<div style="text-align: center; padding: 10px; background: white; border-radius: 4px;"><div style="font-size: 1.5em; font-weight: bold; color: #667eea;">' + connectedEdges.length + '</div><div style="font-size: 0.85em; color: #666;">Relationships</div></div>';
                detailsHtml += '<div style="text-align: center; padding: 10px; background: white; border-radius: 4px;"><div style="font-size: 1.5em; font-weight: bold; color: #667eea;">' + connectedNodes.length + '</div><div style="font-size: 0.85em; color: #666;">Connected Nodes</div></div>';
                detailsHtml += '</div></div>';

                // Relationship breakdown
                if (connectedEdges.length > 0) {
                    const edgeTypes = {};
                    connectedEdges.forEach(edgeId => {
                        const edge = edges.get(edgeId);
                        if (edge) {
                            const label = edge.label || edge.type || 'Unknown';
                            edgeTypes[label] = (edgeTypes[label] || 0) + 1;
                        }
                    });

                    detailsHtml += '<div style="background: #f8f9fa; padding: 15px; border-radius: 6px;">';
                    detailsHtml += '<h4 style="margin: 0 0 10px 0; color: #333;">Relationship Breakdown</h4>';
                    detailsHtml += '<div style="display: flex; flex-direction: column; gap: 8px;">';

                    for (const [label, count] of Object.entries(edgeTypes).sort((a, b) => b[1] - a[1])) {
                        const percentage = Math.round((count / connectedEdges.length) * 100);
                        detailsHtml += '<div><div style="display: flex; justify-content: space-between; margin-bottom: 4px;"><span style="font-size: 0.9em; color: #666;">' + label + '</span><span style="font-size: 0.9em; font-weight: 600;">' + count + '</span></div><div style="background: #e0e0e0; height: 6px; border-radius: 3px; overflow: hidden;"><div style="background: #667eea; height: 100%; width: ' + percentage + '%; transition: width 0.3s;"></div></div></div>';
                    }

                    detailsHtml += '</div></div>';
                }

                detailsHtml += '</div>';

                modalContent.innerHTML = detailsHtml;
                modal.style.display = 'block';
                overlay.style.display = 'block';
            }

            // Add click listener to selected node info panel (after showNodeDetails is defined)
            document.getElementById('selectedNodeInfo').addEventListener('click', function() {
                console.log('Selected node info clicked');
                console.log('Current selected node:', currentSelectedNode);
                if (currentSelectedNode) {
                    console.log('Calling showNodeDetails');
                    showNodeDetails(currentSelectedNode);
                } else {
                    console.log('No node selected');
                }
            });

            function highlightEscalationPathFromNode(startNodeId) {
                // Critical roles we want to trace paths to
                const criticalRoles = [
                    'Global Administrator',
                    'Privileged Role Administrator',
                    'Application Administrator',
                    'Cloud Application Administrator'
                ];
                
                // Find critical role nodes
                const criticalRoleIds = graphNodes
                    .filter(node => node.type === 'role' && criticalRoles.includes(node.label))
                    .map(node => node.id);
                
                if (criticalRoleIds.length === 0) {
                    // No critical roles found, show all escalation paths
                    const allEdges = edges.get();
                    const escalationNodeIds = new Set();
                    const escalationEdgeIds = new Set();
                    
                    allEdges.forEach(edge => {
                        if (edge.isEscalationPath) {
                            escalationNodeIds.add(edge.from);
                            escalationNodeIds.add(edge.to);
                            escalationEdgeIds.add(edge.id);
                        }
                    });
                    
                    displayFilteredGraph(escalationNodeIds, escalationEdgeIds);
                    return;
                }
                
                // Build adjacency list for forward traversal (from -> to)
                const adjacency = {};
                const allEdges = edges.get();
                allEdges.forEach(edge => {
                    if (!adjacency[edge.from]) {
                        adjacency[edge.from] = [];
                    }
                    adjacency[edge.from].push({
                        to: edge.to,
                        edgeId: edge.id,
                        isEscalationPath: edge.isEscalationPath
                    });
                });
                
                // BFS from start node to find paths to critical roles
                const pathNodes = new Set();
                const pathEdges = new Set();
                const queue = [startNodeId];
                const visited = new Set([startNodeId]);
                const parent = {};
                const parentEdge = {};
                
                pathNodes.add(startNodeId);
                
                while (queue.length > 0) {
                    const currentId = queue.shift();
                    
                    // Check if we reached a critical role
                    if (criticalRoleIds.includes(currentId)) {
                        // Backtrack to add all nodes and edges in this path
                        let backtrackId = currentId;
                        while (parent[backtrackId]) {
                            pathNodes.add(backtrackId);
                            pathEdges.add(parentEdge[backtrackId]);
                            backtrackId = parent[backtrackId];
                        }
                        pathNodes.add(startNodeId);
                        continue; // Continue to find other paths
                    }
                    
                    // Explore neighbors (only through escalation path edges)
                    if (adjacency[currentId]) {
                        adjacency[currentId].forEach(neighbor => {
                            if (!visited.has(neighbor.to) && neighbor.isEscalationPath) {
                                visited.add(neighbor.to);
                                queue.push(neighbor.to);
                                parent[neighbor.to] = currentId;
                                parentEdge[neighbor.to] = neighbor.edgeId;
                            }
                        });
                    }
                }
                
                // Display only the path nodes and edges
                displayFilteredGraph(pathNodes, pathEdges);
            }
            
            function displayFilteredGraph(nodeIds, edgeIds) {
                const nodeUpdates = [];
                const allNodes = nodes.get();
                
                allNodes.forEach(node => {
                    if (nodeIds.has(node.id)) {
                        const baseStyle = originalNodeStyles[node.id] || {};
                        const update = {
                            id: node.id,
                            borderWidth: baseStyle.hasIcon ? 0 : 4,
                            font: { color: '#000', size: 16 },
                            hidden: false,
                            shadow: false,
                            shadowSize: 0
                        };
                        if (baseStyle.color) {
                            update.color = baseStyle.color;
                        }
                        nodeUpdates.push(update);
                    } else {
                        nodeUpdates.push({ id: node.id, hidden: true });
                    }
                });
                nodes.update(nodeUpdates);
                
                const edgeUpdates = [];
                const allEdges = edges.get();
                
                allEdges.forEach(edge => {
                    if (edgeIds.has(edge.id)) {
                        edgeUpdates.push({ id: edge.id, hidden: false });
                    } else {
                        edgeUpdates.push({ id: edge.id, hidden: true });
                    }
                });
                edges.update(edgeUpdates);
            }

            function applyFilters() {
                const searchTerm = document.getElementById('nodeFilter').value.toLowerCase();
                const typeFilter = document.getElementById('typeFilter').value;
                const assignmentFilter = document.getElementById('assignmentFilter').value;
                const escalationFilter = document.getElementById('escalationFilter').checked;

                // If escalation filter is enabled, show only escalation paths
                if (escalationFilter) {
                    const allEdges = edges.get();
                    const edgeUpdates = [];
                    const escalationNodeIds = new Set();
                    const escalationEdgeIds = new Set();

                    allEdges.forEach(edge => {
                        if (edge.isEscalationPath) {
                            escalationNodeIds.add(edge.from);
                            escalationNodeIds.add(edge.to);
                            escalationEdgeIds.add(edge.id);
                            edgeUpdates.push({ id: edge.id, hidden: false });
                        } else {
                            edgeUpdates.push({ id: edge.id, hidden: true });
                        }
                    });
                    edges.update(edgeUpdates);

                    const matchingNodes = graphNodes.filter(node => {
                        const matchesSearch = !searchTerm || node.label.toLowerCase().includes(searchTerm);
                        const matchesType = !typeFilter || node.type === typeFilter;
                        const isInEscalationPath = escalationNodeIds.has(node.id);
                        return matchesSearch && matchesType && isInEscalationPath;
                    });

                    // If only one node matches, select it and show its escalation path
                    if (matchingNodes.length === 1) {
                        const selectedNode = matchingNodes[0];
                        highlightEscalationPathFromNode(selectedNode.id);
                        document.getElementById('selectedNodeName').textContent = selectedNode.label;
                        document.getElementById('selectedNodeType').textContent = '(' + selectedNode.type + ')';
                        document.getElementById('selectedNodeInfo').style.display = 'block';
                        network.focus(selectedNode.id, {
                            scale: 1.5,
                            animation: { duration: 500, easingFunction: 'easeInOutQuad' }
                        });
                        return;
                    }

                    const nodeUpdates = [];
                    const allNodes = nodes.get();
                    const matchingIds = new Set(matchingNodes.map(n => n.id));

                    allNodes.forEach(node => {
                        if (matchingIds.has(node.id)) {
                            const baseStyle = originalNodeStyles[node.id] || {};
                            const update = {
                                id: node.id,
                                borderWidth: baseStyle.hasIcon ? 0 : 4,
                                font: { color: '#000', size: 16 },
                                hidden: false,
                                shadow: false,
                                shadowSize: 0
                            };
                            if (baseStyle.color) {
                                update.color = baseStyle.color;
                            }
                            nodeUpdates.push(update);
                        } else {
                            nodeUpdates.push({ id: node.id, hidden: true });
                        }
                    });
                    nodes.update(nodeUpdates);
                    return;
                }

                if (assignmentFilter) {
                    const allEdges = edges.get();
                    const edgeUpdates = [];
                    const validNodeIds = new Set();

                    allEdges.forEach(edge => {
                        let matches = false;
                        const edgeLabel = (edge.label || '').toLowerCase();

                        if (assignmentFilter === 'member' && edgeLabel === 'member') {
                            matches = true;
                        } else if (assignmentFilter === 'active' && (edgeLabel === 'direct' || edgeLabel === 'pim active')) {
                            matches = true;
                        } else if (assignmentFilter === 'eligible' && edgeLabel === 'eligible') {
                            matches = true;
                        }

                        if (matches) {
                            validNodeIds.add(edge.from);
                            validNodeIds.add(edge.to);
                            edgeUpdates.push({ id: edge.id, hidden: false });
                        } else {
                            edgeUpdates.push({ id: edge.id, hidden: true });
                        }
                    });
                    edges.update(edgeUpdates);

                    const matchingNodes = graphNodes.filter(node => {
                        const matchesSearch = !searchTerm || node.label.toLowerCase().includes(searchTerm);
                        const matchesType = !typeFilter || node.type === typeFilter;
                        const matchesAssignment = !assignmentFilter || validNodeIds.has(node.id);
                        return matchesSearch && matchesType && matchesAssignment;
                    });

                    const nodeUpdates = [];
                    const allNodes = nodes.get();
                    const matchingIds = new Set(matchingNodes.map(n => n.id));

                    allNodes.forEach(node => {
                        if (matchingIds.has(node.id)) {
                            const baseStyle = originalNodeStyles[node.id] || {};
                            const update = {
                                id: node.id,
                                borderWidth: baseStyle.hasIcon ? 0 : 4,
                                font: { color: '#000', size: 16 },
                                hidden: false,
                                shadow: false,
                                shadowSize: 0
                            };
                            if (baseStyle.color) {
                                update.color = baseStyle.color;
                            }
                            nodeUpdates.push(update);
                        } else {
                            nodeUpdates.push({ id: node.id, hidden: true });
                        }
                    });
                    nodes.update(nodeUpdates);

                } else {
                    const matchingNodes = graphNodes.filter(node => {
                        const matchesSearch = !searchTerm || node.label.toLowerCase().includes(searchTerm);
                        const matchesType = !typeFilter || node.type === typeFilter;
                        return matchesSearch && matchesType;
                    });

                    if (matchingNodes.length === 1) {
                        network.selectNodes([matchingNodes[0].id]);
                        network.focus(matchingNodes[0].id, {
                            scale: 1.5,
                            animation: { duration: 500, easingFunction: 'easeInOutQuad' }
                        });
                        highlightPath(matchingNodes[0].id);
                        document.getElementById('selectedNodeName').textContent = matchingNodes[0].label;
                        document.getElementById('selectedNodeType').textContent = '(' + matchingNodes[0].type + ')';
                        document.getElementById('selectedNodeInfo').style.display = 'block';
                    } else if (matchingNodes.length > 1) {
                        const matchingIds = new Set(matchingNodes.map(n => n.id));
                        const updates = [];
                        const allNodes = nodes.get();
                        allNodes.forEach(node => {
                            if (matchingIds.has(node.id)) {
                                const baseStyle = originalNodeStyles[node.id] || {};
                                const update = {
                                    id: node.id,
                                    borderWidth: baseStyle.hasIcon ? 0 : 4,
                                    font: { color: '#000', size: 16 },
                                    hidden: false,
                                    shadow: false,
                                    shadowSize: 0
                                };
                                if (baseStyle.color) {
                                    update.color = baseStyle.color;
                                }
                                updates.push(update);
                            } else {
                                updates.push({ id: node.id, hidden: true });
                            }
                        });
                        nodes.update(updates);
                    } else if (searchTerm || typeFilter) {
                        const updates = [];
                        const allNodes = nodes.get();
                        allNodes.forEach(node => {
                            updates.push({ id: node.id, hidden: true });
                        });
                        nodes.update(updates);
                    } else {
                        resetHighlight();
                    }
                }
            }

            document.getElementById('nodeFilter').addEventListener('input', applyFilters);
            document.getElementById('typeFilter').addEventListener('change', applyFilters);
            document.getElementById('assignmentFilter').addEventListener('change', applyFilters);
            document.getElementById('escalationFilter').addEventListener('change', applyFilters);

            document.getElementById('resetGraph').addEventListener('click', function() {
                document.getElementById('nodeFilter').value = '';
                document.getElementById('typeFilter').value = '';
                document.getElementById('assignmentFilter').value = '';
                document.getElementById('escalationFilter').checked = false;
                resetHighlight();
                network.fit({
                    animation: { duration: 500, easingFunction: 'easeInOutQuad' }
                });
            });

            let initialViewPosition = null;
            network.once('stabilizationIterationsDone', function() {
                initialViewPosition = network.getViewPosition();
            });

            document.getElementById('zoomIn').addEventListener('click', function() {
                const currentScale = network.getScale();
                network.moveTo({
                    scale: currentScale * 1.2,
                    animation: { duration: 300, easingFunction: 'easeInOutQuad' }
                });
            });

            document.getElementById('zoomOut').addEventListener('click', function() {
                const currentScale = network.getScale();
                network.moveTo({
                    scale: currentScale / 1.2,
                    animation: { duration: 300, easingFunction: 'easeInOutQuad' }
                });
            });

            document.getElementById('fitGraph').addEventListener('click', function() {
                network.fit({
                    animation: { duration: 500, easingFunction: 'easeInOutQuad' }
                });
            });

            document.getElementById('resetView').addEventListener('click', function() {
                if (initialViewPosition) {
                    network.moveTo({
                        position: initialViewPosition,
                        scale: 1.0,
                        animation: { duration: 500, easingFunction: 'easeInOutQuad' }
                    });
                } else {
                    network.fit({
                        animation: { duration: 500, easingFunction: 'easeInOutQuad' }
                    });
                }
            });
        </script>
"@
}

function New-ScEntraRiskSection {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][array]$EscalationRisks
    )

    if (-not $EscalationRisks -or $EscalationRisks.Count -eq 0) {
        return ''
    }

    $rowsBuilder = [System.Text.StringBuilder]::new()
    foreach ($risk in ($EscalationRisks | Sort-Object -Property Severity -Descending)) {
        $badgeClass = switch ($risk.Severity) {
            'High' { 'badge-high' }
            'Medium' { 'badge-medium' }
            'Low' { 'badge-low' }
            default { 'badge-medium' }
        }

        $entityIds = @()
        if ($risk.GroupId) { $entityIds += $risk.GroupId }
        if ($risk.ServicePrincipalId) { $entityIds += $risk.ServicePrincipalId }
        if ($risk.AppId) { $entityIds += $risk.AppId }
        if ($risk.PrincipalId) { $entityIds += $risk.PrincipalId }
        if ($risk.MemberId) { $entityIds += $risk.MemberId }
        $entityIdsAttr = ($entityIds -join ',')

        [void]$rowsBuilder.AppendLine(@"
                    <tr data-entity-ids="$entityIdsAttr" class="risk-row">
                        <td><span class="badge $badgeClass">$($risk.Severity)</span></td>
                        <td>$($risk.RiskType)</td>
                        <td>$($risk.Description)</td>
                    </tr>
"@)
    }

    $rows = $rowsBuilder.ToString()

    return @"
        <div class="section">
            <h2>⚠️ Escalation Risks</h2>
            <table>
                <thead>
                    <tr>
                        <th>Severity</th>
                        <th>Risk Type</th>
                        <th>Description</th>
                    </tr>
                </thead>
                <tbody>
$rows                </tbody>
            </table>
        </div>
"@
}

function New-ScEntraReportDocument {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][hashtable]$Stats,
        [Parameter(Mandatory = $true)][array]$RoleDistribution,
        [Parameter(Mandatory = $true)][array]$RiskDistribution,
        [Parameter(Mandatory = $true)][array]$EscalationRisks,
        [Parameter(Mandatory = $false)][hashtable]$GraphData,
        [Parameter(Mandatory = $true)][string]$GeneratedOn
    )

    $headerSection = New-ScEntraReportHeaderSection -Stats $Stats -GeneratedOn $GeneratedOn
    $chartSection = New-ScEntraReportChartSection -RoleDistribution $RoleDistribution -RiskDistribution $RiskDistribution
    $graphSection = if ($GraphData -and $GraphData.nodes -and $GraphData.nodes.Count -gt 0) { New-ScEntraGraphSection -GraphData $GraphData } else { '' }
    $riskSection = New-ScEntraRiskSection -EscalationRisks $EscalationRisks

    return @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ScEntra Analysis Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/vis-network@9.1.6/dist/vis-network.min.js"></script>
    <link href="https://cdn.jsdelivr.net/npm/vis-network@9.1.6/dist/dist/vis-network.min.css" rel="stylesheet" type="text/css" />
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            padding: 20px;
            color: #333;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: white;
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }
        header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }
        header h1 { font-size: 2.5em; margin-bottom: 10px; }
        header p { font-size: 1.1em; opacity: 0.9; }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            padding: 40px;
            background: #f8f9fa;
        }
        .stat-card {
            background: white;
            padding: 25px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            transition: transform 0.3s;
        }
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 5px 20px rgba(0,0,0,0.15);
        }
        .stat-card h3 {
            color: #667eea;
            font-size: 0.9em;
            text-transform: uppercase;
            margin-bottom: 10px;
            font-weight: 600;
        }
        .stat-card .number { font-size: 2.5em; font-weight: bold; color: #333; }
        .stat-card.warning .number { color: #ff6b6b; }
        .section { padding: 40px; }
        .section h2 {
            color: #667eea;
            margin-bottom: 20px;
            font-size: 1.8em;
            border-bottom: 3px solid #667eea;
            padding-bottom: 10px;
        }
        .chart-container {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 30px;
            margin-top: 20px;
        }
        .chart-box {
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        .chart-box h3 { color: #333; margin-bottom: 15px; text-align: center; }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            background: white;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            border-radius: 8px;
            overflow: hidden;
        }
        th {
            background: #667eea;
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: 600;
        }
        td { padding: 12px 15px; border-bottom: 1px solid #eee; }
        tr:hover { background: #f8f9fa; }
        .severity-high { color: #dc3545; font-weight: bold; }
        .severity-medium { color: #ffc107; font-weight: bold; }
        .severity-low { color: #28a745; font-weight: bold; }
        footer {
            background: #2c3e50;
            color: white;
            text-align: center;
            padding: 20px;
            margin-top: 40px;
        }
        .badge {
            display: inline-block;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: 600;
        }
        .badge-high { background: #dc3545; color: white; }
        .badge-medium { background: #ffc107; color: #333; }
        .badge-low { background: #28a745; color: white; }
        #escalationGraph {
            width: 100%;
            height: 800px;
            border: 1px solid #ddd;
            border-radius: 8px;
            background: #fafafa;
        }
        .graph-legend {
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            margin-top: 20px;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 8px;
        }
        .graph-controls {
            display: flex;
            justify-content: center;
            gap: 10px;
            margin-top: 15px;
            padding: 10px;
        }
        .control-btn {
            padding: 10px 16px;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
            font-weight: 600;
            transition: background 0.2s;
        }
        .control-btn:hover { background: #5568d3; }
        .control-btn:active { transform: scale(0.95); }
        .legend-item { display: flex; align-items: center; gap: 8px; }
        .legend-icon { width: 22px; height: 22px; }
    </style>
</head>
<body>
    <div class="container">
$headerSection
$chartSection
$graphSection
$riskSection
        <footer>
            <p>Generated by ScEntra - Entra ID Security Scanner</p>
            <p>Report generated on $GeneratedOn</p>
        </footer>
    </div>
</body>
</html>
"@
}
