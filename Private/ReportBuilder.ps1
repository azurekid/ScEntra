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
            <div class="header-top">
                <h1>🔐 ScEntra Analysis Report</h1>
                <button id="themeToggle" class="theme-toggle">🌙 Dark Mode</button>
            </div>
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
                        <option value="apiPermission">API Permissions</option>
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
                <div class="graph-button-group">
                    <button id="resetGraph" class="button-primary">Reset View</button>
                </div>
            </div>

            <div id="selectedNodeInfo">
                <strong>Selected:</strong> <span id="selectedNodeName"></span> <span id="selectedNodeType" style="color: var(--muted-text-color); font-size: 0.9em;"></span>
                <div style="margin-top: 8px; font-size: 0.85em; color: var(--accent-color); font-weight: 600;">🔍 Click here for detailed information</div>
            </div>

            <div id="nodeDetailsModal" class="node-details-modal" style="display: none;" role="dialog" aria-modal="true" aria-labelledby="modalTitle">
                <div class="modal-header">
                    <h3 id="modalTitle">Node Details</h3>
                    <button id="closeModal" class="modal-close" aria-label="Close details">&times;</button>
                </div>
                <div id="modalContent" class="modal-body"></div>
            </div>
            <div id="modalOverlay" class="modal-overlay" style="display: none;"></div>

            <div id="escalationGraph"></div>

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
                    <img class="legend-icon" data-icon-type="apiPermission" alt="API permission icon" />
                    <span>API Permission</span>
                </div>
                <div class="legend-item">
                    <span class="legend-line" style="background:#667eea;"></span>
                    <span>Role Assignment</span>
                </div>
                <div class="legend-item">
                    <span class="legend-line" style="background:#2563eb;"></span>
                    <span>Group Membership</span>
                </div>
                <div class="legend-item">
                    <span class="legend-line" style="background:#f59e0b;"></span>
                    <span>Ownership</span>
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
            
            // Filter out service principals, applications, and roles without connections
            const relevantEdgeTypes = ['requests_permission', 'has_permission', 'owns', 'assigned_to', 'has_service_principal'];
            const assignmentEdgeTypes = ['has_role', 'pim_active', 'pim_eligible', 'eligible'];
            const connectedSPandAppIds = new Set();
            const connectedRoleIds = new Set();
            const criticalPathNodeIds = new Set();
            
            graphEdges.forEach(edge => {
                if (edge.isEscalationPath) {
                    criticalPathNodeIds.add(edge.from);
                    criticalPathNodeIds.add(edge.to);
                }
                // Track SPs and Apps with permission/escalation edges
                if (relevantEdgeTypes.includes(edge.type) || edge.isEscalationPath) {
                    const fromNode = graphNodes.find(n => n.id === edge.from);
                    const toNode = graphNodes.find(n => n.id === edge.to);
                    
                    if (fromNode && (fromNode.type === 'servicePrincipal' || fromNode.type === 'application')) {
                        connectedSPandAppIds.add(edge.from);
                    }
                    if (toNode && (toNode.type === 'servicePrincipal' || toNode.type === 'application')) {
                        connectedSPandAppIds.add(edge.to);
                    }
                }
                
                // Track roles with any assignment edges
                if (assignmentEdgeTypes.includes(edge.type)) {
                    const toNode = graphNodes.find(n => n.id === edge.to);
                    if (toNode && toNode.type === 'role') {
                        connectedRoleIds.add(edge.to);
                    }
                }
            });
            
            // Filter nodes to exclude unconnected SPs, Apps, and Roles
            const filteredNodes = graphNodes.filter(node => {
                if (node.type === 'servicePrincipal' || node.type === 'application') {
                    return connectedSPandAppIds.has(node.id);
                }
                if (node.type === 'role') {
                    return connectedRoleIds.has(node.id);
                }
                return true;
            });

            // Create a lookup map for original node data
            const originalNodeData = {};
            filteredNodes.forEach(node => {
                originalNodeData[node.id] = node;
            });
            const svgIcon = function(svg) { return 'data:image/svg+xml;utf8,' + encodeURIComponent(svg); };
            const getCssVar = (name, fallback) => {
                const value = (getComputedStyle(document.body).getPropertyValue(name) || '').trim();
                return value || fallback;
            };
            const currentTextColor = () => getCssVar('--text-color', '#333');
            const currentMutedTextColor = () => getCssVar('--muted-text-color', '#666');
            const formatDateTimeValue = (value) => {
                if (!value) { return null; }
                const date = new Date(value);
                if (Number.isNaN(date.getTime())) { return null; }
                return date.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
            };
            const formatRelativeTimeValue = (value) => {
                if (!value) { return ''; }
                const date = new Date(value);
                if (Number.isNaN(date.getTime())) { return ''; }
                const diffMs = Date.now() - date.getTime();
                if (!Number.isFinite(diffMs)) { return ''; }
                const absDiff = Math.abs(diffMs);
                const units = [
                    { label: 'year', ms: 365 * 24 * 60 * 60 * 1000 },
                    { label: 'month', ms: 30 * 24 * 60 * 60 * 1000 },
                    { label: 'week', ms: 7 * 24 * 60 * 60 * 1000 },
                    { label: 'day', ms: 24 * 60 * 60 * 1000 },
                    { label: 'hour', ms: 60 * 60 * 1000 },
                    { label: 'minute', ms: 60 * 1000 }
                ];
                for (const unit of units) {
                    if (absDiff >= unit.ms || unit.label === 'minute') {
                        const delta = Math.round(diffMs / unit.ms);
                        if (delta === 0) {
                            return 'just now';
                        }
                        const plural = Math.abs(delta) === 1 ? unit.label : unit.label + 's';
                        return delta > 0 ? (Math.abs(delta) + ' ' + plural + ' ago') : ('in ' + Math.abs(delta) + ' ' + plural);
                    }
                }
                return '';
            };
            const formatDetailTimestamp = (value) => {
                const absolute = formatDateTimeValue(value);
                if (!absolute) { return null; }
                const relative = formatRelativeTimeValue(value);
                return relative ? absolute + ' (' + relative + ')' : absolute;
            };
            const textColor = currentTextColor();
            const mutedTextColor = currentMutedTextColor();
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
                application: svgIcon('<svg id="a76a0103-ce03-4d58-859d-4c27e02925d2" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 18 18"><defs><linearGradient id="efeb8e96-2af0-4681-9a6a-45f9b0262f19" x1="-6518.78" y1="1118.86" x2="-6518.78" y2="1090.06" gradientTransform="matrix(0.5, 0, 0, -0.5, 3267.42, 559.99)" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#5ea0ef"/><stop offset="0.18" stop-color="#589eed"/><stop offset="0.41" stop-color="#4897e9"/><stop offset="0.66" stop-color="#2e8ce1"/><stop offset="0.94" stop-color="#0a7cd7"/><stop offset="1" stop-color="#0078d4"/></linearGradient></defs><path d="M5.67,10.61H10v4.32H5.67Zm-5-5.76H5V.53H1.23a.6.6,0,0,0-.6.6Zm.6,10.08H5V10.61H.63v3.72A.6.6,0,0,0,1.23,14.93Zm-.6-5H5V5.57H.63Zm10.08,5h3.72a.6.6,0,0,0,.6-.6V10.61H10.71Zm-5-5H10V5.57H5.67Zm5,0H15V5.57H10.71Zm0-9.36V4.85H15V1.13a.6.6,0,0,0-.6-.6Zm-5,4.32H10V.53H5.67Z" fill="url(#efeb8e96-2af0-4681-9a6a-45f9b0262f19)"/><polygon points="17.37 10.7 17.37 15.21 13.5 17.47 13.5 12.96 17.37 10.7" fill="#32bedd"/><polygon points="17.37 10.7 13.5 12.97 9.63 10.7 13.5 8.44 17.37 10.7" fill="#9cebff"/><polygon points="13.5 12.97 13.5 17.47 9.63 15.21 9.63 10.7 13.5 12.97" fill="#50e6ff"/><polygon points="9.63 15.21 13.5 12.96 13.5 17.47 9.63 15.21" fill="#9cebff"/><polygon points="17.37 15.21 13.5 12.96 13.5 17.47 17.37 15.21" fill="#50e6ff"/></svg>'),
                apiPermission: svgIcon('<svg id="uuid-431a759c-a29d-4678-89ee-5b1b2666f890" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 18 18"><defs><linearGradient id="uuid-10478e68-1009-47b7-9e5e-1dad26a11858" x1="9" y1="18" x2="9" y2="0" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#198ab3"/><stop offset="1" stop-color="#32bedd"/></linearGradient><linearGradient id="uuid-7623d8a9-ce5d-405d-98e0-ff8e832bdf61" x1="7.203" y1="11.089" x2="7.203" y2="3.888" gradientUnits="userSpaceOnUse"><stop offset="0" stop-color="#6f4bb2"/><stop offset="1" stop-color="#c69aeb"/></linearGradient></defs><path d="m11.844,12.791c-.316-.081-.641-.073-.947.015l-1.295-2.124c-.04-.065-.124-.087-.19-.049l-.536.309c-.068.039-.091.128-.05.195l1.296,2.127c-.667.668-.737,1.797.01,2.551.12.121.259.223.41.302.276.143.568.213.857.213.463,0,.916-.18,1.273-.527.125-.121.23-.263.31-.417.302-.579.28-1.233-.037-1.769-.245-.413-.636-.707-1.102-.826Zm.424,1.965c-.06.232-.207.428-.414.55-.207.122-.449.156-.682.097-.278-.071-.503-.267-.614-.541-.141-.349-.041-.762.245-1.007.171-.147.379-.222.592-.222.075,0,.151.009.225.029.233.06.428.206.551.413h0c.122.207.157.448.097.681Zm3.555-9.443c-1.012,0-1.863.695-2.106,1.631h-2.54c-.078,0-.141.063-.141.141v.806c0,.078.063.141.141.141h2.54c.243.937,1.093,1.631,2.106,1.631,1.201,0,2.177-.976,2.177-2.175s-.977-2.175-2.177-2.175Zm1.068,2.388c-.082.428-.427.772-.854.854-.766.146-1.428-.515-1.282-1.28.082-.428.426-.772.854-.854.766-.147,1.429.515,1.283,1.28ZM2.978,2.953c.121.03.244.045.366.045.144,0,.286-.022.423-.063l.884,1.447c.04.065.124.087.19.049l.406-.234c.068-.039.091-.128.05-.195l-.887-1.453c.468-.475.577-1.224.218-1.821-.206-.343-.534-.585-.923-.682-.445-.111-.909-.016-1.28.267-.547.417-.737,1.18-.45,1.805.195.424.559.725,1.004.835Zm-.083-2.056c.133-.097.288-.148.445-.148.061,0,.122.008.183.023.232.058.42.219.514.446.13.315.02.691-.258.889-.182.13-.405.172-.619.118-.232-.058-.42-.219-.514-.446-.129-.312-.023-.683.249-.883Zm2.717,10.093l-.828-.477c-.067-.039-.154-.016-.192.052l-1.473,2.577c-1.227-.327-2.587.325-3.009,1.668-.091.289-.125.595-.1.897.071.849.537,1.569,1.253,1.973.377.212.793.321,1.214.321.374,0,.752-.086,1.109-.259.289-.14.549-.34.758-.583.56-.652.743-1.497.522-2.293-.12-.432-.352-.813-.668-1.116l1.468-2.567c.038-.067.015-.153-.052-.192Zm-2.055,5.145l-.213.234c-.161.177-.367.315-.601.366-.298.065-.605.02-.873-.131-.288-.162-.495-.427-.584-.745-.089-.318-.048-.652.115-.939.227-.402.648-.628,1.08-.628.206,0,.415.051.606.16.288.162.495.427.584.745.089.318.048.652-.115.939Z" fill="url(#uuid-10478e68-1009-47b7-9e5e-1dad26a11858)"/><path d="m9.921,5.287l-2.172-1.253c-.339-.195-.757-.195-1.096,0l-2.172,1.253c-.339.196-.548.557-.548.948v2.505c0,.391.209.753.548.949l2.174,1.253c.339.195.757.195,1.096,0l2.174-1.253c.339-.196.548-.557.548-.949v-2.505c-.001-.392-.212-.754-.552-.948Z" fill="url(#uuid-7623d8a9-ce5d-405d-98e0-ff8e832bdf61)"/></svg>')
            };

            const nodes = new vis.DataSet(filteredNodes.map(node => {
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
                    font: { color: textColor, size: 14 }
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

            const permissionEdgeColors = {
                delegatedRequest: '#34d399',
                applicationRequest: '#f59e0b',
                applicationGrant: '#ef5350',
                delegatedGrant: '#3b82f6'
            };
            const escalationEdgeColor = '#dc3545';
            const escalationEdgeOpacity = 0.95;
            const escalationEdgeWidth = 4;

            const edgeLengthPresets = {
                'member_of': 165,
                'has_role': 235,
                'owns': 275,
                'assigned_to': 225,
                'can_manage': 245,
                'requests_permission': 320,
                'has_permission': 345
            };

            const edges = new vis.DataSet(graphEdges.map((edge, idx) => {
                const normalizedLabel = (edge.label || '').toLowerCase();
                let edgeColor;

                if (normalizedLabel === 'pim active') {
                    edgeColor = '#22c55e'; // Always green for PIM Active
                } else if (edge.isPIM) {
                    if (normalizedLabel === 'pim eligible') {
                        edgeColor = '#f59e0b'; // Orange for PIM Eligible (group membership)
                    } else if (normalizedLabel === 'eligible') {
                        edgeColor = '#8b5cf6'; // Purple for Eligible (role assignment)
                    } else {
                        edgeColor = '#8b5cf6'; // Default purple for other PIM
                    }
                } else if (edge.type === 'has_role') {
                    edgeColor = '#667eea';
                } else if (edge.type === 'member_of') {
                    edgeColor = '#2563eb';
                } else if (edge.type === 'owns') {
                    edgeColor = '#f59e0b';
                } else if (edge.type === 'assigned_to') {
                    edgeColor = '#06b6d4';
                } else if (edge.type === 'can_manage') {
                    edgeColor = '#a855f7';
                } else {
                    edgeColor = '#6b7280';
                }

                const explicitGrantType = edge.grantType || '';
                if (!edge.isEscalationPath) {
                    if (edge.type === 'requests_permission') {
                        if (explicitGrantType === 'Delegated' || normalizedLabel.startsWith('delegated')) {
                            edgeColor = permissionEdgeColors.delegatedRequest;
                        }
                        else if (explicitGrantType === 'Application' || normalizedLabel.startsWith('application')) {
                            edgeColor = permissionEdgeColors.applicationRequest;
                        }
                    }
                    else if (edge.type === 'has_permission') {
                        if (explicitGrantType === 'Application' || normalizedLabel.includes('application grant')) {
                            edgeColor = permissionEdgeColors.applicationGrant;
                        }
                        else if (explicitGrantType === 'Delegated' || normalizedLabel.startsWith('delegated')) {
                            edgeColor = permissionEdgeColors.delegatedGrant;
                        }
                    }
                }

                let edgeWidth = edge.type === 'has_role' ? 3 :
                                edge.type === 'can_manage' ? 2 : 1.5;

                const baseLength = edgeLengthPresets[edge.type] || 205;
                const randomStretch = (Math.random() - 0.5) * 90; // +/-45px variance
                const escalates = edge.isEscalationPath ? 60 : 0;
                const resolvedLength = Math.max(140, baseLength + randomStretch + escalates);

                return {
                    id: edge.from + '-' + edge.to + '-' + idx,
                    from: edge.from,
                    to: edge.to,
                    label: edge.label || edge.type,
                    arrows: 'to',
                    color: {
                        color: edgeColor,
                        opacity: edge.type === 'has_role' ? 0.9 : 0.7
                    },
                    dashes: edge.isPIM || edge.type === 'owns' || edge.type === 'can_manage',
                    width: edgeWidth,
                    font: {
                        size: 10,
                        color: mutedTextColor,
                        align: 'middle',
                        strokeWidth: 0,
                        strokeColor: 'transparent'
                    },
                    length: resolvedLength,
                    edgeType: edge.type,
                    isPIM: edge.isPIM || false,
                    isEscalationPath: edge.isEscalationPath || false
                };
            }));

            const cloneColor = (color) => color ? Object.assign({}, color) : null;
            const originalEdgeStyles = {};
            edges.get().forEach(edge => {
                originalEdgeStyles[edge.id] = {
                    color: cloneColor(edge.color),
                    width: edge.width,
                    dashes: edge.dashes || false
                };
            });

            const container = document.getElementById('escalationGraph');
            const data = { nodes: nodes, edges: edges };
            const originalNodePositions = {};
            const groupedNodeIds = new Set();
            const options = {
                nodes: {
                    borderWidth: 2,
                    size: 25,
                    font: { size: 14, color: textColor },
                    scaling: { min: 20, max: 40 }
                },
                edges: {
                    smooth: { type: 'continuous', roundness: 0.5 },
                    width: 2,
                    selectionWidth: 3,
                    chosen: false
                },
                physics: {
                    enabled: true,
                    barnesHut: {
                        gravitationalConstant: -20000,
                        centralGravity: 0.15,
                        springLength: 200,
                        springConstant: 0.015,
                        damping: 0.2,
                        avoidOverlap: 0.9
                    },
                    minVelocity: 0.75,
                    solver: 'barnesHut',
                    stabilization: { enabled: true, iterations: 400, updateInterval: 20 }
                },
                interaction: {
                    hover: true,
                    tooltipDelay: 100,
                    zoomView: true,
                    dragView: true,
                    navigationButtons: true
                },
                layout: {
                    improvedLayout: true,
                    hierarchical: { enabled: false }
                }
            };

            const defaultNodeSize = (options && options.nodes && options.nodes.size) ? options.nodes.size : 25;

            const network = new vis.Network(container, data, options);

            let initialViewPosition = null;
            let initialLayoutSettled = false;
            let gentleMotionAnimationFrame = null;
            let gentleMotionState = null;

            function startGentleMotion() {
                if (gentleMotionAnimationFrame !== null) {
                    return;
                }

                const nodeSnapshot = nodes.get();
                const basePositions = {};
                const nodePhases = {};
                const nodeFrequencies = {};
                const nodeAmplitudes = {};

                nodeSnapshot.forEach(node => {
                    const pos = network.getPosition(node.id) || { x: 0, y: 0 };
                    basePositions[node.id] = { x: pos.x, y: pos.y };
                    nodePhases[node.id] = {
                        x: Math.random() * Math.PI * 2,
                        y: Math.random() * Math.PI * 2
                    };
                    nodeFrequencies[node.id] = {
                        x: 0.5 + Math.random() * 0.3,
                        y: 0.4 + Math.random() * 0.35
                    };
                    nodeAmplitudes[node.id] = 22 + Math.random() * 18;
                });

                gentleMotionState = {
                    basePositions,
                    nodePhases,
                    nodeFrequencies,
                    nodeAmplitudes,
                    nodeIds: nodeSnapshot.map(n => n.id),
                    time: 0
                };

                let lastTimestamp = null;

                const animate = timestamp => {
                    if (!gentleMotionState) {
                        gentleMotionAnimationFrame = null;
                        return;
                    }

                    if (lastTimestamp === null) {
                        lastTimestamp = timestamp;
                    }

                    const deltaSeconds = Math.min((timestamp - lastTimestamp) / 1000, 0.05);
                    lastTimestamp = timestamp;
                    gentleMotionState.time += deltaSeconds * 0.9;

                    const updates = [];
                    gentleMotionState.nodeIds.forEach(nodeId => {
                        const basePos = gentleMotionState.basePositions[nodeId];
                        if (!basePos) {
                            return;
                        }

                        const currentNode = nodes.get(nodeId);
                        if (!currentNode || currentNode.hidden) {
                            return;
                        }

                        const phase = gentleMotionState.nodePhases[nodeId];
                        const freq = gentleMotionState.nodeFrequencies[nodeId];
                        const amplitude = gentleMotionState.nodeAmplitudes[nodeId];
                        const t = gentleMotionState.time;

                        const offsetX = Math.sin(t * freq.x + phase.x) * amplitude * 0.9 +
                                        Math.sin(t * freq.x * 0.4 + phase.x) * amplitude * 0.35;
                        const offsetY = Math.cos(t * freq.y + phase.y) * amplitude * 0.85 +
                                        Math.cos(t * freq.y * 0.55 + phase.y) * amplitude * 0.3;

                        updates.push({
                            id: nodeId,
                            x: basePos.x + offsetX,
                            y: basePos.y + offsetY
                        });
                    });

                    if (updates.length > 0) {
                        nodes.update(updates);
                    }

                    gentleMotionAnimationFrame = requestAnimationFrame(animate);
                };

                gentleMotionAnimationFrame = requestAnimationFrame(animate);
            }
            
            function stopGentleMotion() {
                if (gentleMotionAnimationFrame !== null) {
                    cancelAnimationFrame(gentleMotionAnimationFrame);
                    gentleMotionAnimationFrame = null;
                }
                gentleMotionState = null;
            }

            function finalizeInitialLayout() {
                if (initialLayoutSettled) {
                    return;
                }

                initialLayoutSettled = true;
                network.setOptions({ physics: false });
                network.fit();
                initialViewPosition = network.getViewPosition();

                const stabilizedPositions = network.getPositions(nodes.getIds());
                Object.keys(stabilizedPositions).forEach(nodeId => {
                    originalNodePositions[nodeId] = stabilizedPositions[nodeId];
                });
                
                // Start gentle motion after layout is stable
                setTimeout(() => {
                    startGentleMotion();
                }, 500);
            }

            network.once('stabilizationIterationsDone', finalizeInitialLayout);

            function applyGraphThemeStyles() {
                const updatedTextColor = getCssVar('--text-color', '#333');
                const updatedEdgeTextColor = getCssVar('--muted-text-color', '#666');
                const graphBg = getCssVar('--graph-bg', '#fafafa');
                const graphBorder = getCssVar('--border-color', '#ddd');
                container.style.background = graphBg;
                container.style.borderColor = graphBorder;
                const nodeFontUpdates = nodes.get().map(node => ({
                    id: node.id,
                    font: Object.assign({}, node.font, { color: updatedTextColor })
                }));
                const edgeFontUpdates = edges.get().map(edge => ({
                    id: edge.id,
                    font: Object.assign({}, edge.font, { color: updatedEdgeTextColor })
                }));
                nodes.update(nodeFontUpdates);
                edges.update(edgeFontUpdates);
                network.setOptions({
                    nodes: { font: { color: updatedTextColor } },
                    edges: { font: { color: updatedEdgeTextColor } }
                });
            }

            applyGraphThemeStyles();
            window.scEntraApplyGraphTheme = applyGraphThemeStyles;

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
            filteredNodes.forEach(node => {
                const hasIcon = Boolean(nodeIcons[node.type]);
                const baseColor = node.type === 'user' ? '#4CAF50' :
                                  node.type === 'group' ? '#2196F3' :
                                  node.type === 'role' ? '#FF5722' :
                                  node.type === 'servicePrincipal' ? '#9C27B0' :
                                  node.type === 'application' ? '#FF9800' : '#999';
                const datasetNode = nodes.get(node.id) || {};
                const baseSize = datasetNode.size || defaultNodeSize;
                originalNodeStyles[node.id] = {
                    hasIcon,
                    color: hasIcon ? null : {
                        background: baseColor,
                        border: '#333'
                    },
                    size: baseSize
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
                        const baseSize = baseStyle.size || defaultNodeSize;
                        const selectedSize = Math.round(baseSize * 2);
                        const update = {
                            id: node.id,
                            borderWidth: baseStyle.hasIcon ? (isSelected ? 4 : 0) : (isSelected ? 6 : 4),
                            font: { color: currentTextColor(), size: isSelected ? 18 : 16, bold: true },
                            hidden: false,
                            shadow: baseStyle.hasIcon && isSelected,
                            shadowColor: 'rgba(0,0,0,0.4)',
                            shadowSize: baseStyle.hasIcon && isSelected ? 12 : 0,
                            size: isSelected ? selectedSize : baseSize
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
                        const baseStyle = originalEdgeStyles[edge.id] || {};
                        const baseColor = cloneColor(baseStyle.color) || { color: '#999', opacity: 0.7 };
                        let highlightColor = Object.assign({}, baseColor, { opacity: 1 });
                        let edgeWidth = baseStyle.width ?? edge.width ?? 2;

                        if (edge.isEscalationPath) {
                            highlightColor = { color: escalationEdgeColor, opacity: escalationEdgeOpacity };
                            edgeWidth = Math.max(edgeWidth, escalationEdgeWidth);
                        } else if (edge.edgeType === 'has_role') {
                            edgeWidth = Math.max(edgeWidth, 3);
                        }

                        edgeUpdates.push({
                            id: edge.id,
                            width: edgeWidth,
                            color: highlightColor,
                            hidden: false,
                            dashes: baseStyle.dashes ?? edge.dashes ?? false
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

            function highlightNodeAndShowEscalation(nodeId) {
                if (!nodeId) {
                    return;
                }

                const nodeData = nodes.get(nodeId);
                if (!nodeData) {
                    return;
                }

                currentSelectedNode = originalNodeData[nodeId];

                const escalationFilterCheckbox = document.getElementById('escalationFilter');
                if (!escalationFilterCheckbox.checked) {
                    escalationFilterCheckbox.checked = true;
                }

                highlightEscalationPathFromNode(nodeId);
                detangleConnectedNodes(nodeId);

                document.getElementById('selectedNodeName').textContent = nodeData.label;
                document.getElementById('selectedNodeType').textContent = '(' + nodeData.type + ')';
                document.getElementById('selectedNodeInfo').style.display = 'block';

                network.focus(nodeId, {
                    scale: 1.5
                });
            }

            function ensureOriginalPositionSnapshot() {
                if (Object.keys(originalNodePositions).length > 0) {
                    return;
                }
                const fallbackPositions = network.getPositions(nodes.getIds());
                Object.keys(fallbackPositions).forEach(nodeId => {
                    originalNodePositions[nodeId] = fallbackPositions[nodeId];
                });
            }

            function restoreGroupedNodes() {
                if (groupedNodeIds.size === 0) {
                    return;
                }
                ensureOriginalPositionSnapshot();
                const updates = [];
                groupedNodeIds.forEach(nodeId => {
                    const originalPos = originalNodePositions[nodeId];
                    if (originalPos) {
                        updates.push({
                            id: nodeId,
                            x: originalPos.x,
                            y: originalPos.y,
                            fixed: false
                        });
                    } else {
                        updates.push({ id: nodeId, fixed: false });
                    }
                });
                if (updates.length > 0) {
                    nodes.update(updates);
                }
                groupedNodeIds.clear();
            }

            function groupMatchingNodes(matchingNodes) {
                if (!Array.isArray(matchingNodes) || matchingNodes.length < 2) {
                    restoreGroupedNodes();
                    return;
                }

                ensureOriginalPositionSnapshot();
                restoreGroupedNodes();

                const uniqueVisibleNodes = [];
                const seenIds = new Set();

                matchingNodes.forEach(candidate => {
                    const candidateId = candidate && candidate.id ? candidate.id : candidate;
                    if (!candidateId || seenIds.has(candidateId)) {
                        return;
                    }
                    const nodeData = nodes.get(candidateId);
                    if (!nodeData || nodeData.hidden) {
                        return;
                    }

                    const storedPosition = originalNodePositions[candidateId];
                    if (storedPosition) {
                        uniqueVisibleNodes.push({ id: candidateId, position: storedPosition });
                    } else {
                        const fallbackPositions = network.getPositions([candidateId]) || {};
                        const fallback = fallbackPositions[candidateId] || { x: nodeData.x || 0, y: nodeData.y || 0 };
                        uniqueVisibleNodes.push({ id: candidateId, position: fallback });
                    }
                    seenIds.add(candidateId);
                });

                if (uniqueVisibleNodes.length < 2) {
                    restoreGroupedNodes();
                    return;
                }

                const centroid = uniqueVisibleNodes.reduce((acc, node) => {
                    acc.x += node.position.x || 0;
                    acc.y += node.position.y || 0;
                    return acc;
                }, { x: 0, y: 0 });
                centroid.x /= uniqueVisibleNodes.length;
                centroid.y /= uniqueVisibleNodes.length;

                let minX = Infinity;
                let minY = Infinity;
                let maxX = -Infinity;
                let maxY = -Infinity;

                uniqueVisibleNodes.forEach(node => {
                    const { x, y } = node.position;
                    if (x < minX) minX = x;
                    if (x > maxX) maxX = x;
                    if (y < minY) minY = y;
                    if (y > maxY) maxY = y;
                });

                const spanX = Math.max(maxX - minX, 1);
                const spanY = Math.max(maxY - minY, 1);
                const maxSpan = Math.max(spanX, spanY);
                const targetSpan = Math.max(200, Math.min(uniqueVisibleNodes.length * 60, 540));
                const minScale = 0.65;
                const maxScale = 1.35;
                const spanRatio = targetSpan / Math.max(maxSpan, 1);
                const scale = Math.max(minScale, Math.min(maxScale, spanRatio));

                const usedBuckets = new Set();
                const bucketSize = 12;
                const jitterDistance = Math.max(22, Math.min(38, uniqueVisibleNodes.length * 3));
                const updates = uniqueVisibleNodes.map((node, idx) => {
                    const relX = node.position.x - centroid.x;
                    const relY = node.position.y - centroid.y;
                    let newX = centroid.x + relX * scale;
                    let newY = centroid.y + relY * scale;

                    const bucketKey = Math.round(newX / bucketSize) + ':' + Math.round(newY / bucketSize);
                    if (usedBuckets.has(bucketKey)) {
                        const angle = (idx / uniqueVisibleNodes.length) * 2 * Math.PI;
                        newX += Math.cos(angle) * jitterDistance;
                        newY += Math.sin(angle) * jitterDistance;
                    }
                    usedBuckets.add(bucketKey);

                    groupedNodeIds.add(node.id);
                    return {
                        id: node.id,
                        x: newX,
                        y: newY,
                        fixed: { x: true, y: true }
                    };
                });

                nodes.update(updates);

                const nodeIdsForFit = uniqueVisibleNodes.map(node => node.id);
                network.fit({
                    nodes: nodeIdsForFit,
                    animation: {
                        duration: 550,
                        easingFunction: 'easeInOutQuad'
                    },
                    maxZoomLevel: 2.4
                });
            }

            function resetHighlight() {
                selectedNodes.clear();
                restoreGroupedNodes();

                const updates = [];
                filteredNodes.forEach(node => {
                    const baseStyle = originalNodeStyles[node.id] || {};
                    const baseSize = baseStyle.size || defaultNodeSize;
                    const update = {
                        id: node.id,
                        borderWidth: baseStyle.hasIcon ? 0 : 2,
                        font: { color: currentTextColor(), size: 14 },
                        hidden: false,
                        shadow: false,
                        shadowSize: 0,
                        size: baseSize
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
                    const baseStyle = originalEdgeStyles[edge.id] || {};
                    const restoredColor = cloneColor(baseStyle.color) || { color: '#999', opacity: 0.7 };
                    edgeUpdates.push({
                        id: edge.id,
                        width: baseStyle.width ?? edge.width ?? 1.5,
                        color: restoredColor,
                        hidden: false,
                        dashes: baseStyle.dashes ?? edge.dashes ?? false
                    });
                });
                edges.update(edgeUpdates);

                document.getElementById('selectedNodeInfo').style.display = 'none';
                const riskRows = document.querySelectorAll('.risk-row');
                riskRows.forEach(row => { row.style.display = ''; });
                const riskMsg = document.getElementById('risk-filter-msg');
                if (riskMsg) riskMsg.remove();
            }

            function focusSelectedNodeOrFitAll() {
                if (currentSelectedNode && currentSelectedNode.id) {
                    const selectedId = currentSelectedNode.id;
                    
                    // Get all visible nodes connected to the selected node
                    const connectedEdges = network.getConnectedEdges(selectedId);
                    const relatedNodeIds = new Set([selectedId]);
                    
                    // Find all nodes connected by visible edges
                    connectedEdges.forEach(edgeId => {
                        const edge = edges.get(edgeId);
                        if (edge && !edge.hidden) {
                            relatedNodeIds.add(edge.from);
                            relatedNodeIds.add(edge.to);
                        }
                    });
                    
                    const nodesToFit = Array.from(relatedNodeIds).filter(nodeId => {
                        const node = nodes.get(nodeId);
                        return node && !node.hidden;
                    });

                    // Fit to include all related nodes (no focus, just fit)
                    network.fit({
                        nodes: nodesToFit
                    });
                } else {
                    network.fit();
                }
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
                    network.fit();
                }, 500);
            }

            function detangleConnectedNodes(centerNodeId) {
                if (!centerNodeId) {
                    return;
                }

                const neighborIds = network.getConnectedNodes(centerNodeId) || [];
                const visibleNeighbors = neighborIds.filter(id => {
                    const node = nodes.get(id);
                    return node && !node.hidden;
                });

                if (visibleNeighbors.length === 0) {
                    return;
                }

                const positions = network.getPositions([centerNodeId].concat(visibleNeighbors));
                const centerPosition = positions[centerNodeId];
                if (!centerPosition) {
                    return;
                }

                // Inspired by phyllotaxis patterns (golden angle) to minimize overlapping connectors
                const goldenAngle = Math.PI * (3 - Math.sqrt(5));
                const baseOrbit = 150;
                const orbitStep = 55;
                const updates = [];
                const noise = () => (Math.random() - 0.5) * 30;

                visibleNeighbors.forEach((neighborId, index) => {
                    const neighborNode = nodes.get(neighborId);
                    const typeModifier = (() => {
                        if (!neighborNode) return 1;
                        switch (neighborNode.type) {
                            case 'role':
                                return 1.25;
                            case 'servicePrincipal':
                            case 'application':
                                return 1.15;
                            case 'group':
                                return 1.05;
                            default:
                                return 1;
                        }
                    })();

                    const localDegree = (network.getConnectedEdges(neighborId) || []).length;
                    const degreeModifier = 1 + Math.min(localDegree, 8) * 0.04;
                    const spiralIndex = index + 1;
                    const angle = goldenAngle * spiralIndex;
                    const organicRadius = baseOrbit + Math.sqrt(spiralIndex) * orbitStep * typeModifier * degreeModifier;
                    const finalRadius = organicRadius + noise();

                    updates.push({
                        id: neighborId,
                        x: centerPosition.x + Math.cos(angle) * finalRadius,
                        y: centerPosition.y + Math.sin(angle) * finalRadius
                    });
                });

                if (updates.length > 0) {
                    nodes.update(updates);
                }
            }

            network.on('click', function(params) {
                // Stop gentle motion when user interacts
                stopGentleMotion();
                
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
                    
                    // Get connected nodes for fitting
                    const connectedEdges = network.getConnectedEdges(nodeId);
                    const relatedNodeIds = new Set([nodeId]);
                    
                    // Find all nodes connected by visible edges
                    connectedEdges.forEach(edgeId => {
                        const edge = edges.get(edgeId);
                        if (edge && !edge.hidden) {
                            relatedNodeIds.add(edge.from);
                            relatedNodeIds.add(edge.to);
                        }
                    });
                    
                    const nodesToFit = Array.from(relatedNodeIds).filter(id => {
                        const n = nodes.get(id);
                        return n && !n.hidden;
                    });

                    detangleConnectedNodes(nodeId);
                    
                    // Center on the clicked node and fit to screen
                    if (nodesToFit.length > 1) {
                        // Fit to show the selected node and related nodes
                        network.fit({
                            nodes: nodesToFit,
                            animation: {
                                duration: 500,
                                easingFunction: 'easeInOutQuad'
                            }
                        });
                    } else {
                        // If only one node (isolated), center it with appropriate zoom
                        network.focus(nodeId, {
                            scale: 1.5,
                            animation: {
                                duration: 500,
                                easingFunction: 'easeInOutQuad'
                            }
                        });
                    }
                }
            });

            function showNodeDetails(node) {
                if (!node || !node.type) {
                    console.error('Invalid node object:', node);
                    alert('Error: Invalid node data. Please try selecting the node again.');
                    return;
                }

                const modal = document.getElementById('nodeDetailsModal');
                const overlay = document.getElementById('modalOverlay');
                const modalTitle = document.getElementById('modalTitle');
                const modalContent = document.getElementById('modalContent');

                if (!modal || !overlay || !modalTitle || !modalContent) {
                    console.error('Modal elements not found!');
                    return;
                }

                modalTitle.textContent = node.label || node.id || 'Unknown';

                const typeColors = {
                    user: '#4CAF50',
                    group: '#2196F3',
                    role: '#FF5722',
                    servicePrincipal: '#9C27B0',
                    application: '#FF9800',
                    apiPermission: '#6A5ACD'
                };
                const typeColor = typeColors[node.type] || '#999';
                const isCriticalPathNode = criticalPathNodeIds.has(node.id);
                const statusChip = (text, cssClass) => '<span class="status-chip ' + cssClass + '">' + text + '</span>';
                const grantKindLabel = (kind) => {
                    if (!kind) { return ''; }
                    if (kind === 'Scope') { return 'Delegated'; }
                    if (kind === 'Role') { return 'Application'; }
                    if (kind === 'Mixed') { return 'Delegated + Application'; }
                    return kind;
                };

                let detailsHtml = '<div class="node-detail-body">';
                detailsHtml += '<div class="detail-badges">';
                detailsHtml += '<span class="detail-badge" style="background:' + typeColor + '; color:#fff; border-color: rgba(255,255,255,0.35);">' + node.type.toUpperCase() + '</span>';
                if (isCriticalPathNode) {
                    detailsHtml += '<span class="detail-badge critical-path-pill">Critical path node</span>';
                }
                detailsHtml += '</div>';

                if (isCriticalPathNode) {
                    detailsHtml += '<div class="detail-section critical-path-section">';
                    detailsHtml += '<h4>Critical Escalation Context</h4>';
                    detailsHtml += '<p>This entity participates in at least one modeled escalation route to a Tier-0 role. Enable the &ldquo;Show Only Critical Escalation Paths&rdquo; filter or select this node to trace the full path.</p>';
                    detailsHtml += '</div>';
                }

                detailsHtml += '<div class="detail-section">';
                detailsHtml += '<h4>Basic Information</h4>';
                detailsHtml += '<table class="detail-table">';

                if (node.id) {
                    detailsHtml += '<tr><td class="detail-label">ID</td><td class="detail-value code">' + node.id + '</td></tr>';
                }

                if (node.type === 'user') {
                    if (node.userPrincipalName) {
                        detailsHtml += '<tr><td class="detail-label">UPN</td><td class="detail-value">' + node.userPrincipalName + '</td></tr>';
                    }
                    if (node.accountEnabled !== undefined) {
                        const statusText = node.accountEnabled ? 'Enabled' : 'Disabled';
                        const statusClass = node.accountEnabled ? 'status-positive' : 'status-negative';
                        detailsHtml += '<tr><td class="detail-label">Account Status</td><td class="detail-value">' + statusChip(statusText, statusClass) + '</td></tr>';
                    }
                    if (node.mail) {
                        detailsHtml += '<tr><td class="detail-label">Email</td><td class="detail-value">' + node.mail + '</td></tr>';
                    }
                    if (node.userType) {
                        detailsHtml += '<tr><td class="detail-label">User Type</td><td class="detail-value">' + node.userType + '</td></tr>';
                    }
                    if (node.onPremisesSyncEnabled !== undefined) {
                        const text = node.onPremisesSyncEnabled ? 'Hybrid (synced from AD)' : 'Cloud only';
                        const css = node.onPremisesSyncEnabled ? 'status-info' : 'status-positive';
                        detailsHtml += '<tr><td class="detail-label">Source</td><td class="detail-value">' + statusChip(text, css) + '</td></tr>';
                    }
                    if (node.createdDateTime) {
                        const createdText = formatDetailTimestamp(node.createdDateTime);
                        if (createdText) {
                            detailsHtml += '<tr><td class="detail-label">Created On</td><td class="detail-value">' + createdText + '</td></tr>';
                        }
                    }
                    if (node.lastPasswordChangeDateTime) {
                        const pwdText = formatDetailTimestamp(node.lastPasswordChangeDateTime);
                        if (pwdText) {
                            detailsHtml += '<tr><td class="detail-label">Last Password Change</td><td class="detail-value">' + pwdText + '</td></tr>';
                        }
                    }
                } else if (node.type === 'group') {
                    if (node.isAssignableToRole !== undefined) {
                        const text = node.isAssignableToRole ? 'Assignable' : 'Not assignable';
                        const css = node.isAssignableToRole ? 'status-positive' : 'status-negative';
                        detailsHtml += '<tr><td class="detail-label">Role Assignable</td><td class="detail-value">' + statusChip(text, css) + '</td></tr>';
                    }
                    if (node.isPIMEnabled !== undefined) {
                        const text = node.isPIMEnabled ? 'PIM enabled' : 'PIM disabled';
                        const css = node.isPIMEnabled ? 'status-warning' : 'status-negative';
                        detailsHtml += '<tr><td class="detail-label">Privileged Identity Management</td><td class="detail-value">' + statusChip(text, css) + '</td></tr>';
                    }
                    if (node.securityEnabled !== undefined) {
                        const text = node.securityEnabled ? 'Security enabled' : 'Security disabled';
                        const css = node.securityEnabled ? 'status-info' : 'status-negative';
                        detailsHtml += '<tr><td class="detail-label">Security Group</td><td class="detail-value">' + statusChip(text, css) + '</td></tr>';
                    }
                    if (node.memberCount !== undefined) {
                        detailsHtml += '<tr><td class="detail-label">Member Count</td><td class="detail-value">' + node.memberCount + '</td></tr>';
                    }
                    if (node.description) {
                        detailsHtml += '<tr><td class="detail-label">Description</td><td class="detail-value">' + node.description + '</td></tr>';
                    }
                } else if (node.type === 'servicePrincipal' || node.type === 'application') {
                    if (node.appId) {
                        detailsHtml += '<tr><td class="detail-label">App ID</td><td class="detail-value code">' + node.appId + '</td></tr>';
                    }
                    if (node.accountEnabled !== undefined) {
                        const statusText = node.accountEnabled ? 'Enabled' : 'Disabled';
                        const statusClass = node.accountEnabled ? 'status-positive' : 'status-negative';
                        detailsHtml += '<tr><td class="detail-label">Service Status</td><td class="detail-value">' + statusChip(statusText, statusClass) + '</td></tr>';
                    }
                } else if (node.type === 'apiPermission') {
                    if (node.resource) {
                        detailsHtml += '<tr><td class="detail-label">Resource</td><td class="detail-value">' + node.resource + '</td></tr>';
                    }
                    if (node.permissionValue) {
                        detailsHtml += '<tr><td class="detail-label">Permission</td><td class="detail-value code">' + node.permissionValue + '</td></tr>';
                    }
                    if (node.permissionDisplayName && node.permissionDisplayName !== node.permissionValue) {
                        detailsHtml += '<tr><td class="detail-label">Display Text</td><td class="detail-value">' + node.permissionDisplayName + '</td></tr>';
                    }
                    const resolvedGrantSummary = (() => {
                        const rawKinds = Array.isArray(node.grantTypes) && node.grantTypes.length ? node.grantTypes : null;
                        if (rawKinds) {
                            const uniqueKinds = Array.from(new Set(rawKinds));
                            return uniqueKinds.map(grantKindLabel).join(' + ');
                        }
                        if (node.permissionKind) {
                            return grantKindLabel(node.permissionKind);
                        }
                        return '';
                    })();
                    if (resolvedGrantSummary) {
                        detailsHtml += '<tr><td class="detail-label">Grant Type</td><td class="detail-value">' + resolvedGrantSummary + '</td></tr>';
                    }
                    if (node.permissionAudience) {
                        detailsHtml += '<tr><td class="detail-label">Audience</td><td class="detail-value">' + node.permissionAudience + '</td></tr>';
                    }
                    if (node.adminConsentRequired) {
                        detailsHtml += '<tr><td class="detail-label">Admin Consent</td><td class="detail-value">' + node.adminConsentRequired + '</td></tr>';
                    }
                    if (node.severity) {
                        detailsHtml += '<tr><td class="detail-label">Severity</td><td class="detail-value">' + node.severity + '</td></tr>';
                    }
                } else if (node.type === 'role') {
                    if (node.isPrivileged !== undefined) {
                        const text = node.isPrivileged ? 'Privileged role' : 'Standard role';
                        const css = node.isPrivileged ? 'status-warning' : 'status-info';
                        detailsHtml += '<tr><td class="detail-label">Privileged</td><td class="detail-value">' + statusChip(text, css) + '</td></tr>';
                    }
                    if (node.roleIsBuiltIn !== undefined) {
                        const text = node.roleIsBuiltIn ? 'Built-in role' : 'Custom role';
                        const css = node.roleIsBuiltIn ? 'status-info' : 'status-warning';
                        detailsHtml += '<tr><td class="detail-label">Origin</td><td class="detail-value">' + statusChip(text, css) + '</td></tr>';
                    }
                    if (node.roleIsEnabled !== undefined) {
                        const text = node.roleIsEnabled ? 'Enabled' : 'Disabled';
                        const css = node.roleIsEnabled ? 'status-positive' : 'status-negative';
                        detailsHtml += '<tr><td class="detail-label">Status</td><td class="detail-value">' + statusChip(text, css) + '</td></tr>';
                    }
                    if (node.description) {
                        detailsHtml += '<tr><td class="detail-label">Description</td><td class="detail-value">' + node.description + '</td></tr>';
                    }
                    if (node.roleTemplateId) {
                        detailsHtml += '<tr><td class="detail-label">Role Template</td><td class="detail-value code">' + node.roleTemplateId + '</td></tr>';
                    }
                    if (node.roleDefinitionId) {
                        detailsHtml += '<tr><td class="detail-label">Role Definition</td><td class="detail-value code">' + node.roleDefinitionId + '</td></tr>';
                    }
                    if (Array.isArray(node.roleResourceScopes) && node.roleResourceScopes.length > 0) {
                        const scopeEntries = node.roleResourceScopes.filter(scope => scope);
                        if (scopeEntries.length > 0) {
                            const scopeHtml = scopeEntries.map(scope => '<div>' + scope + '</div>').join('');
                            detailsHtml += '<tr><td class="detail-label">Resource Scopes</td><td class="detail-value code">' + scopeHtml + '</td></tr>';
                        }
                    }
                    if (typeof node.roleAllowedActionsCount === 'number' && node.roleAllowedActionsCount > 0) {
                        detailsHtml += '<tr><td class="detail-label">Allowed Actions</td><td class="detail-value">' + node.roleAllowedActionsCount + '</td></tr>';
                    }
                }

                detailsHtml += '</table></div>';

                if (node.type === 'apiPermission' && (node.permissionDescription || node.escalationDescription)) {
                    detailsHtml += '<div class="detail-section">';
                    detailsHtml += '<h4>Permission Details</h4>';
                    if (node.permissionDescription) {
                        detailsHtml += '<p style="margin-bottom: 10px;">' + node.permissionDescription + '</p>';
                    }
                    if (node.escalationDescription) {
                        detailsHtml += '<div class="permission-callout">';
                        detailsHtml += '<strong style="display:block; margin-bottom:4px;">Escalation Impact</strong>' + node.escalationDescription;
                        detailsHtml += '</div>';
                    }
                    detailsHtml += '</div>';
                }

                if (node.type === 'role' && Array.isArray(node.roleAllowedActions) && node.roleAllowedActions.length > 0) {
                    const allowedActions = node.roleAllowedActions.filter(action => action);
                    if (allowedActions.length > 0) {
                        const maxActionsToShow = 20;
                        detailsHtml += '<div class="detail-section">';
                        detailsHtml += '<h4>Allowed Resource Actions</h4>';
                        detailsHtml += '<ul class="detail-code-list">';
                        allowedActions.slice(0, maxActionsToShow).forEach(action => {
                            detailsHtml += '<li>' + action + '</li>';
                        });
                        if (allowedActions.length > maxActionsToShow) {
                            const remaining = allowedActions.length - maxActionsToShow;
                            detailsHtml += '<li class="detail-more">+' + remaining + ' additional actions</li>';
                        }
                        detailsHtml += '</ul>';
                        detailsHtml += '</div>';
                    }
                }

                const connectedEdges = network.getConnectedEdges(node.id);
                const connectedNodes = network.getConnectedNodes(node.id);

                detailsHtml += '<div class="detail-section">';
                detailsHtml += '<h4>Connections</h4>';
                detailsHtml += '<div class="detail-grid">';
                detailsHtml += '<div class="detail-stat"><div class="detail-stat-value">' + connectedEdges.length + '</div><div class="detail-stat-label">Relationships</div></div>';
                detailsHtml += '<div class="detail-stat"><div class="detail-stat-value">' + connectedNodes.length + '</div><div class="detail-stat-label">Connected Nodes</div></div>';
                detailsHtml += '</div></div>';

                if (connectedEdges.length > 0) {
                    const edgeTypes = {};
                    connectedEdges.forEach(edgeId => {
                        const edge = edges.get(edgeId);
                        if (edge) {
                            const label = edge.label || edge.type || 'Unknown';
                            edgeTypes[label] = (edgeTypes[label] || 0) + 1;
                        }
                    });

                    detailsHtml += '<div class="detail-section">';
                    detailsHtml += '<h4>Relationship Breakdown</h4>';

                    for (const [label, count] of Object.entries(edgeTypes).sort((a, b) => b[1] - a[1])) {
                        const percentage = Math.round((count / connectedEdges.length) * 100);
                        detailsHtml += '<div class="detail-breakdown-item">';
                        detailsHtml += '<div class="detail-breakdown-row"><span>' + label + '</span><span class="detail-breakdown-value">' + count + '</span></div>';
                        detailsHtml += '<div class="detail-progress"><div class="detail-progress-bar" style="width: ' + percentage + '%;"></div></div>';
                        detailsHtml += '</div>';
                    }

                    detailsHtml += '</div>';
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
                        const baseSize = baseStyle.size || defaultNodeSize;
                        const update = {
                            id: node.id,
                            borderWidth: baseStyle.hasIcon ? 0 : 4,
                            font: { color: currentTextColor(), size: 16 },
                            hidden: false,
                            shadow: false,
                            shadowSize: 0,
                            size: baseSize
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
                        const baseStyle = originalEdgeStyles[edge.id] || {};
                        let color = cloneColor(baseStyle.color) || { color: '#999', opacity: 0.7 };
                        let width = baseStyle.width ?? edge.width ?? 1.5;

                        if (edge.isEscalationPath) {
                            color = { color: escalationEdgeColor, opacity: escalationEdgeOpacity };
                            width = Math.max(width, escalationEdgeWidth);
                        }

                        edgeUpdates.push({
                            id: edge.id,
                            hidden: false,
                            color,
                            width,
                            dashes: baseStyle.dashes ?? edge.dashes ?? false
                        });
                    } else {
                        edgeUpdates.push({ id: edge.id, hidden: true });
                    }
                });
                edges.update(edgeUpdates);
            }

            function focusOnSearchMatch(candidates, normalizedSearchTerm) {
                if (!Array.isArray(candidates) || candidates.length === 0) {
                    return;
                }

                const sanitizedTerm = (normalizedSearchTerm || '').trim();
                let target = null;

                if (sanitizedTerm.length > 0) {
                    const lowerTerm = sanitizedTerm.toLowerCase();
                    target = candidates.find(node => (node.label || '').toLowerCase() === lowerTerm) ||
                             candidates.find(node => (node.label || '').toLowerCase().startsWith(lowerTerm)) ||
                             candidates.find(node => (node.label || '').toLowerCase().includes(lowerTerm));
                }

                if (!target) {
                    target = candidates[0];
                }

                if (target && target.id) {
                    network.focus(target.id, {
                        scale: candidates.length === 1 ? 1.5 : 1.25
                    });
                }
            }

            function applyFilters() {
                // Stop gentle motion when user applies filters
                stopGentleMotion();
                
                const rawSearchValue = document.getElementById('nodeFilter').value || '';
                const normalizedSearchTerm = rawSearchValue.trim().toLowerCase();
                const hasSearchTerm = normalizedSearchTerm.length > 0;
                const typeFilter = document.getElementById('typeFilter').value;
                const assignmentFilter = document.getElementById('assignmentFilter').value;
                const escalationFilter = document.getElementById('escalationFilter').checked;
                const shouldGroupMatches = hasSearchTerm;

                if (!shouldGroupMatches) {
                    restoreGroupedNodes();
                }

                // If escalation filter is enabled, show only escalation paths
                if (escalationFilter) {
                    const hasSelectedNode = currentSelectedNode && currentSelectedNode.id;
                    const noAdditionalFilters = !hasSearchTerm && !typeFilter && !assignmentFilter;

                    if (hasSelectedNode && noAdditionalFilters) {
                        highlightEscalationPathFromNode(currentSelectedNode.id);
                        document.getElementById('selectedNodeName').textContent = currentSelectedNode.label;
                        document.getElementById('selectedNodeType').textContent = '(' + currentSelectedNode.type + ')';
                        document.getElementById('selectedNodeInfo').style.display = 'block';
                        restoreGroupedNodes();
                        return;
                    }

                    const allEdges = edges.get();
                    const edgeUpdates = [];
                    const escalationNodeIds = new Set();
                    const escalationEdgeIds = new Set();

                    allEdges.forEach(edge => {
                        if (edge.isEscalationPath) {
                            const baseStyle = originalEdgeStyles[edge.id] || {};
                            escalationNodeIds.add(edge.from);
                            escalationNodeIds.add(edge.to);
                            escalationEdgeIds.add(edge.id);
                            edgeUpdates.push({
                                id: edge.id,
                                hidden: false,
                                color: { color: escalationEdgeColor, opacity: escalationEdgeOpacity },
                                width: Math.max(baseStyle.width ?? edge.width ?? 1.5, escalationEdgeWidth),
                                dashes: baseStyle.dashes ?? edge.dashes ?? false
                            });
                        } else {
                            edgeUpdates.push({ id: edge.id, hidden: true });
                        }
                    });
                    edges.update(edgeUpdates);

                    const matchingNodes = graphNodes.filter(node => {
                        const matchesSearch = !normalizedSearchTerm || node.label.toLowerCase().includes(normalizedSearchTerm);
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
                            scale: 1.5
                        });
                        if (shouldGroupMatches) {
                            groupMatchingNodes(matchingNodes);
                        }
                        return;
                    }

                    const nodeUpdates = [];
                    const allNodes = nodes.get();
                    const matchingIds = new Set(matchingNodes.map(n => n.id));

                    allNodes.forEach(node => {
                        if (matchingIds.has(node.id)) {
                            const baseStyle = originalNodeStyles[node.id] || {};
                            const baseSize = baseStyle.size || defaultNodeSize;
                            const update = {
                                id: node.id,
                                borderWidth: baseStyle.hasIcon ? 0 : 4,
                                font: { color: currentTextColor(), size: 16 },
                                hidden: false,
                                shadow: false,
                                shadowSize: 0,
                                size: baseSize
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
                    if (shouldGroupMatches) {
                        groupMatchingNodes(matchingNodes);
                    }
                    if (hasSearchTerm && matchingNodes.length > 0) {
                        focusOnSearchMatch(matchingNodes, normalizedSearchTerm);
                    }
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
                        const matchesSearch = !normalizedSearchTerm || node.label.toLowerCase().includes(normalizedSearchTerm);
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
                            const baseSize = baseStyle.size || defaultNodeSize;
                            const update = {
                                id: node.id,
                                borderWidth: baseStyle.hasIcon ? 0 : 4,
                                font: { color: currentTextColor(), size: 16 },
                                hidden: false,
                                shadow: false,
                                shadowSize: 0,
                                size: baseSize
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
                    if (shouldGroupMatches) {
                        groupMatchingNodes(matchingNodes);
                    }
                    if (hasSearchTerm && matchingNodes.length > 0) {
                        focusOnSearchMatch(matchingNodes, normalizedSearchTerm);
                    }

                } else {
                    const matchingNodes = graphNodes.filter(node => {
                        const matchesSearch = !normalizedSearchTerm || node.label.toLowerCase().includes(normalizedSearchTerm);
                        const matchesType = !typeFilter || node.type === typeFilter;
                        return matchesSearch && matchesType;
                    });

                    if (matchingNodes.length === 1) {
                        network.selectNodes([matchingNodes[0].id]);
                        network.focus(matchingNodes[0].id, {
                            scale: 1.5
                        });
                        highlightPath(matchingNodes[0].id);
                        if (shouldGroupMatches) {
                            groupMatchingNodes(matchingNodes);
                        }
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
                                const baseSize = baseStyle.size || defaultNodeSize;
                                const update = {
                                    id: node.id,
                                    borderWidth: baseStyle.hasIcon ? 0 : 4,
                                    font: { color: currentTextColor(), size: 16 },
                                    hidden: false,
                                    shadow: false,
                                    shadowSize: 0,
                                    size: baseSize
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
                        if (shouldGroupMatches) {
                            groupMatchingNodes(matchingNodes);
                        }
                        if (hasSearchTerm) {
                            focusOnSearchMatch(matchingNodes, normalizedSearchTerm);
                        }
                    } else if (hasSearchTerm || typeFilter) {
                        const updates = [];
                        const allNodes = nodes.get();
                        allNodes.forEach(node => {
                            updates.push({ id: node.id, hidden: true });
                        });
                        nodes.update(updates);
                        if (shouldGroupMatches) {
                            groupMatchingNodes([]);
                        }
                    } else {
                        resetHighlight();
                    }
                }
            }

            function setupZoomExtendsButton() {
                const zoomButton = container.querySelector('.vis-button.vis-zoomExtends');
                if (!zoomButton) {
                    requestAnimationFrame(setupZoomExtendsButton);
                    return;
                }

                if (zoomButton.dataset.customZoomHandler === 'true') {
                    return;
                }

                zoomButton.dataset.customZoomHandler = 'true';
                zoomButton.title = 'Fit view to selected node and related nodes';
                
                // Remove default click handlers
                const newButton = zoomButton.cloneNode(true);
                zoomButton.parentNode.replaceChild(newButton, zoomButton);
                
                newButton.addEventListener('click', event => {
                    event.preventDefault();
                    event.stopPropagation();
                    focusSelectedNodeOrFitAll();
                    return false;
                });
            }

            document.getElementById('nodeFilter').addEventListener('input', applyFilters);
            document.getElementById('typeFilter').addEventListener('change', applyFilters);
            document.getElementById('assignmentFilter').addEventListener('change', applyFilters);
            document.getElementById('escalationFilter').addEventListener('change', applyFilters);

            const graphContainer = document.getElementById('escalationGraph');
            let fullscreenButtonRef = null;
            let fullscreenNavObserver = null;

            const updateFullscreenUI = () => {
                if (!fullscreenButtonRef) {
                    return;
                }

                const isFullscreen = document.fullscreenElement === graphContainer;
                fullscreenButtonRef.setAttribute('data-active', isFullscreen ? 'true' : 'false');
                fullscreenButtonRef.setAttribute('aria-pressed', isFullscreen.toString());
            };

            const requestContainerFullscreen = async () => {
                if (!graphContainer) {
                    throw new Error('Graph container is not available.');
                }

                if (graphContainer.requestFullscreen) {
                    await graphContainer.requestFullscreen();
                }
                else if (graphContainer.webkitRequestFullscreen) { // Safari
                    graphContainer.webkitRequestFullscreen();
                }
                else {
                    throw new Error('Fullscreen API is not supported in this browser.');
                }
            };

            const exitFullscreen = async () => {
                if (document.exitFullscreen) {
                    await document.exitFullscreen();
                }
                else if (document.webkitExitFullscreen) {
                    await document.webkitExitFullscreen();
                }
            };

            const toggleFullscreen = async () => {
                try {
                    if (document.fullscreenElement === graphContainer) {
                        await exitFullscreen();
                    }
                    else if (!document.fullscreenElement) {
                        await requestContainerFullscreen();
                    }
                    else {
                        await exitFullscreen();
                        await requestContainerFullscreen();
                    }
                }
                catch (err) {
                    console.error('Failed to toggle fullscreen mode:', err);
                }
            };

            const positionFullscreenButton = () => {
                if (!fullscreenButtonRef) {
                    return;
                }

                const navContainer = container.querySelector('div.vis-navigation');
                const navButtons = navContainer ? Array.from(navContainer.querySelectorAll('.vis-button')) : [];
                const otherButtons = navButtons.filter(btn => btn !== fullscreenButtonRef);
                const navGap = 6;
                const buttonHeight = fullscreenButtonRef.offsetHeight || 34;
                let referenceLeft = 10;
                let referenceTop = 10 + buttonHeight + navGap;

                const computeOffsets = btn => {
                    if (!btn) {
                        return null;
                    }
                    if (typeof btn.offsetTop === 'number' && typeof btn.offsetLeft === 'number') {
                        return { top: btn.offsetTop, left: btn.offsetLeft };
                    }
                    const inlineTop = parseFloat(btn.style.top || '0') || 0;
                    const inlineLeft = parseFloat(btn.style.left || '0') || 0;
                    return { top: inlineTop, left: inlineLeft };
                };

                if (otherButtons.length > 0) {
                    referenceLeft = otherButtons.reduce((minLeft, btn) => {
                        const offsets = computeOffsets(btn);
                        if (!offsets) {
                            return minLeft;
                        }
                        return Math.min(minLeft, offsets.left);
                    }, referenceLeft);

                    referenceTop = otherButtons.reduce((minTop, btn) => {
                        const offsets = computeOffsets(btn);
                        if (!offsets) {
                            return minTop;
                        }
                        return Math.min(minTop, offsets.top);
                    }, referenceTop);
                }

                const fullscreenTop = Math.max(navGap, referenceTop - buttonHeight - navGap);
                const fullscreenLeft = Math.max(navGap, referenceLeft);

                fullscreenButtonRef.style.position = 'absolute';
                fullscreenButtonRef.style.top = fullscreenTop + 'px';
                fullscreenButtonRef.style.left = fullscreenLeft + 'px';
            };

            const ensureFullscreenButton = () => {
                if (!graphContainer) {
                    return;
                }

                const navContainer = container.querySelector('div.vis-navigation');
                if (!navContainer) {
                    return;
                }

                const zoomExtendsButton = navContainer.querySelector('.vis-button.vis-zoomExtends');

                if (fullscreenButtonRef && navContainer.contains(fullscreenButtonRef)) {
                    positionFullscreenButton();
                    return;
                }

                fullscreenButtonRef = document.createElement('div');
                fullscreenButtonRef.id = 'toggleFullscreen';
                fullscreenButtonRef.className = 'vis-button vis-fullscreen';
                fullscreenButtonRef.setAttribute('role', 'button');
                fullscreenButtonRef.setAttribute('tabindex', '0');
                fullscreenButtonRef.setAttribute('aria-pressed', 'false');
                fullscreenButtonRef.setAttribute('aria-label', 'Toggle fullscreen view');
                fullscreenButtonRef.title = 'Toggle fullscreen';
                fullscreenButtonRef.style.minWidth = '34px';
                fullscreenButtonRef.style.minHeight = '34px';

                const fullscreenIcon = document.createElement('span');
                fullscreenIcon.className = 'vis-button-icon';
                fullscreenIcon.setAttribute('aria-hidden', 'true');
                fullscreenIcon.textContent = '⤢';
                fullscreenButtonRef.appendChild(fullscreenIcon);

                fullscreenButtonRef.addEventListener('click', async event => {
                    event.preventDefault();
                    await toggleFullscreen();
                });

                fullscreenButtonRef.addEventListener('keydown', async event => {
                    if (event.key === 'Enter' || event.key === ' ') {
                        event.preventDefault();
                        await toggleFullscreen();
                    }
                });

                if (zoomExtendsButton && zoomExtendsButton.parentNode === navContainer) {
                    zoomExtendsButton.insertAdjacentElement('afterend', fullscreenButtonRef);
                }
                else {
                    navContainer.appendChild(fullscreenButtonRef);
                }

                positionFullscreenButton();
                updateFullscreenUI();
            };

            function setupFullscreenButton() {
                if (!graphContainer) {
                    return;
                }

                const navContainer = container.querySelector('div.vis-navigation');
                if (!navContainer) {
                    requestAnimationFrame(setupFullscreenButton);
                    return;
                }

                ensureFullscreenButton();

                if (!fullscreenNavObserver) {
                    fullscreenNavObserver = new MutationObserver(() => {
                        ensureFullscreenButton();
                    });
                    fullscreenNavObserver.observe(container, {
                        childList: true,
                        subtree: true
                    });
                }
            }

            setupZoomExtendsButton();
            setupFullscreenButton();

            document.addEventListener('fullscreenchange', () => {
                updateFullscreenUI();
                if (document.fullscreenElement === graphContainer) {
                    setTimeout(() => {
                        try {
                            network.fit({ animation: false });
                        }
                        catch (err) {
                            console.debug('Unable to refit network after entering fullscreen:', err);
                        }
                    }, 150);
                }
            });

            // Wait for DOM to be fully loaded before attaching risk row listeners
            function attachRiskRowListeners() {
                const riskRows = document.querySelectorAll('.risk-row');
                if (riskRows.length === 0) {
                    // Risk table might not be rendered yet, try again
                    setTimeout(attachRiskRowListeners, 100);
                    return;
                }
                
                riskRows.forEach(row => {
                    row.addEventListener('click', () => {
                        const primaryEntityId = row.getAttribute('data-primary-entity-id');
                        const hasIds = row.getAttribute('data-entity-ids');
                        const allIds = hasIds ? hasIds.split(',').map(id => id.trim()).filter(Boolean) : [];
                        const targetId = primaryEntityId || allIds[0];
                        if (!targetId) {
                            return;
                        }

                        highlightNodeAndShowEscalation(targetId);
                    });
                });
            }
            
            // Attach listeners after a short delay to ensure table is rendered
            setTimeout(attachRiskRowListeners, 200);

            document.getElementById('resetGraph').addEventListener('click', function() {
                document.getElementById('nodeFilter').value = '';
                document.getElementById('typeFilter').value = '';
                document.getElementById('assignmentFilter').value = '';
                document.getElementById('escalationFilter').checked = false;
                resetHighlight();
                network.fit();
                
                // Restart gentle motion after a brief delay
                setTimeout(() => {
                    startGentleMotion();
                }, 300);
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

        $primaryEntityId = if ($entityIds.Count -gt 0) { $entityIds[0] } else { '' }
        [void]$rowsBuilder.AppendLine(@"
                    <tr data-entity-ids="$entityIdsAttr" data-primary-entity-id="$primaryEntityId" class="risk-row">
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
        :root {
            --body-bg: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --text-color: #222c3c;
            --muted-text-color: #4a5568;
            --container-bg: #ffffff;
            --header-bg: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --card-bg: #ffffff;
            --card-shadow: rgba(0,0,0,0.1);
            --section-bg: #f8f9fa;
            --accent-color: #667eea;
            --table-header-bg: #667eea;
            --table-row-hover: #f8f9fa;
            --badge-medium-text: #333;
            --graph-bg: #f5f5fb;
            --legend-bg: #f0f2f8;
            --control-btn-bg: #667eea;
            --control-btn-bg-hover: #5568d3;
            --footer-bg: #2c3e50;
            --border-color: #d9dce3;
            --info-panel-bg: #f8f9fa;
            --info-panel-hover-bg: #e8eaf6;
            --info-panel-border: #667eea;
            --info-panel-hover-border: #5e6ad2;
        }

        body[data-theme="dark"] {
            --body-bg: linear-gradient(135deg, #0f172a 0%, #1e293b 100%);
            --text-color: #e2e8f0;
            --muted-text-color: #a5b4fc;
            --container-bg: #0f172a;
            --header-bg: linear-gradient(135deg, #1e40af 0%, #312e81 100%);
            --card-bg: #1f2937;
            --card-shadow: rgba(0,0,0,0.55);
            --section-bg: #111827;
            --accent-color: #a5b4fc;
            --table-header-bg: #334155;
            --table-row-hover: rgba(255,255,255,0.04);
            --badge-medium-text: #1f2933;
            --graph-bg: #111827;
            --legend-bg: #182033;
            --control-btn-bg: #4c51bf;
            --control-btn-bg-hover: #4338ca;
            --footer-bg: #0b1220;
            --border-color: #374151;
            --info-panel-bg: #1f2937;
            --info-panel-hover-bg: #273349;
            --info-panel-border: #818cf8;
            --info-panel-hover-border: #a5b4fc;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: var(--body-bg);
            padding: 20px;
            color: var(--text-color);
            transition: background 0.4s ease, color 0.2s ease;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            background: var(--container-bg);
            border-radius: 10px;
            box-shadow: 0 10px 40px rgba(0,0,0,0.2);
            overflow: hidden;
        }
        header {
            background: var(--header-bg);
            color: white;
            padding: 40px;
        }
        .header-top {
            display: flex;
            flex-wrap: wrap;
            align-items: center;
            justify-content: space-between;
            gap: 20px;
        }
        header h1 { font-size: 2.5em; }
        header p { font-size: 1.1em; opacity: 0.9; margin-top: 10px; }
        .theme-toggle {
            padding: 10px 18px;
            border: 2px solid rgba(255,255,255,0.4);
            border-radius: 999px;
            background: transparent;
            color: white;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.2s ease, color 0.2s ease;
        }
        .theme-toggle:hover {
            background: rgba(255,255,255,0.15);
        }
        body[data-theme="dark"] .theme-toggle {
            border-color: rgba(255,255,255,0.6);
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            padding: 40px;
            background: var(--section-bg);
        }
        .stat-card {
            background: var(--card-bg);
            padding: 25px;
            border-radius: 8px;
            box-shadow: 0 2px 14px var(--card-shadow);
            transition: transform 0.3s, box-shadow 0.3s;
        }
        .stat-card:hover {
            transform: translateY(-4px);
            box-shadow: 0 10px 25px rgba(0,0,0,0.2);
        }
        .stat-card h3 {
            color: var(--accent-color);
            font-size: 0.9em;
            text-transform: uppercase;
            margin-bottom: 10px;
            font-weight: 600;
        }
        .stat-card .number { font-size: 2.5em; font-weight: bold; color: var(--text-color); }
        .stat-card.warning .number { color: #ff6b6b; }
        body[data-theme="dark"] .stat-card.warning .number { color: #fca5a5; }
        .section { padding: 40px; background: var(--container-bg); }
        .section h2 {
            color: var(--accent-color);
            margin-bottom: 20px;
            font-size: 1.8em;
            border-bottom: 3px solid var(--accent-color);
            padding-bottom: 10px;
        }
        .chart-container {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 30px;
            margin-top: 20px;
        }
        .chart-box {
            background: var(--card-bg);
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 12px var(--card-shadow);
        }
        .chart-box h3 { color: var(--text-color); margin-bottom: 15px; text-align: center; }
        .button-primary {
            padding: 10px 16px;
            background: var(--control-btn-bg);
            color: #fff;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 600;
            transition: background 0.2s ease, transform 0.1s ease;
        }
        .button-primary:hover { background: var(--control-btn-bg-hover); }
        .button-primary:active { transform: scale(0.97); }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
            background: var(--card-bg);
            box-shadow: 0 2px 10px var(--card-shadow);
            border-radius: 8px;
            overflow: hidden;
            color: var(--text-color);
        }
        th {
            background: var(--table-header-bg);
            color: white;
            padding: 15px;
            text-align: left;
            font-weight: 600;
        }
        td { padding: 12px 15px; border-bottom: 1px solid var(--border-color); }
        tr:hover { background: var(--table-row-hover); }
        .risk-row { cursor: pointer; }
        .risk-row:hover { background: var(--table-row-hover); }
        .severity-high { color: #f87171; font-weight: bold; }
        .severity-medium { color: #fbbf24; font-weight: bold; }
        .severity-low { color: #34d399; font-weight: bold; }
        footer {
            background: var(--footer-bg);
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
        .badge-medium { background: #ffc107; color: var(--badge-medium-text); }
        .badge-low { background: #28a745; color: white; }
        #escalationGraph {
            width: 100%;
            height: 800px;
            border: 1px solid var(--border-color);
            border-radius: 8px;
            background: var(--graph-bg);
            transition: background 0.3s ease;
        }
        #selectedNodeInfo {
            display: none;
            margin-bottom: 15px;
            padding: 12px;
            background: var(--info-panel-bg);
            border-left: 4px solid var(--info-panel-border);
            border-radius: 4px;
            cursor: pointer;
            transition: background 0.2s ease, border-color 0.2s ease;
            color: var(--text-color);
        }
        #selectedNodeInfo:hover {
            background: var(--info-panel-hover-bg);
            border-left-color: var(--info-panel-hover-border);
        }
        .graph-legend {
            display: flex;
            flex-wrap: wrap;
            gap: 20px;
            margin-top: 20px;
            padding: 15px;
            background: var(--legend-bg);
            border-radius: 8px;
            border: 1px solid var(--border-color);
        }
        .graph-button-group {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        .graph-button-group .button-primary {
            white-space: nowrap;
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
            background: var(--control-btn-bg);
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 16px;
            font-weight: 600;
            transition: background 0.2s, transform 0.1s;
        }
        .control-btn:hover { background: var(--control-btn-bg-hover); }
        .control-btn:active { transform: scale(0.96); }
        .legend-item { display: flex; align-items: center; gap: 8px; color: var(--text-color); }
        .legend-icon { width: 22px; height: 22px; }
        .legend-line {
            width: 32px;
            height: 4px;
            border-radius: 999px;
            display: inline-block;
        }
        .node-details-modal,
        .modal-overlay {
            display: none;
        }
        .node-details-modal {
            position: fixed;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            background: var(--card-bg);
            color: var(--text-color);
            padding: 0;
            border-radius: 12px;
            box-shadow: 0 25px 60px rgba(15,23,42,0.45);
            z-index: 1000;
            max-width: 620px;
            width: 90%;
            max-height: 85vh;
            overflow: hidden;
            border: 1px solid var(--border-color);
            transition: background 0.3s ease, color 0.3s ease;
        }
        .modal-header {
            background: var(--header-bg);
            color: white;
            padding: 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 10px;
        }
        .modal-header h3 {
            margin: 0;
            font-size: 1.3em;
        }
        .modal-close {
            background: rgba(255,255,255,0.2);
            border: none;
            color: white;
            font-size: 24px;
            cursor: pointer;
            width: 36px;
            height: 36px;
            border-radius: 6px;
            display: flex;
            align-items: center;
            justify-content: center;
            transition: background 0.2s ease;
        }
        .modal-close:hover {
            background: rgba(255,255,255,0.35);
        }
        body[data-theme="dark"] .modal-close {
            background: rgba(255,255,255,0.15);
        }
        .modal-body {
            padding: 20px;
            overflow-y: auto;
            max-height: calc(85vh - 80px);
            background: var(--card-bg);
        }
        .modal-overlay {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(15,23,42,0.65);
            z-index: 999;
        }
        .node-detail-body {
            display: flex;
            flex-direction: column;
            gap: 18px;
        }
        .detail-badges {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
        }
        .detail-badge {
            display: inline-flex;
            align-items: center;
            padding: 4px 12px;
            border-radius: 999px;
            font-size: 0.85em;
            font-weight: 600;
            letter-spacing: 0.03em;
            border: 1px solid var(--border-color);
            background: var(--info-panel-bg);
            color: var(--text-color);
            text-transform: uppercase;
        }
        .critical-path-pill {
            background: rgba(220,53,69,0.12);
            color: #dc8892;
            border-color: rgba(220,53,69,0.3);
        }
        body[data-theme="dark"] .critical-path-pill {
            background: rgba(248,113,113,0.15);
            color: #fecaca;
            border-color: rgba(248,113,113,0.4);
        }
        .detail-section {
            background: var(--info-panel-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 18px;
            box-shadow: 0 5px 14px rgba(0,0,0,0.08);
        }
        body[data-theme="dark"] .detail-section {
            box-shadow: none;
        }
        .detail-section h4 {
            margin: 0 0 12px 0;
            color: var(--accent-color);
            font-size: 1.05em;
        }
        .detail-table {
            width: 100%;
            border-collapse: collapse;
        }
        .detail-label {
            color: var(--muted-text-color);
            font-weight: 600;
            width: 40%;
            padding: 6px 0;
            vertical-align: top;
        }
        .detail-value {
            color: var(--text-color);
            padding: 6px 0;
        }
        .detail-value.code {
            font-family: 'SFMono-Regular', 'Consolas', 'Liberation Mono', monospace;
            font-size: 0.9em;
            word-break: break-all;
        }
        .detail-code-list {
            list-style: none;
            margin: 0;
            padding: 0;
            max-height: 220px;
            overflow-y: auto;
            background: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 6px;
            padding: 10px 12px;
            font-family: 'SFMono-Regular', 'Consolas', 'Liberation Mono', monospace;
            font-size: 0.85em;
            line-height: 1.45;
        }
        .detail-code-list li {
            margin-bottom: 6px;
            word-break: break-all;
        }
        .detail-code-list li:last-child {
            margin-bottom: 0;
        }
        .detail-code-list .detail-more {
            color: var(--muted-text-color);
            font-style: italic;
        }
        .detail-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 12px;
        }
        .detail-stat {
            text-align: center;
            padding: 12px;
            border-radius: 6px;
            background: var(--card-bg);
            border: 1px solid var(--border-color);
        }
        .detail-stat-value {
            font-size: 1.6em;
            font-weight: 700;
            color: var(--accent-color);
        }
        .detail-stat-label {
            font-size: 0.85em;
            color: var(--muted-text-color);
            margin-top: 4px;
        }
        .detail-progress {
            background: rgba(0,0,0,0.08);
            height: 6px;
            border-radius: 4px;
            overflow: hidden;
        }
        body[data-theme="dark"] .detail-progress {
            background: rgba(255,255,255,0.08);
        }
        .detail-progress-bar {
            background: var(--accent-color);
            height: 100%;
            transition: width 0.3s ease;
        }
        .detail-breakdown-item { margin-bottom: 10px; }
        .detail-breakdown-row {
            display: flex;
            justify-content: space-between;
            font-size: 0.9em;
            color: var(--muted-text-color);
            margin-bottom: 4px;
        }
        .detail-breakdown-value {
            font-weight: 600;
            color: var(--text-color);
        }
        .critical-path-section {
            border-left: 4px solid #dc3545;
        }
        body[data-theme="dark"] .critical-path-section {
            border-left-color: #f87171;
        }
        .permission-callout {
            background: rgba(255,244,229,0.9);
            border-left: 4px solid #ff9800;
            padding: 10px 12px;
            border-radius: 4px;
        }
        body[data-theme="dark"] .permission-callout {
            background: rgba(251,191,36,0.1);
        }
        .status-chip {
            display: inline-flex;
            align-items: center;
            padding: 2px 10px;
            border-radius: 999px;
            font-weight: 600;
            font-size: 0.85em;
        }
        .status-positive { background: rgba(34,197,94,0.15); color: #4ade80; }
        .status-negative { background: rgba(239,68,68,0.15); color: #f87171; }
        .status-warning { background: rgba(251,191,36,0.2); color: #fbbf24; }
        .status-info { background: rgba(59,130,246,0.15); color: #93c5fd; }
        
        /* Override vis-network navigation buttons - blue icons without circles */
        div.vis-network div.vis-navigation div.vis-button {
            background-color: rgba(102, 126, 234, 0.15) !important;
            background-image: none !important;
            box-shadow: none !important;
            border-radius: 4px !important;
            display: flex !important;
            align-items: center !important;
            justify-content: center !important;
        }
        div.vis-network div.vis-navigation div.vis-button:hover {
            background-color: rgba(102, 126, 234, 0.25) !important;
            box-shadow: 0 2px 8px rgba(102, 126, 234, 0.3) !important;
        }
        div.vis-network div.vis-navigation div.vis-button.vis-up::after,
        div.vis-network div.vis-navigation div.vis-button.vis-down::after,
        div.vis-network div.vis-navigation div.vis-button.vis-left::after,
        div.vis-network div.vis-navigation div.vis-button.vis-right::after,
        div.vis-network div.vis-navigation div.vis-button.vis-zoomIn::after,
        div.vis-network div.vis-navigation div.vis-button.vis-zoomOut::after,
        div.vis-network div.vis-navigation div.vis-button.vis-zoomExtends::after {
            color: #667eea !important;
            font-size: 24px !important;
            font-weight: bold !important;
            line-height: 30px !important;
        }
        div.vis-network div.vis-navigation div.vis-button.vis-up::after { content: '↑' !important; }
        div.vis-network div.vis-navigation div.vis-button.vis-down::after { content: '↓' !important; }
        div.vis-network div.vis-navigation div.vis-button.vis-left::after { content: '←' !important; }
        div.vis-network div.vis-navigation div.vis-button.vis-right::after { content: '→' !important; }
        div.vis-network div.vis-navigation div.vis-button.vis-zoomIn::after { content: '+' !important; }
        div.vis-network div.vis-navigation div.vis-button.vis-zoomOut::after { content: '−' !important; }
        div.vis-network div.vis-navigation div.vis-button.vis-zoomExtends::after { content: '⊡' !important; }
        div.vis-network div.vis-navigation div.vis-button.vis-fullscreen .vis-button-icon {
            color: #667eea;
            font-size: 24px;
            font-weight: bold;
            line-height: 30px;
            font-family: 'Segoe UI Symbol', 'Helvetica Neue', Helvetica, Arial, sans-serif;
            display: flex;
            align-items: center;
            justify-content: center;
            width: 24px;
            height: 24px;
        }
        div.vis-network div.vis-navigation div.vis-button.vis-fullscreen[data-active="true"] {
            background-color: rgba(102, 126, 234, 0.35) !important;
        }
        
        body[data-theme="dark"] div.vis-network div.vis-navigation div.vis-button {
            background-color: rgba(165, 180, 252, 0.15) !important;
        }
        body[data-theme="dark"] div.vis-network div.vis-navigation div.vis-button:hover {
            background-color: rgba(165, 180, 252, 0.25) !important;
            box-shadow: 0 2px 8px rgba(165, 180, 252, 0.3) !important;
        }
        body[data-theme="dark"] div.vis-network div.vis-navigation div.vis-button::after {
            color: #a5b4fc !important;
        }
        body[data-theme="dark"] div.vis-network div.vis-navigation div.vis-button.vis-fullscreen .vis-button-icon {
            color: #a5b4fc;
        }
        body[data-theme="dark"] div.vis-network div.vis-navigation div.vis-button.vis-fullscreen[data-active="true"] {
            background-color: rgba(165, 180, 252, 0.35) !important;
        }
    </style>
</head>
<body data-theme="light">
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
    <script>
        (function() {
            const body = document.body;
            const toggleBtn = document.getElementById('themeToggle');
            if (!toggleBtn) {
                return;
            }

            const prefersDark = window.matchMedia('(prefers-color-scheme: dark)');
            const getActiveTheme = () => body.getAttribute('data-theme') || 'light';

            const setTheme = theme => {
                body.setAttribute('data-theme', theme);
                toggleBtn.textContent = theme === 'dark' ? '☀️ Light Mode' : '🌙 Dark Mode';
                requestAnimationFrame(() => {
                    if (window.scEntraApplyGraphTheme) {
                        window.scEntraApplyGraphTheme();
                    }
                    const legendTextColor = getComputedStyle(body).getPropertyValue('--text-color');
                    document.querySelectorAll('.legend-item').forEach(item => {
                        item.style.color = legendTextColor;
                    });
                });
            };

            const storedTheme = localStorage.getItem('scEntraTheme');
            const initialTheme = storedTheme || 'dark';
            setTheme(initialTheme);

            prefersDark.addEventListener('change', event => {
                if (!localStorage.getItem('scEntraTheme')) {
                    setTheme(event.matches ? 'dark' : 'light');
                }
            });

            toggleBtn.addEventListener('click', () => {
                const nextTheme = getActiveTheme() === 'dark' ? 'light' : 'dark';
                localStorage.setItem('scEntraTheme', nextTheme);
                setTheme(nextTheme);
            });
        })();
    </script>
</body>
</html>
"@
}
