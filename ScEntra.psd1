@{
    # Script module or binary module file associated with this manifest.
    RootModule = 'ScEntra.psm1'

    # Version number of this module.
    ModuleVersion = '1.0.0'

    # ID used to uniquely identify this module
    GUID = '8c3d4e5f-6a7b-8c9d-0e1f-2a3b4c5d6e7f'

    # Author of this module
    Author = 'ScEntra Contributors'

    # Company or vendor of this module
    CompanyName = 'ScEntra'

    # Copyright statement for this module
    Copyright = '(c) 2025 ScEntra. All rights reserved.'

    # Description of the functionality provided by this module
    Description = 'Scan Entra for risk in role assignments and escalation paths. Provides inventory of users, groups, service principals, app registrations, and analyzes privilege escalation risks.'

    # Minimum version of the PowerShell engine required by this module
    PowerShellVersion = '7.0'

    # Modules that must be imported into the global environment prior to importing this module
    # Note: No longer requires Microsoft.Graph PowerShell modules - uses direct REST API calls
    # Az modules are checked at runtime in functions that require them
    RequiredModules = @()

    # Functions to export from this module
    FunctionsToExport = @(
        'Connect-ScEntraGraph'
        'Invoke-ScEntraAnalysis'
        'Get-ScEntraUsers'
        'Get-ScEntraGroups'
        'Get-ScEntraServicePrincipals'
        'Get-ScEntraAppRegistrations'
        'Get-ScEntraRoleAssignments'
        'Get-ScEntraPIMAssignments'
        'Get-ScEntraEscalationPaths'
        'Get-ScEntraEnvironmentSize'
        'Get-ScEntraEnvironmentConfig'
        'New-ScEntraGraphData'
        'Export-ScEntraReport'
        'New-ScEntraServicePrincipal'
    )

    # Cmdlets to export from this module
    CmdletsToExport = @()

    # Variables to export from this module
    VariablesToExport = @()

    # Aliases to export from this module
    AliasesToExport = @()

    # Private data to pass to the module specified in RootModule/ModuleToProcess
    PrivateData = @{
        PSData = @{
            # Tags applied to this module
            Tags = @('Entra', 'Azure', 'Security', 'Identity', 'PIM', 'RBAC', 'Escalation')

            # A URL to the license for this module.
            LicenseUri = ''

            # A URL to the main website for this project.
            ProjectUri = 'https://github.com/azurekid/ScEntra'

            # ReleaseNotes of this module
            ReleaseNotes = 'Initial release with Entra configuration inventory and escalation path analysis.'
        }
    }
}
