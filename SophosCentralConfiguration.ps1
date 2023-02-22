# The Central API Client ID.
[PSCredential] $script:clientId = $null

#The Central API Client Secret.
[PSCredential] $script:clientSecret = $null

# The location of the file that we'll store any settings that can/should roam with the user.
[string] $script:configurationFilePath = [System.IO.Path]::Combine(
    [System.Environment]::GetFolderPath('ApplicationData'),
    'Microsoft',
    'PowerShellForSophosCentral',
    'config.json'
)

# The location of the file that we'll store the Access Token SecureString.
[string] $script:apiTokenFilePath = [System.IO.Path]::Combine(
    [System.Environment]::GetFolderPath('LocalApplicationData'),
    'Microsoft',
    'PowerShellForSophosCentral',
    'accessToken.txt'
)

# Only tell ysers about needing to configure an API token once per session.
$script:seenTokenWarningThisSession = $false

# The session-cached copy of the module's configuration properties.
[PSCustomObject] $script:configuration = $null

function Initialize-SophosCentralConfiguration {
    <#
    .SYNOPSIS
        Populates the configuration of the module for this session, loading in any values that may have already been saved to disk.
    
    .DESCRIPTION
        Populates the configuration of the module for this session, loading in any values that may have been saved to disk. 
    .NOTES
        Internal helper method.   
    #>
    [CmdletBinding()]
    param()

    $script:seenTokenWarningThisSession = $false
    $script:configuration = Import-SophosCentralConfiguration -Path $script:configurationFilePath
}

function Set-SophosCentralConfiguration {
    <#
        .SYNOPSIS
        Allows the user to configure the Central API Client ID and Client Secret for authentication with the Sophos Central API.
        .DESCRIPTION
        Allows the user to configure the Central API Client ID and Client Secret for authentication with the Sophos Central API.

        The token will be stored on the machine as SecureString and will automatically be read on future PowerShell sessions with this module. 
        .PARAMETER clientId
        The Sophos Central API Client ID.
        .PARAMETER clientSecret
        The Sophos Central API Client Secret.
        .EXAMPLE
        Set-CentralAuthentication -clientId "1234567890" -clientSecret "0987654321"

        Prompts the user for the Sophos Central API Client ID and Client Secret.
    #>
    [CmdletBinding(
        PositionalBinding = $false,
        SupportsShouldProcess
    )]

    param(
        [Parameter()]
        [string]$clientId,
        [Parameter()]
        [string]$clientSecret,
        [switch] $SessionOnly
    )

    $persistedConfig = $null
    if (-not $SessionOnly){
        $persistedConfig = Read-SophosCentralConfiguration -Path $script:configurationFilePath
    }

    if (-not $PSCmdlet.ShouldProcess('SophosCentralConfiguration', 'Set'))
    {
        return
    }

    $properties = Get-Member -InputObject $script:configuration -MemberType Property | 
    Select-Object -ExpandProperty Name
    foreach ($name in $properties)
    {
        if ($PSBoundParameters.ContainsKey($name))
        {
            if ($value -is [switch]) { $value = $value.ToBool() }
            $script:configuration.$name = $value

            if (-not $SessionOnly)
            {
                Add-Member -InputObject $persistedConfig -Name $name -Value $value -MemberType NoteProperty -Force
            }
        }
    }

    if (-not $SessionOnly)
    {
        Save-SophosCentralConfiguration -Configuration $persistedConfig -Path $script:configurationFilePath
    }
}

function Save-SophosCentralConfiguration {
    <#
        .SYNOPSIS
        Serializes the provided settings objects to disk as a JSON file.

        .DESCRIPTION
        Serializes the provided settings objects to disk as a JSON file.

        .PARAMETER Configuration
        The configuration object to save to disk.

        .PARAMETER Path
        The path to the file on disk that Configuration should be persisted to.

        .NOTES
        Internal helper method.

        .EXAMPLE
        Save-SophosCentralConfiguration - Configuration $config -Path 'C:\Users\Public\Documents\config.json'
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)]
        [PSCustomObject] $Configuration,
        
        [Parameter(Mandatory)]
        [string] $Path
    )

    if (-not $PSCmdlet.ShouldProcess('SophosCentralConfiguration', 'Save'))
    {
        return
    }

    $null = New-Item -Path $Path -Force
    ConvertTo-Json -InputObject $Configuration |
        Set-Content -Path $Path -Force -ErrorAction SilentlyContinue -ErrorVariable ev
    
    if (($null -ne $ev) -and ($ev.Count -gt 0)){
        $message = "Failed to persist the updated settings to disk. They will remain for this PowerShell session only."
        Write-Log -Message $message -Level Warning -Exception $ev[0]
    }
}

function Read-SophosCentralConfiguration {
    <#
        .SYNOPSIS
        Loads the default configuration values and returns the deserialized object.
        
        .DESCRIPTION

    #>
}
