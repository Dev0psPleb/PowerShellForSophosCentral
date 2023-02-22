<#
.SYNOPSIS
place_holder
.DESCRIPTION
place_holder
.PARAMETER client_id
place_holder
.PARAMETER client_secret
place_holder
.EXAMPLE
place_holder
.NOTES
place_holder
.LINK
place_holder
.LINK
place_holder
#>

$global:header = @{
    Authorization = "Bearer $bearerToken"
    'X-Tenant-ID' = $tenantId
    Accept = 'application/json'
}

function init(){
    function createIni(){
        $clientId = Read-Host -Prompt "Enter the Sophos Central API Client ID"
        $clientSecret = Read-Host -Prompt "Enter the Sophos Central API Client Secret"
        $ini = @"
        [global]
        clientId = "$clientId"
        clientSecret = "$clientSecret"
"@
        $iniFile = New-Item -Path "api.ini" -ItemType File - Force -Value $ini
        return $iniFile
    }

    
    if (-not(Test-Path $iniFile -PathType Leaf)) {
        try {
            $null = createIni
            Write-Host -ForegroundColor Green "Successfully created the configuration file, $iniFile"
        } catch {
            throw "Error: $($_.Exception.Message)"
        } else {
            Write-Host -ForegroundColor Green "Configuration file, $iniFile, already exists"
        }
    }
}

function apiCall(){
    [CmdletBinding()]
    param(
        [Parameter]$uri,
        [Parameter]$method,
        [Parameter]$global:header,
        [Parameter]$body
    )
    $header = $global:header
    $response = Invoke-RestMethod -Uri $uri -Method $method -Headers $header -Body $body
    $data = $response
    return $data
}

function centralApiAuth(){

    function getAccessToken(){
        $iniFile = Get-IniContent "api.ini"
        $clientId = $iniFile.global.clientId
        $clientSecret = $iniFile.global.clientSecret
        $authSuccess = $false
        $uri = "https://id.sophos.com/api/v2/oauth2/token"
    
        $header = @{
            content_type = "application/x-www-form-urlencoded"
        }

        $body = @{
            client_id = $clientId
            client_secret = $clientSecret
            grant_type = 'client_credentials'
            scope = 'token'
        }

        try {
            $response = Invoke-RestMethod  -Uri $uri -Method POST -headers $header -Body $body
            $accessToken = $response.access_token
            $authSuccess = $true
            return $accessToken
        } catch {
            $authSuccess = $false
            Write-Host -ForgroundColor Red "Error: $($_.Exception.Message)"
        }
    }

    function getTenantId(){
        $uri = "https://api.central.sophos.com/whoami/v1"
        $bearerToken = getAccessToken

        $response = Invoke-RestMethod -Uri $uri -Method GET -Headers $header
        $data = @{
            tenantId = $response.id
            dataRegion = $response.apiHosts.dataRegion
        }

        return $data
    }
}

function main(){
    init
}

main