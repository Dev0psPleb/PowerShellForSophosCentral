function centralApiAuth(){
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