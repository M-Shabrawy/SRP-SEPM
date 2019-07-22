[cmdletbinding()]
param(
    [Parameter(Mandatory)]
    [string]
    $SEPuser,
    $SEPpass,
    $computerName,
    $SEPMServer,
    [ValidateSet('ActiveScan','FullScan','EOCScan','UpdateContent')]
    $Command
)

add-type @"
    using System.Net;
    using System.Security.Cryptography.X509Certificates;
    public class TrustAllCertsPolicy : ICertificatePolicy {
        public bool CheckValidationResult(
            ServicePoint srvPoint, X509Certificate certificate,
            WebRequest request, int certificateProblem) {
            return true;
        }
    }
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Ssl3, [Net.SecurityProtocolType]::Tls, [Net.SecurityProtocolType]::Tls11, [Net.SecurityProtocolType]::Tls12

trap [Exception] 
{
	write-error $("Exception: " + $_)
	exit 1
}

$SEPMAPIBaseURL = "https://"+$SEPMServer+":8446/sepm/api/v1/"

$AuthenticateURL = $SEPMAPIBaseURL + "identity/authenticate"

$ComputerURL = $SEPMAPIBaseURL + "computers"

$activeScanURL = $SEPMAPIBaseURL + "command-queue/activescan"

$fullScanURL = $SEPMAPIBaseURL + "command-queue/fullscan"

$EOCScanURL = $SEPMAPIBaseURL + "command-queue/eoc"

$ContentUpdateURL = $SEPMAPIBaseURL + "command-queue/updatecontent"

$Body = "{""username"" : ""$SEPuser"", ""password"" : ""$SEPpass"", ""domain"" :  """" }"

$Result = Invoke-RestMethod -Method Post -Uri $AuthenticateURL -Body $Body -ContentType "Application/JSON"

$Token = $Result.token

$Headers = @{
    Authorization = "Bearer $Token"
    }

$Computer = (Invoke-WebRequest -Method Get -Uri $ComputerURL"?computerName="$computerName -ContentType "Application/JSON" -Headers $Headers).Content

$uniqueId = ([regex]::Match($Computer,'"uniqueId"\:"(?<uniqueId>[^"]+)"')).Groups[1].Value

Switch($Command)
{
    'ActiveScan' {$result = Invoke-WebRequest -Method Post -Uri $activeScanURL"?computer_ids="$uniqueId -ContentType "Application/JSON" -Headers $Headers}
    'FullScan' {$result = Invoke-WebRequest -Method Post -Uri $fullScanURL"?computer_ids="$uniqueId -ContentType "Application/JSON" -Headers $Headers}
    'EOCScan' {$result = Invoke-WebRequest -Method Post -Uri $EOCScanURL"?computer_ids="$uniqueId -ContentType "Application/JSON" -Headers $Headers}
    'UpdateContent' {$result = Invoke-WebRequest -Method Post -Uri $ContentUpdateURL"?computer_ids="$uniqueId -ContentType "Application/JSON" -Headers $Headers}
    default {
        Write-Error "Computer ID $uniqueId"
        exit 1
        }
}

if ($result.StatusCode -ne '200')
{
    Write-Error $Result.Content
}
else
{
    Write-Host "Successful $Command"
    Write-Host $Result.Content
    exit 0
}


