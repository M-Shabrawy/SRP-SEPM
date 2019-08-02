[cmdletbinding()]
param(
    [Parameter(Mandatory)]
    [string]
    $SEPuser,
    $SEPpass,
    $ID,
    $SEPMServer,
    [ValidateSet('ActiveScan','FullScan','NetQuarantine','NetUnQuarantine','EOCScan','UpdateContent','CommandStatus','CancelCommand')]
    $Command
)
Function InSecure{
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
}


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

$NetQuarantineURL = $SEPMAPIBaseURL + "command-queue/quarantine"

$ContentUpdateURL = $SEPMAPIBaseURL + "command-queue/updatecontent"

$CommanStatusURL = $SEPMAPIBaseURL + "command-queue/"

$Body = "{""username"" : ""$SEPuser"", ""password"" : ""$SEPpass"", ""domain"" :  """" }"

$Result = Invoke-RestMethod -Method Post -Uri $AuthenticateURL -Body $Body -ContentType "Application/JSON" -UseBasicParsing

$Token = $Result.token

$Headers = @{
    Authorization = "Bearer $Token"
    }

$Computer = (Invoke-WebRequest -Method Get -Uri $ComputerURL"?computerName="$ID -ContentType "Application/JSON" -Headers $Headers -UseBasicParsing).Content

$uniqueId = ([regex]::Match($Computer,'"uniqueId"\:"(?<uniqueId>[^"]+)"')).Groups[1].Value

Switch($Command)
{
    'ActiveScan' {$result = Invoke-WebRequest -Method Post -Uri $activeScanURL"?computer_ids="$uniqueId -ContentType "Application/JSON" -Headers $Headers -UseBasicParsing}
    'FullScan' {$result = Invoke-WebRequest -Method Post -Uri $fullScanURL"?computer_ids="$uniqueId -ContentType "Application/JSON" -Headers $Headers -UseBasicParsing}
    'EOCScan' {$result = Invoke-WebRequest -Method Post -Uri $EOCScanURL"?computer_ids="$uniqueId -ContentType "Application/JSON" -Headers $Headers -UseBasicParsing}
	'NetQuarantine' {$result = Invoke-WebRequest -Method Post -Uri $NetQuarantineURL"?computer_ids="$uniqueId -ContentType "Application/JSON" -Headers $Headers -UseBasicParsing}
	'NetUnQuarantine' {$result = Invoke-WebRequest -Method Post -Uri $NetQuarantineURL"?computer_ids="$uniqueId"&"undo=true -ContentType "Application/JSON" -Headers $Headers -UseBasicParsing}
    'UpdateContent' {$result = Invoke-WebRequest -Method Post -Uri $ContentUpdateURL"?computer_ids="$uniqueId -ContentType "Application/JSON" -Headers $Headers -UseBasicParsing}
    'CommandStatus' {$result = Invoke-WebRequest -Method Get -Uri $CommanStatusURL$ID -ContentType "Application/JSON" -Headers $Headers -UseBasicParsing}
    'CommandCancel' {$result = Invoke-WebRequest -Method Post -Uri $CommanStatusURL$ID"/cancel" -ContentType "Application/JSON" -Headers $Headers -UseBasicParsing}
    default {
        write-error "Computer ID $uniqueId"
        exit 1
        }
}

if ($result.StatusCode -ne '200')
{
    write-error $Result.Content
}
else
{
    "Successful $Command"
    $Result.Content
    exit 0
}
