[cmdletbinding()]
param(
    [Parameter(Mandatory)]
    [string]
    $ID,
    [ValidateSet('ActiveScan','FullScan','NetQuarantine','NetUnQuarantine','EOCScan','UpdateContent','CommandStatus','CancelCommand')]
    $Command,
    $ConfigFile = "C:\Program Files\LogRhythm\Smart Response Plugins\SEPM.xml"
)

Function Disable-SSLError{
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


[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Ssl3,[Net.SecurityProtocolType]::Tls, [Net.SecurityProtocolType]::Tls11, [Net.SecurityProtocolType]::Tls12
}


trap [Exception] 
{
	write-error $("Exception: " + $_)
	exit 1
}

Function Get-Config{
   try {
        if (Test-Path $ConfigFile) {
            Write-Host ("Configuration file found: " + $ConfigFile)
            $Credentials = Import-Clixml -Path $ConfigFile
            $SEPMServer =  [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((($Credentials.SEPHost))))
            $SEPUser =  [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((($Credentials.SEPUser))))
            $SEPDomain =  [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((($Credentials.SEPDomain))))
            $SEPPass =  [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR((($Credentials.SEPPass))))

        }
       else{
           Write-Host ("Configuration file not found. Please use Setup action to creat: " + $ConfigFile)
           exit 1
       }
    }
    catch {
        Write-Error ("The credentials within the configuration file are corrupt. Please recreate the file: " + $ConfigFile)
        exit 1
    }
}

Function Get-APIToken{

    $Body = "{""username"" : ""$SEPUser"", ""password"" : ""$SEPPass"", ""domain"" :  ""$SEPDomain"" }"
    $Result = Invoke-RestMethod -Method Post -Uri $AuthenticateURL -Body $Body -ContentType "Application/JSON" -UseBasicParsing    
    $Token = $Result.token
    $Token
}

Function Get-ComputerID{
    param(
        [string]$Token
    )
    
    $Headers = @{
        Authorization = "Bearer $Token"
    }
    $Computer = (Invoke-WebRequest -Method Get -Uri $ComputerURL"?computerName="$ID -ContentType "Application/JSON" -Headers $Headers -UseBasicParsing).Content

    $ComputerId = ([regex]::Match($Computer,'"uniqueId"\:"(?<uniqueId>[^"]+)"')).Groups[1].Value
    $ComputerId
}
Get-Config

$SEPMAPIBaseURL = "https://"+$SEPMServer+":8446/sepm/api/v1/"
$AuthenticateURL = $SEPMAPIBaseURL + "identity/authenticate"
$ComputerURL = $SEPMAPIBaseURL + "computers"
$activeScanURL = $SEPMAPIBaseURL + "command-queue/activescan"
$fullScanURL = $SEPMAPIBaseURL + "command-queue/fullscan"
$EOCScanURL = $SEPMAPIBaseURL + "command-queue/eoc"
$NetQuarantineURL = $SEPMAPIBaseURL + "command-queue/quarantine"
$ContentUpdateURL = $SEPMAPIBaseURL + "command-queue/updatecontent"
$CommandStatusURL = $SEPMAPIBaseURL + "command-queue/"

$APIToken = Get-APIToken

$Headers = @{
    Authorization = "Bearer $APIToken"
    }



Switch($Command)
{
    'ActiveScan' {
        $uniqueId = Get-ComputerID
        $result = Invoke-WebRequest -Method Post -Uri $activeScanURL"?computer_ids="$uniqueId -ContentType "Application/JSON" -Headers $Headers -UseBasicParsing
    }
    'FullScan' {
        $uniqueId = Get-ComputerID
        $result = Invoke-WebRequest -Method Post -Uri $fullScanURL"?computer_ids="$uniqueId -ContentType "Application/JSON" -Headers $Headers -UseBasicParsing
    }
    'EOCScan' {
        $uniqueId = Get-ComputerID
        $result = Invoke-WebRequest -Method Post -Uri $EOCScanURL"?computer_ids="$uniqueId -ContentType "Application/JSON" -Headers $Headers -UseBasicParsing
    }
	'NetQuarantine' {
        $uniqueId = Get-ComputerID
        $result = Invoke-WebRequest -Method Post -Uri $NetQuarantineURL"?computer_ids="$uniqueId -ContentType "Application/JSON" -Headers $Headers -UseBasicParsing
    }
	'NetUnQuarantine' {
        $uniqueId = Get-ComputerID
        $result = Invoke-WebRequest -Method Post -Uri $NetQuarantineURL"?computer_ids="$uniqueId"&"undo=true -ContentType "Application/JSON" -Headers $Headers -UseBasicParsing
    }
    'UpdateContent' {
        $uniqueId = Get-ComputerID
        $result = Invoke-WebRequest -Method Post -Uri $ContentUpdateURL"?computer_ids="$uniqueId -ContentType "Application/JSON" -Headers $Headers -UseBasicParsing
    }
    'CommandStatus' {$result = Invoke-WebRequest -Method Get -Uri $CommandStatusURL$ID -ContentType "Application/JSON" -Headers $Headers -UseBasicParsing}
    'CommandCancel' {$result = Invoke-WebRequest -Method Post -Uri $CommandStatusURL$ID"/cancel" -ContentType "Application/JSON" -Headers $Headers -UseBasicParsing}
}

if ($result.StatusCode -ne '200'){
    write-error $Result.Content
}
else{
    Write-Host "Successful $Command"
    Write-Host $Result.Content
    exit 0
}
