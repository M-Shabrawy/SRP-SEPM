[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$SEPMServer,
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$SEPUser,
    [Parameter(Mandatory=$true)]
    [ValidateNotNullOrEmpty()]
    [string]$SEPPass,
    [Parameter(Mandatory=$false)]
    [string]$ConfigFilePath = 'C:\Program Files\LogRhythm\Smart Response Plugins\SEPM-API'
)

trap [Exception] 
{
	write-error $("Exception: " + $_)
	exit 1
}

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

#-----------Check Configuration file path------------
Function Check-ConfigPath
{
    if(!(Test-Path $global:ConfigFilePath)) {
        Write-Host ('Folder not found: "$CredentialsFile" Creating')
        try {
            New-Item -Path $global:ConfigFilePath -ItemType Directory -Force
        }
        catch {
            Write-Error ('Failed to create folder $global:ConfigFilePath')
            exit 1
        }
    }
}

Function Validate-Input
{
    $SEPMAPIBaseURL = "https://"+$global:SEPMServer+":8446/sepm/api/v1/"
    $AuthenticateURL = $SEPMAPIBaseURL + "identity/authenticate"
    $Body = "{""username"" : ""$SEPuser"", ""password"" : ""$SEPpass"", ""domain"" :  """" }"
    try{
        $Result = Invoke-RestMethod -Method Post -Uri $AuthenticateURL -Body $Body -ContentType "Application/JSON" -UseBasicParsing
    }
    catch {
        
		}
        if($message -eq "The remote server returned an error: (401) Unauthorized."){
            write-host "Invalid Credentials."
			write-error "Error: Invalid or Incorrect Credentials provided."
			throw "ExecutionFailure"
            exit
        }
		else{
			write-host $message
			write-error "API Call Unsuccessful."
			throw "ExecutionFailure"
            exit
		}
}


Function Create-Hashtable
{
	$HashTable = [PSCustomObject]@{  
        "SEPHost" = $SEPMServer | ConvertTo-SecureString
        "SEPUser" = $SEPUser | ConvertTo-SecureString
        "SEPPass" = $SEPPass | ConvertTo-SecureString
	}
}


Function Create-ConfigFile
{
    try {
        if (!(Test-Path $ConfigFile)) {
            Write-Host ("Configuration file not found: " + $ConfigFile + "Creating a new one")
            New-Item -Path $ConfigFile -ItemType File -Force
        }
        else {
            $HashTable | Export-Clixml -Path $ConfigFile
        }
    }
    catch {
    Write-Error ("Failed to create configuration file: " + $ConfigFile)
    exit
    }
}

Disable-SSLError
Validate-Input
Check-ConfigPath
Create-ConfigFile