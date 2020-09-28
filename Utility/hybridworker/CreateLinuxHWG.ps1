Param(
    [Parameter(Mandatory = $false)]
    [string] $location = "West Central US",  
    [Parameter(Mandatory = $false)]
    [string] $Environment = "AzureCloud", 
    [Parameter(Mandatory = $false)]
    [string] $ResourceGroupName = "Test-auto-creation",
    [Parameter(Mandatory = $false)]
    [string] $AccountName = "Test-auto-creation-aa",
    [Parameter(Mandatory = $false)]
    [string] $WorkspaceName = "Test-LAWorkspace",
    [Parameter(Mandatory = $true)]
    [String] $vmName,
    [Parameter(Mandatory = $true)]
    [String] $WorkerGroupName
)
 
$ErrorActionPreference = "Stop"
$guid_val = [guid]::NewGuid()
$guid = $guid_val.ToString()
if ($Environment -eq "USNat") {
    Add-AzEnvironment -Name USNat -ServiceManagementUrl 'https://management.azure.eaglex.ic.gov/' -ActiveDirectoryAuthority 'https://login.microsoftonline.eaglex.ic.gov/' -ActiveDirectoryServiceEndpointResourceId 'https://management.azure.eaglex.ic.gov/' -ResourceManagerEndpoint 'https://usnatwest.management.azure.eaglex.ic.gov' -GraphUrl 'https://graph.cloudapi.eaglex.ic.gov' -GraphEndpointResourceId 'https://graph.cloudapi.eaglex.ic.gov/' -AdTenant 'Common' -AzureKeyVaultDnsSuffix 'vault.cloudapi.eaglex.ic.gov' -AzureKeyVaultServiceEndpointResourceId 'https://vault.cloudapi.eaglex.ic.gov' -EnableAdfsAuthentication 'False'
}
if ($Environment -eq "USSec") {
    Add-AzEnvironment -Name USSecEast `
        -ServiceManagementUrl 'https://management.core.microsoft.scloud/' `
        -StorageEndpointSuffix 'core.microsoft.scloud' `
        -ActiveDirectoryAuthority 'https://login.microsoftonline.microsoft.scloud/' `
        -ActiveDirectoryServiceEndpointResourceId 'https://management.azure.microsoft.scloud/' `
        -ResourceManagerEndpoint 'https://usseceast.management.azure.microsoft.scloud' `
        -GraphUrl 'https://graph.microsoft.scloud' `
        -GraphEndpointResourceId 'https://graph.microsoft.scloud/' `
        -AdTenant 'Common' `
        -AzureKeyVaultDnsSuffix 'vault.cloudapi.microsoft.scloud' `
        -AzureKeyVaultServiceEndpointResourceId 'https://vault.cloudapi.microsoft.scloud' `
        -EnableAdfsAuthentication 'False'
}
# Connect using RunAs account connection
$connectionName = "AzureRunAsConnection"
$agentEndpoint = ""
$aaPrimaryKey = ""
$workspaceId = ""
$workspacePrimaryKey = ""

try {
    $servicePrincipalConnection = Get-AutomationConnection -Name $connectionName      
    Write-Output  "Logging in to Azure..." -verbose
    Connect-AzAccount `
        -ServicePrincipal `
        -TenantId $servicePrincipalConnection.TenantId `
        -ApplicationId $servicePrincipalConnection.ApplicationId `
        -CertificateThumbprint $servicePrincipalConnection.CertificateThumbprint `
        -Environment $Environment | Out-Null
}
catch {
    if (!$servicePrincipalConnection) {
        $ErrorMessage = "Connection $connectionName not found."
        throw $ErrorMessage
    }
    else {
        Write-Error -Message $_.Exception
        throw $_.Exception
    }
}


#Get-Automation Account
Write-Output  "Getting Automation Account....."

# Write-Output "Create account" -verbose
try {
    ($Account = Get-AzAutomationAccount -Name $AccountName -ResourceGroupName $ResourceGroupName) | Out-Null 
    if ($Account.AutomationAccountName -like $AccountName) {
        Write-Output  "Account retrieved successfully"
        ($accRegInfo = Get-AzAutomationRegistrationInfo -ResourceGroup $ResourceGroupName -AutomationAccountName  $AccountName) | Out-Null
        $agentEndpoint = $accRegInfo.Endpoint
        $aaPrimaryKey = $accRegInfo.PrimaryKey

        Write-Output  "AgentService endpoint: $agentEndpoint  Primary key : $aaPrimaryKey"
    } 
    else {
        Write-Error "HWG Creation :: Account retrieval failed"
    }
}
catch {
    Write-Error "HWG Creation :: Account retrieval failed"
}


### Create an LA workspace
Write-Output  "Creating LA Workspace...."
if ($WorkspaceName -eq "Test-LAWorkspace") {
    $workspace_guid = [guid]::NewGuid()
    $WorkspaceName = $WorkspaceName + $workspace_guid.ToString()
}
# Create a new Log Analytics workspace if needed
try {
    Write-Output "Creating new workspace named $WorkspaceName in region $Location..."
    #check if already exists
    $laworkspace = Get-AzResource -ResourceGroupName $ResourceGroupName -Name $WorkspaceName

    if ($null -eq $laworkspace) {
        New-AzOperationalInsightsWorkspace -Location $Location -Name $WorkspaceName -Sku Standard -ResourceGroupName $ResourceGroupName
        Start-Sleep -s 60
    }

    Write-Output "Enabling Automation for the created workspace...."
    (Set-AzOperationalInsightsIntelligencePack -ResourceGroupName $ResourceGroupName -WorkspaceName $WorkspaceName -IntelligencePackName "AzureAutomation" -Enabled $true) | Out-Null

    ($workspaceDetails = Get-AzOperationalInsightsWorkspace -ResourceGroupName $ResourceGroupName -Name $WorkspaceName)  | Out-Null
    $workspaceId = $workspaceDetails.CustomerId

    ($workspaceSharedKey = Get-AzOperationalInsightsWorkspaceSharedKey -ResourceGroupName $ResourceGroupName -Name $WorkspaceName) | Out-Null
    $workspacePrimaryKey = $workspaceSharedKey.PrimarySharedKey

    Write-Output  "Workspace Details to be used to register machine are WorkspaceId : $workspaceId and WorkspaceKey : $workspacePrimaryKey"
} 
catch {
    Write-Error "HWG Creation :: Error creating LA workspace : $_"
}


#Create a VM
$vmNetworkName = "TestVnet" + $guid.SubString(0, 4)
$subnetName = "TestSubnet" + $guid.SubString(0, 4)
$newtworkSG = "TestNetworkSecurityGroup" + $guid.SubString(0, 4)
$ipAddressName = "TestPublicIpAddress" + $guid.SubString(0, 4)
$User = "TestVMUserLinux"
$Password = ConvertTo-SecureString "SecurePassword12345" -AsPlainText -Force
$VMCredential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $User, $Password
$vmlocation = "West Europe"

function New-VM {
    try {
        New-AzVm `
            -ResourceGroupName $ResourceGroupName `
            -Name $vmName `
            -Location $vmlocation `
            -VirtualNetworkName $vmNetworkName `
            -SubnetName $subnetName `
            -SecurityGroupName $newtworkSG `
            -PublicIpAddressName $ipAddressName `
            -Image "UbuntuLTS" `
            -Credential $VMCredential | Out-Null

        Start-Sleep -s 120
        return
    }
    catch {
        Write-Output "Error creating VM retrying in $vmlocation..."
        $vmlocation = "Australia East"
        New-AzVm `
            -ResourceGroupName $ResourceGroupName `
            -Name $vmName `
            -Location $vmlocation `
            -VirtualNetworkName $vmNetworkName `
            -SubnetName $subnetName `
            -SecurityGroupName $newtworkSG `
            -PublicIpAddressName $ipAddressName `
            -Image "UbuntuLTS" `
            -Credential $VMCredential | Out-Null
        Start-Sleep -s 120
    }
    
    throw "Error Creating VM after 3 attempts"
}

#Create a VM
try { 
    New-VM
}
catch {
    Write-Error "HWG Creation :: Error creating VM : $_"
}

function Check-UrlIsAccessible {
    param (
        $url
    )
    # First we create the request.
    $HTTP_Request = [System.Net.WebRequest]::Create($url)

    try {
        # We then get a response from the site.
        $HTTP_Response = $HTTP_Request.GetResponse()

        # We then get the HTTP code as an integer.
        $HTTP_Status = [int]$HTTP_Response.StatusCode

        If ($HTTP_Status -eq 200) {
            return $true
        }
        Else {
            return $false
        }
    }
    catch {
        return $false
    }
    finally {
        # Finally, we clean up the http request by closing it.
        If ($null -eq $HTTP_Response) { } 
        Else { $HTTP_Response.Close() }
    }
}

$shellScriptName = "RunVMCommandOnLinux.sh"
$destination = Join-Path $env:Temp -ChildPath $shellScriptName -Verbose
$shellscripturi = "https://raw.githubusercontent.com/krmanupa/AzureAutomationRegionValidation/master/VMExtensionScripts/RunVMCommandOnLinux.sh"
$isacc = Check-UrlIsAccessible -url $shellscripturi
if ($isacc -eq $false) {
    Write-Output "The Location of the script to run script is not accessible trying to check if the automation variable has been added for an internal script location"
    $runshellscriptvar = Get-AzAutomationVariable -AutomationAccountName $AccountName -ResourceGroupName $ResourceGroupName -Name "RunVMCommandOnLinux"
    $shellscripturi = $runshellscriptvar.Value
}

# Get the Script to be run on the VM
Invoke-WebRequest -URI $shellscripturi -OutFile $destination

# Auto registration script URL
$uri = "https://raw.githubusercontent.com/krmanupa/AzureAutomationRegionValidation/master/VMExtensionScripts/AutoRegisterLinuxHW.py"
$isacc = Check-UrlIsAccessible -url $uri
if ($isacc -eq $false) {
    Write-Output "The Location of the script to run script is not accessible trying to check if the automation variable has been added for an internal script location"
    $variable = Get-AzAutomationVariable -AutomationAccountName $AccountName -ResourceGroupName $ResourceGroupName -Name "AutoRegisterLinuxHW"
    $uri = $variable.Value 
}

if ($shellscripturi -eq "") {
    Write-Error "Cannot continue since the uri to the script to run registration on Linux machine is not present in the automation account"
    return
}

$filename = "AutoRegisterLinuxHW.py"


$params = @{"fileuri" = $uri ; "filename" = $filename; "endpoint" = $agentEndpoint; "groupname" = $WorkerGroupName; "workspaceid" = $workspaceId ; "workspacekey" = $workspacePrimaryKey; "key" = $aaPrimaryKey; "region" = $location }
Invoke-AzVMRunCommand -ResourceGroupName $ResourceGroupName -VMName $vmName -CommandId "RunShellScript" -ScriptPath $destination -Parameter $params | Out-Null

Get-AzAutomationHybridWorkerGroup -AutomationAccountName $AccountName -ResourceGroupName $ResourceGroupName -Name $WorkerGroupName
Write-Output "Creation of HWG Successful"
