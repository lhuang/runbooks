﻿<#

.SYNOPSIS 

    This Azure/OMS Automation runbook onboards a hybrid worker. A resource group, automation account, OMS workspace, 
    and VM will all be generated if needed.


.DESCRIPTION

    This Azure/OMS Automation runbook onboards a hybrid worker. A resource group, automation account, OMS workspace,
    and VM will all be generated if needed. The major steps of the script are outlined below.
    
    1) Login to an Azure account
    2) Create a resource group if needed
    3) Create and configure an Automaiton Account if needed
    4) Create an OMS Workspace if needed
    5) Enable the Azure Automation solution in OMS
    6) Check if the machine provided was flagged as an on-premise device
        a) If not, create and configure a VM if needed
    7) Download the DSC agent
    8) Submit the configuration to register the machine as a hybrid worker


.PARAMETER IDString

    Optional. A string added to newly generated resources to create unique identifiers, If not specified,

    a random number (Maximum of 99999) is used.
 

.EXAMPLE

    New-HybridWorker


.NOTES

    AUTHOR: Jennifer Hunter, Azure/OMS Automation Team

    LASTEDIT: August 16, 2016  

#>


#Requires -RunAsAdministrator

Param (
# Setup initial variables
[Parameter(Mandatory=$false)]
[String] $IDString = "43479",
#[String] $IDString = (Get-Random -Maximum 99999),

[Parameter(Mandatory=$false)]
[String] $ResourceGroup = "hybrid-worker-" + $IDstring,

[Parameter(Mandatory=$false)]
#[String] $SubscriptionID = "",
[String] $SubscriptionID = "c9d8154e-9f57-47a9-8871-1f9b29fe2199",

# OMS Workspace
[Parameter(Mandatory=$false)]
[String] $WorkspaceName = "hybrid-worker-" + $IDstring,

[Parameter(Mandatory=$false)]
[String] $Location = "eastus",

# Automation
[Parameter(Mandatory=$false)]
[String] $AutomationAccountName = "hybrid-worker-AA-" + $IDstring,

[Parameter(Mandatory=$false)]
[String] $AutomationLocation = "eastus2",

[Parameter(Mandatory=$false)]
[String] $ApplicationDisplayName = $AutomationAccountName,

[Parameter(Mandatory=$false)]
[String] $CertPlainPassword = "p@ssw0rdHybrid",

[Parameter(Mandatory=$false)]
[int] $NoOfMonthsUntilExpired = 12,

# VM
[Parameter(Mandatory=$false)]
[Boolean] $OnPremise = $false,

[Parameter(Mandatory=$false)]
[String] $MachineName = "hybridVM" + $IDstring,

[Parameter(Mandatory=$false)]
[String] $VMUser = "hybridUser",

[Parameter(Mandatory=$false)]
[String] $VMPassword = "p@ssw0rdHybrid",

[Parameter(Mandatory=$false)]
[String] $AvailabilityName = "hybrid-worker-availability-" + $IDstring,

[Parameter(Mandatory=$false)]
[String] $StorageName = "hybridworkerstorage" + $IDstring,

[Parameter(Mandatory=$false)]
[String] $OSDiskName = $MachineName + "OSDisk",

[Parameter(Mandatory=$false)]
[String] $VNetName = $ResourceGroup,

[Parameter(Mandatory=$false)]
[String] $PIpName = $ResourceGroup,

[Parameter(Mandatory=$false)]
[String] $InterfaceName = $ResourceGroup
)

# Parameter adjustment
$VMSecurePassword = ConvertTo-SecureString $VMPassword -AsPlainText -Force;
$VMCredential = New-Object System.Management.Automation.PSCredential ($VMUser, $VMSecurePassword);

# Login to Azure account
$Account = Add-AzureRmAccount

# If a subscriptionID has not been provided, select the first registered to the account
if ([string]::IsNullOrEmpty($SubscriptionID)) {
   
    # Get a list of all subscriptions
    $Subscription =  Get-AzureRmSubscription

    # Get the subscription ID
    $SubscriptionID = (($Subscription).SubscriptionId | Select -First 1).toString()

    # Get the tenant id for this subscription
    $TenantID = (($Subscription).TenantId | Select -First 1).toString()
} else {

    # Get a reference to the current subscription
    $Subscription = Get-AzureRmSubscription -SubscriptionId $SubscriptionID
    # Get the tenant id for this subscription
    $TenantID = $Subscription.TenantId
}


Set-AzureRmContext -SubscriptionID $SubscriptionID

# Create the resource group if needed
try {

    Get-AzureRmResourceGroup -Name $ResourceGroup -ErrorAction Stop
} catch {

    New-AzureRmResourceGroup -Name $ResourceGroup -Location $Location -WarningAction SilentlyContinue
}

#Create a new automation account if needed 
try {

    Get-AzureRmAutomationAccount -ResourceGroupName $ResourceGroup -Name $AutomationAccountName -ErrorAction Stop
} catch {

    New-AzureRmAutomationAccount -Name $AutomationAccountName -Location $AutomationLocation -ResourceGroupName $ResourceGroup -Plan "Free" -WarningAction SilentlyContinue
}

# Check if the account is configured as a runAs account
$ConnectionAssetName = "AzureRunAsConnection"

try {
    $ServicePrincipalConnection = Get-AzureRmAutomationConnection -ResourceGroupName $ResourceGroup -AutomationAccountName $AutomationAccountName -Name $ConnectionAssetName -ErrorAction Stop
} catch {    
    # Configure the Automation account as a RunAs account
    $CurrentDate = Get-Date
    $EndDate = $CurrentDate.AddMonths($NoOfMonthsUntilExpired)
    $KeyId = (New-Guid).Guid
    $CertPath = Join-Path $env:TEMP ($ApplicationDisplayName + ".pfx")

    $Cert = New-SelfSignedCertificate -DnsName $ApplicationDisplayName -CertStoreLocation cert:\LocalMachine\My -KeyExportPolicy Exportable -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider"

    $CertPassword = ConvertTo-SecureString $CertPlainPassword -AsPlainText -Force
    Export-PfxCertificate -Cert ("Cert:\localmachine\my\" + $Cert.Thumbprint) -FilePath $CertPath -Password $CertPassword -Force | Write-Verbose

    $PFXCert = New-Object -TypeName System.Security.Cryptography.X509Certificates.X509Certificate -ArgumentList @($CertPath, $CertPlainPassword)
    $KeyValue = [System.Convert]::ToBase64String($PFXCert.GetRawCertData())

    $KeyCredential = New-Object  Microsoft.Azure.Commands.Resources.Models.ActiveDirectory.PSADKeyCredential
    $KeyCredential.StartDate = $CurrentDate
    $KeyCredential.EndDate= $EndDate
    $KeyCredential.KeyId = $KeyId
    $KeyCredential.Type = "AsymmetricX509Cert"
    $KeyCredential.Usage = "Verify"
    $KeyCredential.Value = $KeyValue

    # Use Key credentials
    $Application = New-AzureRmADApplication -DisplayName $ApplicationDisplayName -HomePage ("http://" + $ApplicationDisplayName) -IdentifierUris ("http://" + $KeyId) -KeyCredentials $keyCredential

    New-AzureRMADServicePrincipal -ApplicationId $Application.ApplicationId | Write-Verbose 
    Get-AzureRmADServicePrincipal | Where {$_.ApplicationId -eq $Application.ApplicationId} | Write-Verbose

    $NewRole = $null
    $Retries = 0;
    while ($NewRole -eq $null -and $Retries -le 2)
    {

      # Sleep here for a few seconds to allow the service principal application to become active (should only take a couple of seconds normally)
      Sleep 5
      New-AzureRMRoleAssignment -RoleDefinitionName Contributor -ServicePrincipalName $Application.ApplicationId | Write-Verbose -ErrorAction SilentlyContinue
      Sleep 5
      $NewRole = Get-AzureRMRoleAssignment -ServicePrincipalName $Application.ApplicationId -ErrorAction SilentlyContinue
      $Retries++;
    }

    # Create the automation resources if needed
    try {

        Get-AzureRmAutomationCertificate -ResourceGroupName $ResourceGroup -AutomationAccountName $AutomationAccountName
    } catch {

        New-AzureRmAutomationCertificate -ResourceGroupName $ResourceGroup -AutomationAccountName $AutomationAccountName -Path $CertPath -Name AzureRunAsCertificate -Password $CertPassword -Exportable | write-verbose -WarningAction SilentlyContinue
    }

    # Create a Automation connection asset named AzureRunAsConnection in the Automation account. This connection uses the service principal.

    Remove-AzureRmAutomationConnection -ResourceGroupName $ResourceGroup -AutomationAccountName $AutomationAccountName -Name $ConnectionAssetName -Force -ErrorAction SilentlyContinue
    $ConnectionFieldValues = @{"ApplicationId" = $Application.ApplicationId; "TenantId" = $TenantID; "CertificateThumbprint" = $Cert.Thumbprint; "SubscriptionId" = $SubscriptionId}
    $AzureRunAsConnetion = 
    $ServicePrincipalConnection = New-AzureRmAutomationConnection -ResourceGroupName $ResourceGroup -AutomationAccountName $AutomationAccountName -Name $ConnectionAssetName -ConnectionTypeName AzureServicePrincipal -ConnectionFieldValues $ConnectionFieldValues
}

# Get Azure Automation Primary Key and Endpoint
$AutomationInfo = Get-AzureRMAutomationRegistrationInfo -ResourceGroupName $ResourceGroup -AutomationAccountName $AutomationAccountName
$AutomationPrimaryKey = $AutomationInfo.PrimaryKey
$AutomationEndpoint = $AutomationInfo.Endpoint

# Create a new OMS workspace if needed
try {
    $Workspace = Get-AzureRmOperationalInsightWorkspace -Name $WorkspaceName -ResourceGroupName $ResourceGroup -ErrorAction Stop
} catch {
    # Create the new workspace for the given name, region, and resource group
    $Workspace = New-AzureRmOperationalInsightsWorkspace -Location $Location -Name $WorkspaceName -Sku Standard -ResourceGroupName $ResourceGroup -WarningAction SilentlyContinue
}

# Get the workspace ID
$WorkspaceId = $Workspace.CustomerId

# Get the primary key for the OMS workspace
$WorkspaceSharedKeys = Get-AzureRmOperationalInsightsWorkspaceSharedKeys -ResourceGroupName $ResourceGroup -Name $WorkspaceName
$WorkspaceKey = $WorkspaceSharedKeys.PrimarySharedKey

# Activate the Azure Automation solution in the workspace
Set-AzureRmOperationalInsightsIntelligencePack -ResourceGroupName $ResourceGroup -WorkspaceName $WorkspaceName -IntelligencePackName "AzureAutomation" -Enabled $true

# Check if the machine was flagged as an on-premise device
if (!$OnPremise) {
# Create a new VM if needed
    try {
        Get-AzureRmVM -ResourceGroupName $ResourceGroup -Name $MachineName -ErrorAction Stop
    } catch {
    
        # Create a new availability set if needed
        try {

            $AvailabilitySet = Get-AzureRmAvailabilitySet -ResourceGroupName $ResourceGroup -Name $AvailabilityName -ErrorAction Stop
        } catch {

            $AvailabilitySet = New-AzureRmAvailabilitySet -ResourceGroupName $ResourceGroup -Name $AvailabilityName -Location $Location -WarningAction SilentlyContinue 
        }
    
        # Create a new VM configurable object
        $VM = New-AzureRmVMConfig -VMName $MachineName -VMSize "Standard_A1" -AvailabilitySetID $AvailabilitySet.Id
    
        # Set the Operating System for the new VM
        # Create a new Windows VM
        $VM = Set-AzureRmVMOperatingSystem -VM $VM -Windows -Credential $VMCredential -ComputerName $MachineName
        $VM = Set-AzureRmVMSourceImage -VM $VM -PublisherName MicrosoftWindowsServer -Offer WindowsServer -Skus 2012-R2-Datacenter -Version "latest"

        # Storage - create a new storage accounot if needed
        try {

            $StorageAccount = Get-AzureRmStorageAccount -ResourceGroupName $ResourceGroup -Name $StorageName -ErrorAction Stop
        } catch {

            $StorageAccount = New-AzureRmStorageAccount -ResourceGroupName $ResourceGroup -Name $StorageName -Type "Standard_LRS" -Location $Location -WarningAction SilentlyContinue
        }

        #Network - create new network attributes if needed
        try {

            $PIp = Get-AzureRmPublicIpAddress -Name $PIpName -ResourceGroupName $ResourceGroup -ErrorAction Stop
        } catch {

            $PIp = New-AzureRmPublicIpAddress -Name $PIpName -ResourceGroupName $ResourceGroup -Location $Location -AllocationMethod Dynamic -WarningAction SilentlyContinue
        }

        try {

            $SubnetConfig = Get-AzureRmVirtualNetworkSubnetConfig -Name "default" -VirtualNetwork $VNetName -ErrorAction Stop
        } catch {

            $SubnetConfig = New-AzureRmVirtualNetworkSubnetConfig -Name "default" -AddressPrefix "10.0.0.0/24" -WarningAction SilentlyContinue
        }

        try {

            $VNet = Get-AzureRmVirtualNetwork -Name $VNetName -ResourceGroupName $ResourceGroup -ErrorAction Stop
        } catch {

            $VNet = New-AzureRmVirtualNetwork -Name $VNetName -ResourceGroupName $ResourceGroup -Location $Location -AddressPrefix "10.0.0.0/16" -Subnet $SubnetConfig -WarningAction SilentlyContinue
        }

        try {
            $Interface = Get-AzureRmNetworkInterface -Name $InterfaceName -ResourceGroupName $ResourceGroup -SubnetId $VNet.Subnets[0].Id -PublicIpAddressId $PIp.Id -ErrorAction Stop
        } catch {

            $Interface = New-AzureRmNetworkInterface -Name $InterfaceName -ResourceGroupName $ResourceGroup -Location $Location -SubnetId $VNet.Subnets[0].Id -PublicIpAddressId $PIp.Id -WarningAction SilentlyContinue
        }
   
        $VM = Add-AzureRmVMNetworkInterface -VM $VM -Id $Interface.Id

        # Setup local VM Object
        $OSDiskUri = $StorageAccount.PrimaryEndpoints.Blob.ToString() + "vhds/" + $OSDiskName + ".vhd"
        $VM = Set-AzureRmVMOSDisk -VM $VM -Name $OSDiskName -VhdUri $OSDiskUri -CreateOption FromImage

        # Create the new VM
        New-AzureRmVM -ResourceGroupName $ResourceGroup -Location $Location -VM $VM -WarningAction SilentlyContinue
    }

    # Enable the MMAgent extension if needed
    try {

        Get-AzureRMVMExtension -ResourceGroupName $ResourceGroup -VMName $MachineName -Name 'MicrosoftMonitoringAgent' -ErrorAction Stop
    } catch {

        Set-AzureRMVMExtension -ResourceGroupName $ResourceGroup -VMName $MachineName -Name 'MicrosoftMonitoringAgent' -Publisher 'Microsoft.EnterpriseCloud.Monitoring' -ExtensionType 'MicrosoftMonitoringAgent' -TypeHandlerVersion '1.0' -Location $location -SettingString "{'workspaceId':  '$workspaceId'}" -ProtectedSettingString "{'workspaceKey': '$workspaceKey' }"

    }
       

    # Add the HybridRunbookWorker Module to the Automation Account
    # The below code is based off of code written by Joe Levy at https://github.com/azureautomation/runbooks/blob/master/Utility/Update-ModulesInAutomationToLatestVersion.ps1
    ######################################
    <#
    $ModulesImported = @()

    function _doImport {
        param(
            [Parameter(Mandatory=$true)]
            [String] $ResourceGroupName,

            [Parameter(Mandatory=$true)]
            [String] $AutomationAccountName,
    
            [Parameter(Mandatory=$true)]
            [String] $ModuleName,

            # if not specified latest version will be imported
            [Parameter(Mandatory=$false)]
            [String] $ModuleVersion
        )

        $Url = "https://www.powershellgallery.com/api/v2/Search()?`$filter=IsLatestVersion&searchTerm=%27$ModuleName%27&targetFramework=%27%27&includePrerelease=false&`$skip=0&`$top=40" 
        $SearchResult = Invoke-RestMethod -Method Get -Uri $Url -UseBasicParsing

        if($SearchResult.Length -and $SearchResult.Length -gt 1) {

            $SearchResult = $SearchResult | Where-Object -FilterScript {
                return $_.properties.title -eq $ModuleName
            }
        }

        if(!$SearchResult) {

            Write-Error "Could not find module '$ModuleName' on PowerShell Gallery."
        }
        else {
            $ModuleName = $SearchResult.properties.title # get correct casing for the module name
            $PackageDetails = Invoke-RestMethod -Method Get -UseBasicParsing -Uri $SearchResult.id 
    
            if(!$ModuleVersion) {
                # get latest version
                $ModuleVersion = $PackageDetails.entry.properties.version
            }

            $ModuleContentUrl = "https://www.powershellgallery.com/api/v2/package/$ModuleName/$ModuleVersion"

            # Make sure module dependencies are imported
            $Dependencies = $PackageDetails.entry.properties.dependencies

            if($Dependencies -and $Dependencies.Length -gt 0) {
                $Dependencies = $Dependencies.Split("|")

                # parse depencencies, which are in the format: module1name:module1version:|module2name:module2version:
                $Dependencies | ForEach-Object {

                    if($_ -and $_.Length -gt 0) {

                        $Parts = $_.Split(":")
                        $DependencyName = $Parts[0]
                        $DependencyVersion = $Parts[1]

                        # check if we already imported this dependency module during execution of this script
                        if(!$ModulesImported.Contains($DependencyName)) {

                            $AutomationModule = Get-AzureRmAutomationModule `
                                -ResourceGroupName $ResourceGroupName `
                                -AutomationAccountName $AutomationAccountName `
                                -Name $DependencyName `
                                -ErrorAction SilentlyContinue
    
                            # check if Automation account already contains this dependency module of the right version
                            if((!$AutomationModule) -or $AutomationModule.Version -ne $DependencyVersion) {
                                
                                Write-Output "Importing dependency module $DependencyName of version $DependencyVersion first."

                                # this dependency module has not been imported, import it first
                                _doImport `
                                    -ResourceGroupName $ResourceGroupName `
                                    -AutomationAccountName $AutomationAccountName `
                                    -ModuleName $DependencyName `
                                    -ModuleVersion $DependencyVersion

                                $ModulesImported += $DependencyName
                            }
                        }
                    }
                }
            }
            
            # Find the actual blob storage location of the module
            do {

                $ActualUrl = $ModuleContentUrl
                $ModuleContentUrl = (Invoke-WebRequest -Uri $ModuleContentUrl -MaximumRedirection 0 -UseBasicParsing -ErrorAction Ignore).Headers.Location 
            } while(!$ModuleContentUrl.Contains(".nupkg"))

            $ActualUrl = $ModuleContentUrl

            Write-Output "Importing $ModuleName module of version $ModuleVersion from $ActualUrl to Automation"

            $AutomationModule = New-AzureRmAutomationModule `
                -ResourceGroupName $ResourceGroup `
                -AutomationAccountName $AutomationAccountName `
                -Name $ModuleName `
                -ContentLink $ActualUrl

            while(

                $AutomationModule.ProvisioningState -ne "Created" -and
                $AutomationModule.ProvisioningState -ne "Succeeded" -and
                $AutomationModule.ProvisioningState -ne "Failed"
            )
            {
                Write-Verbose -Message "Polling for module import completion"
                Start-Sleep -Seconds 10
                $AutomationModule = $AutomationModule | Get-AzureRmAutomationModule
            }

            if($AutomationModule.ProvisioningState -eq "Failed") {

                Write-Error "Importing $ModuleName module to Automation failed."
            }
            else {

                Write-Output "Importing $ModuleName module to Automation succeeded."
            }
        }
    }

    if(!$ServicePrincipalConnection) {

        throw "Connection $ConnectionAssetName not found."
    }

    $Module = Get-AzureRmAutomationModule -ResourceGroupName $ResourceGroup -AutomationAccountName $AutomationAccountName -Name "HybridRunbookWorker"

    $ModuleName = $Module.Name

    $ModuleVersionInAutomation = $Module.Version

    Write-Output "Checking if module '$ModuleName' is up to date in your automation account"


    $Url = "https://www.powershellgallery.com/api/v2/Search()?`$filter=IsLatestVersion&searchTerm=%27$ModuleName%27&targetFramework=%27%27&includePrerelease=false&`$skip=0&`$top=40" 

    $SearchResult = Invoke-RestMethod -Method Get -Uri $Url -UseBasicParsing



    if($SearchResult.Length -and $SearchResult.Length -gt 1) {

        $SearchResult = $SearchResult | Where-Object -FilterScript {

            return $_.properties.title -eq $ModuleName
        }
    }

    if(!$SearchResult) {

        Write-Error "Could not find module '$ModuleName' on PowerShell Gallery."
    }

    else {
        $PackageDetails = Invoke-RestMethod -Method Get -UseBasicParsing -Uri $SearchResult.id 
        $LatestModuleVersionOnPSGallery = $PackageDetails.entry.properties.version

        if($ModuleVersionInAutomation -ne $LatestModuleVersionOnPSGallery) {

            Write-Output "Module '$ModuleName' is not up to date. Latest version on PS Gallery is '$LatestModuleVersionOnPSGallery' but this automation account has version '$ModuleVersionInAutomation'"

            Write-Output "Importing latest version of '$ModuleName' into your automation account"

            _doImport -ResourceGroupName $ResourceGroup -AutomationAccountName $AutomationAccountName -ModuleName $ModuleName
        }

        else {

            Write-Output "Module '$ModuleName' is up to date."
        }
    }
    ##########################
    #>

    # Enable the DSC extension if needed
    try {
        Get-AzureRMVMDscExtension -ResourceGroupName $ResourceGroup -VMName $VMachineName -Name 'DSC'-ErrorAction Stop
    } catch {
        # Install the necessary modules
        Install-Module -Name xPSDesiredStateConfiguration  
        Install-Module -Name HybridRunbookWorker  

    
        # Enable the DSC extension on the VM
        Set-AzureRMVMExtension -ResourceGroupName $ResourceGroup -VMName $MachineName -Name 'DSC' -Publisher 'Microsoft.Powershell' -ExtensionType 'DSC' -TypeHandlerVersion '2.20' -Location $location
    }

    # Register the VM as a DSC Node
    #$DscNode = 
    Register-AzureRmAutomationDscNode -AutomationAccountName $AutomationAccountName -AzureVMName $MachineName -ResourceGroupName $ResourceGroup

    # Publish DSC Configuration within storage account
    #Publish-AzureRmVMDscConfiguration -ConfigurationPath .\HybridWorkerConfiguration.ps1 -ResourceGroupName $ResourceGroup -StorageAccountName $StorageName

    # Configure the DSC node
    #Set-AzureRmAutomationDscNode -ResourceGroupName $ResourceGroup  -NodeConfigurationName "HybridRunbookWorkerConfig" -Id $DscNode.Id


} else {
    # Do some on-premise stuff
}

<#
# Register Hybrid Worker
Import-Module ./HybridResgitration.ps1
Add-HybridRunbookWorker -Name $MachineName -EndPoint $EndPoint -Token $Token
#>