
Skip to content
Pull requests
Issues
Marketplace
Explore
@zhudso
zhudso /
Offboard-User

1
0

    0

Code
Issues
Pull requests
Actions
Projects
Wiki
Security
Insights

    Settings

Offboard-User/UserOffboarding.ps1
@zhudso
zhudso Update UserOffboarding.ps1
Latest commit 9bb0016 9 hours ago
History
1 contributor
104 lines (99 sloc) 4.22 KB
function Write-Notes{
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline=$true)]
        $pipeValue,
        [Parameter()]
        $Message,
        [Parameter()]
        $FileName = "$User Offboarding Notes",
        [Parameter()]
        $FilePath = "$env:USERPROFILE\Desktop"
    )
    begin {
        <# Process each value and get them ready as 1 unit for the process block.
        If no begin block, they'll be processed as single items. #>
    }
    process {
        <# Take each item in the pipeline and write it out to a file. #>
        foreach ($pValue in $pipeValue) {
            $pValue | Out-File "$FilePath\$FileName.txt" -Append
        }
    }
    end {
        <# Take the -message parameter and append the message (once) to the file. #>
        $Message | Out-File "$FilePath\$FileName.txt" -Append
    }
}
function Backup-User {
    <# Show Original Object Location #>
    $ObjectLocation = Get-ADUser -identity $User -Properties CanonicalName | select-object -ExpandProperty CanonicalName
    Write-Notes -Message "Original Object location: $ObjectLocation"
    <# Backup the current groups to the desktop in a .txt file #>
    Get-ADPrincipalGroupMembership -Identity $User | Select-Object -ExpandProperty Name | Write-Notes -FileName "$User ADGroups.txt"
    Write-Notes -Message "Saved copy of Active Directory Groups $env:userprofile\desktop\$User ADGroups.txt"
}
function Set-Password {
    <# Generates a new 8-character password with at least 2 non-alphanumeric character. #>
    Add-Type -AssemblyName System.Web
    $NewPassword = [System.Web.Security.Membership]::GeneratePassword(8,2)
    Write-Notes -Message "Changed user password to: '$NewPassword'"
    Set-ADAccountPassword -Identity $user -Reset -NewPassword (ConvertTo-SecureString -AsPlainText $NewPassword -Force)
}

function Move-User {
    $currentOU = Get-ADUser -identity $user -Properties CanonicalName | select-object -expandproperty DistinguishedName
    $disabledOU = Get-ADOrganizationalUnit -Filter 'Name -like "* - Mailbox Retention"'
    try {
        Move-ADObject -Identity "$currentOU" -TargetPath "$disabledOU"
        Write-Notes -Message "Moved $User to $disabledOU"
    }
    catch {
        Write-Warning "Unable to move user account. There are multiple or no OU's found on the search condition of 'Mailbox Retention'. Please manually move the user to a Disabled OU, I wish I could catch every naming convention"
    }
}

function Remove-DistributionGroups {
    $ADGroups = Get-ADPrincipalGroupMembership -Identity $User | Where-Object {$_.Name -ne "Domain Users"} | Select-Object -ExpandProperty Name
    try {
        foreach ($ADG in $ADGroups) {
            Remove-ADPrincipalGroupMembership -Identity $User -MemberOf $ADG -ErrorAction Stop -Confirm:$false
        }
        Write-Notes -Message "Removed Active Directory groups."
    } 
    catch {
        Write-Output $Error[0]
      }
    }

function Hide-GAL {
    <# For whatever reason, -erroraction doesn't do anything on hiding from GAL #>
    $OldErrorActionPreference = $global:ErrorActionPreference
    $global:ErrorActionPreference = "SilentlyContinue"
    Set-ADUser -Identity $User -Replace @{msExchHideFromAddressLists="TRUE"} -ErrorAction SilentlyContinue
    $GALStatus = Get-ADUser -id $User -properties * | Select-Object -ExpandProperty msExchHideFromAddressLists
    $global:ErrorActionPreference = $OldErrorActionPreference
    if ($GALStatus -eq "TRUE") {
        Write-Notes -Message "Hid $User from global address lists in AD"
    }
    else {
        <# Do nothing, could be that msExchHideFromAddressLists isn't found due to it not being installed/configured. #>
    }
}

function Offboard-User {
    param (
        [parameter(Mandatory, Position=0)]
        [ValidateScript({get-aduser -id $_})]
        [string]$User
        )
        try {
        Write-Notes -Message "Logged into server: $env:COMPUTERNAME"
        Backup-User
        Set-ADUser $User -Enabled $false
        Write-Notes -Message "Disabled user"
        Set-Password
        Move-User
        Remove-DistributionGroups
        Hide-GAL
        <# DIRSYNC COMMAND: SOON TO COME.. #>
        Write-Output "Successfully offboarded user. Please check: $FilePath for your notes."
        }
        catch {
            
        }
}

    © 2021 GitHub, Inc.
    Terms
    Privacy
    Security
    Status
    Docs

    Contact GitHub
    Pricing
    API
    Training
    Blog
    About

