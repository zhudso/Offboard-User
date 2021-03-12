function Write-Notes{
    [CmdletBinding()]
    param (
        [Parameter(ValueFromPipeline=$true)]
        $pipeValue,
        [Parameter()]
        $Message,
        [Parameter()]
        $FileName = "Offboarding Notes",
        [Parameter()]
        $FilePath = "$env:USERPROFILE\Desktop"
    )
    ForEach ($pValue in $pipeValue) {
        Write-Output $pipeValue
        <# $pValue | Out-File "$FilePath\$FileName.txt" -Append #>
    }
        $Message | Out-File "$FilePath\$FileName.txt" -Append
}
<# Out-File $env:USERPROFILE\Desktop\"$user ADgroups.txt" #>
function Backup-User {
    <# Show Original Object Location #>
    $ObjectLocation = Get-ADUser -identity $User -Properties CanonicalName | select-object -ExpandProperty CanonicalName
    Write-Notes -Message "Original Object location: $ObjectLocation"
    <# Backup the current groups to the desktop in a .txt file #>
    Get-ADPrincipalGroupMembership -Identity $User | Select-Object Name | Out-file $env:userprofile\desktop\$User ADGroups.txt"
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
        Write-Warning "Unable to move user account. There are multiple or no OU's found on the search condition of 'Mailbox Retention'. Please provide the OU name or manually move the user"
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

function Offboard-User {
    param (
        [parameter(Mandatory, Position=0)]
        [ValidateScript({get-aduser -id $_})]
        [string]$User
        )
        Write-Notes -Message "Logged into server: $env:COMPUTERNAME"
        Backup-User
        Set-ADUser $User -Enabled $false
        Write-Notes -Message "Disabled user"
        Set-Password
        Move-User
        Remove-DistributionGroups
        <# For whatever reason, -erroraction doesn't do anything on hiding from GAL #>
        $OldErrorActionPreference = $global:ErrorActionPreference
        $global:ErrorActionPreference = "SilentlyContinue"
        Set-ADUser -Identity $User -Replace @{msExchHideFromAddressLists="TRUE"} -ErrorAction SilentlyContinue
        $global:ErrorActionPreference = $OldErrorActionPreference
}