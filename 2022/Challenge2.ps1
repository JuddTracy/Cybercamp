
function Get-IniFile {
  <#
    .SYNOPSIS
    Read an ini file.

    .DESCRIPTION
    Reads an ini file into a hash table of sections with keys and values.

    .PARAMETER filePath
    The path to the INI file.

    .PARAMETER anonymous
    The section name to use for the anonymous section (keys that come before any section declaration).

    .PARAMETER comments
    Enables saving of comments to a comment section in the resulting hash table.
    The comments for each section will be stored in a section that has the same name as the section of its origin, but has the comment suffix appended.
    Comments will be keyed with the comment key prefix and a sequence number for the comment. The sequence number is reset for every section.

    .PARAMETER commentsSectionsSuffix
    The suffix for comment sections. The default value is an underscore ('_').
    .PARAMETER commentsKeyPrefix
    The prefix for comment keys. The default value is 'Comment'.

    .EXAMPLE
    Get-IniFile /path/to/my/inifile.ini

    .NOTES
    The resulting hash table has the form [sectionName->sectionContent], where sectionName is a string and sectionContent is a hash table of the form [key->value] where both are strings.
    This function is largely copied from https://stackoverflow.com/a/43697842/1031534. An improved version has since been pulished at https://gist.github.com/beruic/1be71ae570646bca40734280ea357e3c.
    #>

  param(
    [parameter(Mandatory = $true)] [string] $filePath,
    [string] $anonymous = 'NoSection',
    [switch] $comments,
    [string] $commentsSectionsSuffix = '_',
    [string] $commentsKeyPrefix = 'Comment'
  )

  $ini = @{}
  switch -regex -file ($filePath) {
    "^\[(.+)\]$" {
      # Section
      $section = $matches[1]
      $ini[$section] = @{}
      $CommentCount = 0
      if ($comments) {
        $commentsSection = $section + $commentsSectionsSuffix
        $ini[$commentsSection] = @{}
      }
      continue
    }

    "^(;.*)$" {
      # Comment
      if ($comments) {
        if (!($section)) {
          $section = $anonymous
          $ini[$section] = @{}
        }
        $value = $matches[1]
        $CommentCount = $CommentCount + 1
        $name = $commentsKeyPrefix + $CommentCount
        $commentsSection = $section + $commentsSectionsSuffix
        $ini[$commentsSection][$name] = $value
      }
      continue
    }

    "^(.+?)\s*=\s*(.*)$" {
      # Key
      if (!($section)) {
        $section = $anonymous
        $ini[$section] = @{}
      }
      $name, $value = $matches[1..2]
      $ini[$section][$name] = $value
      continue
    }
  }

  return $ini
}

function Parse-SecPol {
  [CmdletBinding()]
  param (
    # Clear cache
    [Parameter()]
    [Switch]
    $ClearCache
  )

  if (-not (Test-Path variable:script:Secpol) -or $ClearCache) {
    $SecpolTempfile = New-TemporaryFile
    Write-Host $SecpolTempfile
    secedit /export /cfg "$SecpolTempfile" | Out-Null
    $script:Secpol = Get-IniFile -filePath $SecpolTempfile

    Remove-Item $SecpolTempfile
  }

  $script:Secpol
}

function Get-PassowrdPolicyLockoutThreshold {
  [CmdletBinding()]
  param (
    # Clear cache
    [Parameter()]
    [Switch]
    $ClearCache
  )

  $Secpol = Parse-SecPol -ClearCache:$ClearCache

  $Secpol.'System Access'.LockoutBadCount
}

function Get-PassowrdPolicyHistory {
  [CmdletBinding()]
  param (
    # Clear cache
    [Parameter()]
    [Switch]
    $ClearCache
  )

  $Secpol = Parse-SecPol -ClearCache:$ClearCache

  $Secpol.'System Access'.PasswordHistorySize
}

function Get-PasswordPolicyMaximumAge {
  [CmdletBinding()]
  param (
    # Clear cache
    [Parameter()]
    [Switch]
    $ClearCache
  )

  $Secpol = Parse-SecPol -ClearCache:$ClearCache

  $Secpol.'System Access'.MaximumPasswordAge
}

function Get-PasswordPolicyMinimumAge {
  [CmdletBinding()]
  param (
    # Clear cache
    [Parameter()]
    [Switch]
    $ClearCache
  )

  $Secpol = Parse-SecPol -ClearCache:$ClearCache

  $Secpol.'System Access'.MinimumPasswordAge
}

function Get-PasswordPolicyPasswordLength {
  [CmdletBinding()]
  param (
    # Clear cache
    [Parameter()]
    [Switch]
    $ClearCache
  )

  $Secpol = Parse-SecPol -ClearCache:$ClearCache

  $Secpol.'System Access'.MinimumPasswordLength
}

function Get-PasswordPolicyComplexityEnabled {
  [CmdletBinding()]
  param (
    # Clear cache
    [Parameter()]
    [Switch]
    $ClearCache
  )

  $Secpol = Parse-SecPol -ClearCache:$ClearCache

  $Secpol.'System Access'.PasswordComplexity
}

function Get-PasswordPolicyClearTextPassword {
  [CmdletBinding()]
  param (
    # Clear cache
    [Parameter()]
    [Switch]
    $ClearCache
  )

  $Secpol = Parse-SecPol -ClearCache:$ClearCache

  $Secpol.'System Access'.ClearTextPassword
}

function Get-AuditPolicyAuditLogonEventsSuccess {
  [CmdletBinding()]
  param (
    # Clear cache
    [Parameter()]
    [Switch]
    $ClearCache
  )

  $Secpol = Parse-SecPol -ClearCache:$ClearCache

  if ($Secpol.'Event Audit'.AuditAccountLogon -band 1) {
    $true
  }
  else {
    $False
  }
}

function Get-AuditPolicyAuditLogonEventsFailure {
  [CmdletBinding()]
  param (
    # Clear cache
    [Parameter()]
    [Switch]
    $ClearCache
  )

  $Secpol = Parse-SecPol -ClearCache:$ClearCache

  if ($Secpol.'Event Audit'.AuditAccountLogon -band 2) {
    $true
  }
  else {
    $False
  }

}

function Get-FirewallPublicRulesEnabled {
  [CmdletBinding()]
  param ()

    (Get-NetFirewallProfile | Where-Object { $_.Name -eq 'Public' }).Enabled
}

function Get-FirewallPrivateRulesEnabled {
  [CmdletBinding()]
  param ()

    (Get-NetFirewallProfile | Where-Object { $_.Name -eq 'Private' }).Enabled
}

function Get-LocalAdministrator {
  Get-LocalUser | Where-Object { $_.SID -match "S-1-5-.*-500" }
}

function Get-User {
  [CmdletBinding()]
  param (
    # Filter
    [Parameter(Mandatory = $true)]
    [String]
    $Name


  )
    (Get-LocalUser -Name $Name -ErrorAction SilentlyContinue).Name

}

function Get-Group {
  [CmdletBinding()]
  param (
    # Filter
    [Parameter(Mandatory = $true)]
    [String]
    $Name


  )
    (Get-LocalGroup -Name $Name -ErrorAction SilentlyContinue).Name

}
function Find-File {
  [CmdletBinding()]
  param (
    # Filter
    [Parameter(Mandatory = $true)]
    [String]
    $Filter,

    # Path
    [Parameter()]
    [String[]]
    $Path = 'C:\'
  )

  $Result = Get-ChildItem -Filter $Filter -Path C:\Users\judd\Hidden\ -Recurse -ErrorAction SilentlyContinue -Force

  $List = @()
  $Result | ForEach-Object {
    $List += $_.FullName
  }
  return , $List

  # if ($null -eq $Result) {
  #     return ,@()
  # } else {
  #     @($Result.FullName)
  # }
}

function Find-Share {
  [CmdletBinding()]
  param (
    # Filter
    [Parameter(Mandatory = $true)]
    [String]
    $Name
  )
  , @(Get-SmbShare | Where-Object { $_.Name -eq $Name })

}

function Find-ScheduledTasks {
  [CmdletBinding()]
  param (
    # Filter
    [Parameter(Mandatory = $true)]
    [String]
    $Author
  )
  , @(Get-ScheduledTask | Where-Object { $_.Author -match $Author })
}

function Get-MachineInteractiveTimeout {
  $reg = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -name "InactivityTimeoutSecs"
  $reg.InactivityTimeoutSecs
}

function Get-UACElevateWitoutSecureDesktop {
  $reg = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -name "EnableUIADesktopToggle"
  $reg.EnableUIADesktopToggle -eq $false
}

function Get-RemoteDesktopDisabled {
  $reg = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -name "fDenyTSConnections"
  $reg.fDenyTSConnections -eq 1
}


function Get-WindowsDefenderEnabled {
  $status = Get-MpComputerStatus

    ($null -ne $status) -and ($status.AntivirusEnabled -eq $true)
}

function Verify-UserInGroup {
  [CmdletBinding()]
  param (
    # Group Name
    [Parameter(Mandatory = $true)]
    [Object]
    $Name,

    # User
    [Parameter()]
    [Object]
    $User
  )
  if ($null -eq $User) {
    return $false
  }

  $Found = Get-LocalGroupMember -Name $Name -ErrorAction SilentlyContinue | Where-Object { $_.SID -eq $User.SID }

  if ($null -eq $Found) { $false } else { $true }
}

function Check-Equal {
  [CmdletBinding()]
  param (
    # First
    [Parameter(Mandatory = $true, Position = 0)]
    [AllowNull()]
    [Object]
    $First,
    # Second
    [Parameter(Mandatory = $true, Position = 1)]
    [AllowNull()]
    [Object]
    $Second
  )
  Write-Host ("First: {0}" -f $First)
  Write-Host ("Second: {0}" -f $Second)
  Write-Host ("Check Result: {0}" -f ($First -eq 0))

  $First -eq $Second
}



function Check-NotEqual {
  [CmdletBinding()]
  param (
    # First
    [Parameter(Mandatory = $true, Position = 0)]
    [Object]
    $First,
    # Second
    [Parameter(Mandatory = $true, Position = 1)]
    [Object]
    $Second
  )

  $First -ne $Second
}

function Check-GreaterThanEqual {
  [CmdletBinding()]
  param (
    # First
    [Parameter(Mandatory = $true, Position = 0)]
    [Object]
    $First,
    # Second
    [Parameter(Mandatory = $true, Position = 1)]
    [Object]
    $Second
  )

  $First -ge $Second
}

function Check-LessThanEqual {
  [CmdletBinding()]
  param (
    # First
    [Parameter(Mandatory = $true, Position = 0)]
    [Object]
    $First,
    # Second
    [Parameter(Mandatory = $true, Position = 1)]
    [Object]
    $Second
  )

  $First -le $Second
}

function Check-Empty {
  [CmdletBinding()]
  param (
    # First
    [Parameter(Position = 0)]
    [Object]
    $First = $(),
    # Second
    [Parameter(Position = 1)]
    [String]
    $Second = ''
  )
  #if ($Verbose -gt 0) {
  Write-Host ("First: {0}" -f $First.Length)
  Write-Host ("Second: {0}" -f $Second)
  Write-Host ("Result: {0}" -f ($First.Length -eq 0))
  #}
  $First.Length -eq 0
}

function Check-Between {
  [CmdletBinding()]
  param (
    # First
    [Parameter(Position = 0)]
    [Object]
    $First = $(),
    # Second
    [Parameter(Position = 1)]
    [String]
    $Second = ''
  )
  # Write-Host $First $Second
  $Limits = $Second -split ','
  [int]$First -ge [int]$Limits[0] -and [int]$First -le [int]$Limits[1]
}

$Challenge = Import-Csv -Path .\Challenge2.csv
$Results = $Challenge | ForEach-Object {
  if ($_.Function) {
    $Result = $_

    if ($Verbose -gt 0) {
      Write-Host ("Function: {0}" -f $_.Function)
    }

    $ScriptBlock = [ScriptBlock]::Create($_.Function)
    $Result.ReturnValue = & $ScriptBlock

    if ($Verbose -gt 0) {
      Write-Host ("Result: {0}" -f $Result.ReturnValue)
    }

    $DesiredValue = if ($_.Desiredvaule -eq '$null') { $null } else { $_.DesiredValue }

    if ($Verbose -gt 0) {
      Write-Host ("Check: First = {0}  Second = {1}" -f $Result.ReturnValue, $DesiredValue)
    }

    $CheckResult = & $_.Check $Result.ReturnValue $_.DesiredValue
    Write-Host $CheckResult.GetType()
    if ($CheckResult) {
      if ($Verbose -gt 0) {
        Write-Host ("Setting score: {0}" -f $_.Points)
      }
      $Result.Score = $_.Points
    }
    else {
      if ($Verbose -gt 0) {
        Write-Host "Setting score: 0"
      }
      $Result.Score = 0
    }
    if ($Verbose -gt 0) { Write-Host "" }
    $Result
  }
}

$Results | Select-Object -Property Challenge, Score, DesiredValue, ReturnValue | Format-Table

$Score = $Results | Measure-Object Score -Sum
$Total = $Results | Measure-Object Points -Sum

Write-Host ('Score {0} out of {1}' -f $Score.Sum, $Total.Sum)

$Results | Export-Csv -Path .\Challenge2_Results.csv
