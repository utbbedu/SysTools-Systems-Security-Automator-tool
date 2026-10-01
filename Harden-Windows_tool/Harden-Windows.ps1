# Harden-Windows.ps1
param(
    [ValidateSet('Audit','Apply')]
    [string]$Mode = 'Audit'
)

# ======================= SET YOUR TOOL NAME HERE =======================
$ToolName = 'Guarder'
# =======================================================================

# Category labels used in the code and the report.
$BASELINE = 'Microsoft Security Baseline'
$ADVANCED = 'Advanced hardening'

# The list every New-Check call registers into.
$script:Checks = @()

# ---------- Helper: are we running as Administrator? (done for you) ----------
function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($id)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ---------- Helper: show a pop-up, fall back to the console (done for you) ----------
function Show-Popup {
    param([string]$Message, [string]$Title)
    try {
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        [void][System.Windows.Forms.MessageBox]::Show($Message, $Title)
    } catch {
        Write-Host ('[' + $Title + '] ' + $Message) -ForegroundColor Magenta
    }
}

# ---------- Helper: rate a score (done for you) ----------
function Get-Rating {
    param([int]$Score)
    if ($Score -ge 85)      { return 'STRONG' }
    elseif ($Score -ge 60)  { return 'MODERATE' }
    else                    { return 'NEEDS WORK' }
}

# ---------- Register one control (done for you) ----------
# Usage:  New-Check <Category> '<Name>' { Test returns @{Pass=..;Detail=..} } { Remediate } <Weight>
# Pass $null for the Remediate block to make a control audit only.
function New-Check {
    param(
        [string]$Category,
        [string]$Name,
        [scriptblock]$Test,
        [scriptblock]$Remediate,
        [int]$Weight = 10
    )
    $script:Checks += [pscustomobject]@{
        Category  = $Category
        Name      = $Name
        Test      = $Test
        Remediate = $Remediate
        Weight    = $Weight
    }
}

# =======================================================================
#  Microsoft Security Baseline controls  (category: $BASELINE)
# =======================================================================

# SMBv1 disabled  (DONE: finished example, copy this shape)
New-Check $BASELINE 'SMBv1 disabled' {                 # TEST block starts here
    $c = Get-SmbServerConfiguration -ErrorAction Stop
    @{ Pass = [bool](-not $c.EnableSMB1Protocol); Detail = "EnableSMB1Protocol=$($c.EnableSMB1Protocol)" }
} {                                                    # TEST ends, REMEDIATE starts
    Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force
} 10                                                   # REMEDIATE ends, weight 10

# SMB server signing required  (DONE: the worked example in handout Part B)
New-Check $BASELINE 'SMB server signing required' {
    $c = Get-SmbServerConfiguration -ErrorAction Stop
    @{ Pass = [bool]$c.RequireSecuritySignature; Detail = "RequireSecuritySignature=$($c.RequireSecuritySignature)" }
} {
    Set-SmbServerConfiguration -RequireSecuritySignature $true -Force
} 10

# TODO 1 of 13: NTLM hardened. Use the handout Part B, Microsoft Security Baseline controls table, row "NTLM hardened".
#   Replace the TEST block, then replace $null with a REMEDIATE block.
#   Tip: this value may not exist on a new VM. Add -ErrorAction SilentlyContinue
#   to Get-ItemProperty so a missing value reports FAIL instead of an error.
New-Check $BASELINE 'NTLM hardened (LmCompatibilityLevel = 5)' {
    $c = [int](Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -ErrorAction SilentlyContinue).LmCompatibilityLevel
    @{ Pass = ($c -eq 5); Detail = "LmCompatibilityLevel=$c"}
} {
     Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LmCompatibilityLevel -Value 5 -Type DWord
} 10

# TODO 2 of 13: UAC enabled. Use the handout Part B, Microsoft Security Baseline controls table, row "UAC enabled".
New-Check $BASELINE 'User Account Control (UAC) enabled' {
    $c = (Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA).EnableLUA
    @{ Pass = ($c -eq 1); Detail = "EnableLUA=$c" }
} {
    Set-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name EnableLUA -Value 1 -Type DWord
} 10

# TODO 3 of 13: Minimum password length. Use the handout Part B, Microsoft Security Baseline controls table, row "Min password length 14".
#   Tip: (net accounts) returns lines of text. Find the line containing
#   'Minimum password length' and read the number at the end of it.
New-Check $BASELINE 'Minimum password length 14 or more' {
    $c = [int]((net accounts | Select-String "Minimum password length") -replace '\D')
    @{ Pass = ($c -ge 14); Detail = "Minimum password length=$c" }
} {
    net accounts/minpwlen:14
} 10

# TODO 4 of 13: Lockout threshold. Use the handout Part B, Microsoft Security Baseline controls table, row "Lockout threshold 1..10".
#   Pass when the number is from 1 to 10. A value of Never (0) fails.
New-Check $BASELINE 'Account lockout threshold 1 to 10' {
    $check = (net accounts | Select-String "Lockout threshold") -replace '\D'
    $c = if ($check) { [int]$check } else {0 }
    @{ Pass = ($c -ge 1 -and $c -le 10); Detail = "Lockout threshold=$c" }
} { net accounts /lockoutthreshold:10
} 10

# TODO 5 of 13: Firewall. Use the handout Part B, Microsoft Security Baseline controls table, row "Firewall all profiles".
New-Check $BASELINE 'Firewall enabled on all profiles' {
    $c = (Get-NetFirewallProfile).Enabled 
    @{ Pass = ($c -notcontains $false); Detail = "Firewall profile statuses: $($c -join ', ')" }
} { Set-NetFirewallProfile -Profile Domain,Public,Private Enabled True
} 10

# TODO 6 of 13: Defender real-time protection. Use the handout Part B, Microsoft Security Baseline controls table, row "Defender real-time on".
New-Check $BASELINE 'Defender real-time protection on' {
    $c = (Get-MpPreference).DisableRealtimeMonitoring
    @{ Pass = ($c -eq $false); Detail = "DisableRealtimeMonitoring=$c" }
} { Set-MpPreference DisableRealtimeMonitoring $false
} 10

# TODO 7 of 13: Guest account. Use the handout Part B, Microsoft Security Baseline controls table, row "Guest account disabled".
New-Check $BASELINE 'Guest account disabled' {
    $c = (Get-LocalUser -Name Guest).Enabled
    @{ Pass = ($c -eq $false); Detail = "Guest Enabled=$c" }
} { Disable-LocalUser -Name Guest
} 10

# TODO 8 of 13: RDP requires NLA. Use the handout Part B, Microsoft Security Baseline controls table, row "RDP requires NLA".
#   The handout shortens the registry path with "...". The full path is:
#   'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp'
New-Check $BASELINE 'RDP requires Network Level Authentication' {
    $c = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name UserAuthentication).UserAuthentication
    $c -is [int]
    @{ Pass = $c -eq 1; Detail = "UserAuthentication=$c" }
} { Set-ItemProperty (same path) -Name UserAuthentication Value 1 -Type DWord
} 10

# =======================================================================
#  Advanced controls (beyond the baseline)  (category: $ADVANCED)
# =======================================================================

# TODO 9 of 13: Defender PUA protection. Use the handout Part B, Advanced controls table, row "Defender PUA protection".
New-Check $ADVANCED 'Defender PUA protection on' {
    $c = [int](Get-MpPreference).PUAProtection
    @{ Pass = ($c -eq 1); Detail = "PUAProtection=$c" }
} { Set-MpPreference PUAProtection 1
} 8

# TODO 10 of 13: ASR rule. Use the handout Part B, Advanced controls table, row "ASR: block Office child procs".
#   Tip: (Get-MpPreference) has two matching lists, AttackSurfaceReductionRules_Ids
#   and AttackSurfaceReductionRules_Actions. Find the position of the rule id in
#   the first list, then check that the same position in the second list is 1.
New-Check $ADVANCED 'ASR: block Office child processes' {
    $g = Get-MpPreference
    $id = "D4F940AB-401B-4EFC-AADC-AD5F3C50688A"
    $i = [array]::IndexOf(@($g.AttackSurfaceReductionRules_Ids), $id)

    $c = [int](@($g.AttackSurfaceReductionRules_Actions)[$i])

    #$c = if ($i -ge 0) { $g.AttackSurfaceReductionRules_Actions[$i] } else { $null }
    #$c

    @{ Pass = ($c -eq 1); Detail = "ASR blocking=$c" }
} { Add-MpPreference -AttackSurfaceReductionRules_Ids D4F940AB-401B4EFC-AADC-AD5F3C50688A -AttackSurfaceReductionRules_Actions Enabled
} $null 8

# TODO 11 of 13: Script block logging. Use the handout Part B, Advanced controls table, row "Script block logging".
#   Read the value itself, not the whole object, and allow for a missing key:
#   (Get-ItemProperty '<path>' -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue).EnableScriptBlockLogging -eq 1
New-Check $ADVANCED 'PowerShell script block logging on' {
    $c = [int](Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue).EnableScriptBlockLogging
    @{ Pass = ($c -eq 1); Detail = "EnableScriptBlocklogging=$c" }
} { New-Item 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -Force; Set-ItemProperty -Name EnableScriptBlockLogging -Value 1 -Type DWord
} 8

# TODO 12 of 13: LSA protection. Use the handout Part B, Advanced controls table, row "LSA protection (RunAsPPL)".
#   Tip: add -ErrorAction SilentlyContinue; RunAsPPL may not exist on a new VM.
New-Check $ADVANCED 'LSA protection (RunAsPPL) on' {
    $c = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -ErrorAction SilentlyContinue).RunAsPPL
    @{ Pass = ($c -eq 1); Detail = "RunAsPPL=$c" }
} { Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -Value 1 -Type DWord
} 8

# TODO 13 of 13: BitLocker. Use the handout Part B, Advanced controls table, row "BitLocker on system drive".
#   AUDIT ONLY: write the TEST block, but KEEP $null. Do not add a REMEDIATE block.
New-Check $ADVANCED 'BitLocker on system drive' {
     $c = (Get-BitLockerVolume -MountPoint $env:SystemDrive).ProtectionStatus
    @{ Pass = ($c -eq 'On'); Detail = "ProtectionStatus=$c" }
} {
} $null 6

# =======================================================================
#  Engine (done for you): audit, apply, report
# =======================================================================

# Run every check, print a grouped report, compute the weighted score.
function Invoke-Audit {
    param([string]$Label = '')

    $results = @()
    foreach ($c in $script:Checks) {
        try {
            $r = & $c.Test
        } catch {
            $r = @{ Pass = $false; Detail = ('error: ' + $_.Exception.Message) }
        }
        $results += [pscustomobject]@{
            Category = $c.Category
            Name     = $c.Name
            Pass     = [bool]$r.Pass
            Detail   = [string]$r.Detail
            Weight   = [int]$c.Weight
        }
    }

    $total  = ($script:Checks | Measure-Object -Property Weight -Sum).Sum
    $earned = (@($results | Where-Object { $_.Pass }) | Measure-Object -Property Weight -Sum).Sum
    if (-not $total)  { $total  = 1 }
    if (-not $earned) { $earned = 0 }
    $score  = [math]::Round(($earned / $total) * 100)
    $rating = Get-Rating -Score $score

    $header = '=== Windows Security Audit ==='
    if ($Label) { $header = $header + '  [' + $Label + ']' }
    Write-Host ''
    Write-Host $header -ForegroundColor Cyan

    foreach ($cat in @($BASELINE, $ADVANCED)) {
        $catResults = @($results | Where-Object { $_.Category -eq $cat })
        if ($catResults.Count -eq 0) { continue }
        $catPass = @($catResults | Where-Object { $_.Pass }).Count
        Write-Host ''
        Write-Host ('-- ' + $cat + '  (' + $catPass + ' of ' + $catResults.Count + ' passing) --') -ForegroundColor White
        foreach ($x in $catResults) {
            if ($x.Pass) {
                Write-Host ('  [PASS] ' + $x.Name) -ForegroundColor Green
            } else {
                Write-Host ('  [FAIL] ' + $x.Name + '  ->  ' + $x.Detail) -ForegroundColor Red
            }
        }
    }

    Write-Host ''
    Write-Host ('Security score: ' + $score + ' / 100   (' + $rating + ')') -ForegroundColor Yellow
    Write-Host ''

    return [pscustomobject]@{
        Label   = $Label
        Results = $results
        Earned  = $earned
        Total   = $total
        Score   = $score
        Rating  = $rating
    }
}

# Make a restore point, then remediate every failing control that has a fix.
function Invoke-Apply {
    $actions = @()

    try {
        Enable-ComputerRestore -Drive 'C:\' -ErrorAction SilentlyContinue
        Checkpoint-Computer -Description ('Before ' + $ToolName + ' hardening') -RestorePointType MODIFY_SETTINGS -ErrorAction Stop
        $actions += 'Created a System Restore Point (your undo button).'
    } catch {
        $actions += 'Could not create a restore point (it may be off or rate limited). Continuing.'
    }

    foreach ($c in $script:Checks) {
        if ($null -eq $c.Remediate) { continue }        # audit-only control
        try { $r = & $c.Test } catch { $r = @{ Pass = $false } }
        if ([bool]$r.Pass) { continue }                 # already passing
        try {
            & $c.Remediate
            $note = 'Remediated: ' + $c.Name
            if ($c.Name -match 'UAC' -or $c.Name -match 'LSA') {
                $note = $note + '   (reboot required to take effect)'
            }
            $actions += $note
        } catch {
            $actions += ('Remediation failed: ' + $c.Name + '  ->  ' + $_.Exception.Message)
        }
    }

    return $actions
}

# Write a timestamped, grouped report and return its path.
function Write-Report {
    param([array]$Summaries, [array]$Actions)

    $dir = Join-Path $env:USERPROFILE ($ToolName + '_reports')
    if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $path  = Join-Path $dir ($ToolName + '_report_' + $stamp + '.txt')

    $lines = @()
    $lines += ($ToolName + ' Security Report')
    $lines += ('Generated: ' + (Get-Date))
    $lines += ('Computer:  ' + $env:COMPUTERNAME)
    $lines += ''

    foreach ($s in $Summaries) {
        $title = 'AUDIT'
        if ($s.Label) { $title = $s.Label }
        $lines += ('===== ' + $title + ' =====')
        foreach ($cat in @($BASELINE, $ADVANCED)) {
            $cr = @($s.Results | Where-Object { $_.Category -eq $cat })
            if ($cr.Count -eq 0) { continue }
            $cp = @($cr | Where-Object { $_.Pass }).Count
            $lines += ''
            $lines += ('-- ' + $cat + '  (' + $cp + ' of ' + $cr.Count + ' passing) --')
            foreach ($x in $cr) {
                $flag = '[FAIL]'
                if ($x.Pass) { $flag = '[PASS]' }
                $lines += ('  ' + $flag + ' ' + $x.Name + '  ->  ' + $x.Detail)
            }
        }
        $lines += ''
        $lines += ('Security score: ' + $s.Score + ' / 100  (' + $s.Rating + ')')
        $lines += ''
    }

    if ($Actions -and $Actions.Count -gt 0) {
        $lines += '===== Applying hardening ====='
        foreach ($a in $Actions) { $lines += ('  ' + $a) }
        $lines += ''
    }

    $lines | Out-File -FilePath $path -Encoding UTF8
    return $path
}

# =======================================================================
#  Main (done for you)
# =======================================================================

Write-Host ($ToolName + ' Windows Hardening Toolkit') -ForegroundColor Cyan
Show-Popup ($ToolName + ' is starting a security ' + $Mode + '.') ($ToolName + ' starting')

$elevated = Test-Admin
if (-not $elevated) {
    Write-Host 'Note: you are NOT running as Administrator.' -ForegroundColor Yellow
    Write-Host 'Audit will run, but some checks and all fixes need Administrator.' -ForegroundColor Yellow
}

if ($Mode -eq 'Apply') {
    if (-not $elevated) {
        Write-Host 'Apply mode needs Administrator. Re-open PowerShell as administrator and run again with -Mode Apply.' -ForegroundColor Red
        Show-Popup 'Apply mode needs Administrator. Re-run in an elevated PowerShell.' ($ToolName + ' stopped')
        return
    }

    $before = Invoke-Audit -Label 'BEFORE'

    Write-Host '=== Applying safe hardening fixes ===' -ForegroundColor Cyan
    $actions = Invoke-Apply
    foreach ($a in $actions) { Write-Host ('  ' + $a) -ForegroundColor Green }

    $after = Invoke-Audit -Label 'AFTER'

    $report = Write-Report -Summaries @($before, $after) -Actions $actions
    Write-Host ('Report written: ' + $report) -ForegroundColor Cyan

    Show-Popup ($ToolName + ' apply complete.  Before ' + $before.Score + ' / 100,  After ' + $after.Score + ' / 100  (' + $after.Rating + ')') ($ToolName + ' complete')
}
else {
    $audit = Invoke-Audit

    $report = Write-Report -Summaries @($audit) -Actions @()
    Write-Host ('Report written: ' + $report) -ForegroundColor Cyan

    Show-Popup ($ToolName + ' audit complete.  Score ' + $audit.Score + ' / 100  (' + $audit.Rating + ')') ($ToolName + ' complete')
}
