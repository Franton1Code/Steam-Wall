@echo off
setlocal EnableExtensions
title Steam co-op firewall

rem ---- where this file lives (used for the admin relaunch and the allow list) ----
set "SFW_SELF=%~f0"
set "SFW_DIR=%~dp0"

rem ---- administrator rights are required; ask for them if missing ----
fltmc >nul 2>&1
if "%errorlevel%"=="0" goto :menu
echo Asking for administrator rights...
powershell -NoProfile -ExecutionPolicy Bypass -Command "try { Start-Process -FilePath $env:SFW_SELF -Verb RunAs -ErrorAction Stop } catch { Write-Host 'Administrator rights were not given, so nothing was changed.'; exit 1 }"
if errorlevel 1 pause
exit /b 0

:menu
cls
echo ============================================
echo   Steam firewall - keeps Steam co-op working
echo ============================================
echo.
echo   [1] Apply  - block Steam except the allow list
echo   [2] Remove - delete every rule this script made
echo   [3] Status - show the rules that exist now
echo   [4] Quit
echo.
choice /c 1234 /n /m "Choose 1-4: "
set "SFW_MODE=%errorlevel%"
if "%SFW_MODE%"=="4" exit /b 0
if "%SFW_MODE%"=="0" exit /b 0
if "%SFW_MODE%"=="255" exit /b 0
echo.
powershell -NoProfile -ExecutionPolicy Bypass -Command "$p=$env:SFW_SELF; if (-not $p) { exit 1 }; $t=[IO.File]::ReadAllText($p); $k='##PS'+'BEGIN##'; $i=$t.IndexOf($k,[StringComparison]::Ordinal); if ($i -lt 0) { Write-Host 'ERROR: the PowerShell part of this file is missing.' -ForegroundColor Red; exit 1 }; iex $t.Substring($i + $k.Length)"
echo.
pause
goto :menu

##PSBEGIN##
# =====================================================================
#  PowerShell part - the batch part above runs everything below it.
#  Settings you may want to change:
# =====================================================================
$UseSteamLoginServers = $true   # keep Steam's login/matchmaking servers reachable (co-op needs them)
$ExpandToSlash24      = $true   # also allow the /24 around each of those servers (lists differ per region)

$ErrorActionPreference = 'Stop'
$Prefix   = 'SteamCoopFW'
$Mode     = [string]$env:SFW_MODE
$SelfPath = $env:SFW_SELF
$V6All    = '::2-ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'
$V6Warned = $false

$Dir = $env:SFW_DIR
if (-not $Dir -and $SelfPath) { $Dir = Split-Path -Parent $SelfPath }
if (-not $Dir) { $Dir = (Get-Location).Path }
$AllowFile = Join-Path $Dir 'steam_allow.txt'

$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$Allowed    = New-Object System.Collections.Generic.List[object]
$Seen       = New-Object 'System.Collections.Generic.HashSet[string]'
$Unresolved = New-Object System.Collections.Generic.List[string]
$Skipped    = New-Object System.Collections.Generic.List[string]

# ---------- IPv4 helpers ----------
function IpToNum([System.Net.IPAddress]$ip) {
    $b = $ip.GetAddressBytes()
    return ([int64]$b[0] * 16777216) + ([int64]$b[1] * 65536) + ([int64]$b[2] * 256) + [int64]$b[3]
}

function NumToIp([int64]$n) {
    return '{0}.{1}.{2}.{3}' -f (($n -shr 24) -band 255), (($n -shr 16) -band 255), (($n -shr 8) -band 255), ($n -band 255)
}

function FmtRange([int64]$a, [int64]$b) {
    if ($a -eq $b) { return (NumToIp $a) }
    return ((NumToIp $a) + '-' + (NumToIp $b))
}

# Windows Firewall cannot say "everything except these", so we block the gaps between the allowed ranges.
function Get-BlockRanges($pairs) {
    $sorted = New-Object System.Collections.Generic.List[object]
    foreach ($p in @($pairs)) {
        if ($null -ne $p) { $sorted.Add(@([int64]$p[0], [int64]$p[1])) }
    }
    $sorted = @($sorted | Sort-Object { $_[0] })

    $merged = New-Object System.Collections.Generic.List[object]
    $cs = $null
    $ce = $null
    foreach ($p in $sorted) {
        if ($null -eq $cs) { $cs = $p[0]; $ce = $p[1] }
        elseif ($p[0] -le ($ce + 1)) { if ($p[1] -gt $ce) { $ce = $p[1] } }
        else { $merged.Add(@($cs, $ce)); $cs = $p[0]; $ce = $p[1] }
    }
    if ($null -ne $cs) { $merged.Add(@($cs, $ce)) }

    $out    = New-Object System.Collections.Generic.List[string]
    $cursor = [int64]1
    $high   = [int64]4294967294
    foreach ($m in $merged) {
        if ($m[0] -gt $cursor) { $out.Add((FmtRange $cursor ($m[0] - 1))) }
        if (($m[1] + 1) -gt $cursor) { $cursor = $m[1] + 1 }
    }
    if ($cursor -le $high) { $out.Add((FmtRange $cursor $high)) }
    return ,$out.ToArray()
}

# ---------- allow list ----------
function Add-Range([int64]$a, [int64]$b) {
    if ($b -lt $a) { $t = $a; $a = $b; $b = $t }
    if ($a -lt 1) { $a = 1 }
    if ($b -gt 4294967294) { $b = 4294967294 }
    if ($b -lt $a) { return }
    if ($Seen.Add(('{0}-{1}' -f $a, $b))) { $Allowed.Add(@($a, $b)) }
}

function Add-Ip([System.Net.IPAddress]$addr, [bool]$expand) {
    $n = IpToNum $addr
    if ($expand) { $s = $n - ($n % 256); Add-Range $s ($s + 255) }
    else         { Add-Range $n $n }
}

function Add-Entry([string]$entry, [bool]$expand) {
    $e = ([string]$entry).Trim()
    if (-not $e) { return }
    if ($e -match '^\[.+\]:\d+$') { $Skipped.Add($e); return }        # [IPv6]:port
    if ($e -match '^([^:]+):\d+$') { $e = $Matches[1] }               # drop a :port suffix
    if ($e.Contains(':')) { $Skipped.Add($e); return }                # IPv6 literals are not supported here
    try {
        if ($e -match '^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$') {
            $base = [System.Net.IPAddress]::Parse($Matches[1])
            $bits = [int]$Matches[2]
            if ($bits -gt 32) { throw 'bad prefix length' }
            $size = [int64][math]::Pow(2, 32 - $bits)
            $s = IpToNum $base
            $s = $s - ($s % $size)
            Add-Range $s ($s + $size - 1)
        }
        elseif ($e -match '^(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3}(?:\.\d{1,3}){3})$') {
            $a1 = IpToNum ([System.Net.IPAddress]::Parse($Matches[1]))
            $a2 = IpToNum ([System.Net.IPAddress]::Parse($Matches[2]))
            Add-Range $a1 $a2
        }
        elseif ($e -match '^\d{1,3}(?:\.\d{1,3}){3}$') {
            Add-Ip ([System.Net.IPAddress]::Parse($e)) $expand
        }
        else {
            $found = $false
            foreach ($addr in [System.Net.Dns]::GetHostAddresses($e)) {
                if ($addr.AddressFamily -eq 'InterNetwork') { Add-Ip $addr $expand; $found = $true }
            }
            if (-not $found) { $Unresolved.Add($e + ' (no IPv4 address)') }
        }
    }
    catch { $Unresolved.Add($e) }
}

function New-AllowFile {
    $lines = @(
        '# Steam firewall allow list - one entry per line, # starts a comment.',
        '# Add the servers that must stay reachable (for example the kb_... ones).',
        '# Accepted: host names, single IPs, CIDR blocks (1.2.3.0/24) or ranges (1.2.3.4-1.2.3.99).',
        '# Windows Firewall cannot filter by name, so names are turned into IPs each time you choose Apply.',
        '# Wildcards (*.example.com) cannot be resolved - use real host names or IP ranges.',
        '# If co-op goes through Steam Networking (SDR) relays, add those ranges here too;',
        '# their list is at https://api.steampowered.com/ISteamApps/GetSDRConfig/v1/?appid=<app id>',
        '# Example:',
        '# ext1-sea1.steamserver.net',
        ''
    )
    Set-Content -LiteralPath $AllowFile -Value $lines -Encoding ASCII
}

# ---------- Steam location ----------
function Find-SteamDir {
    $cands = @()
    try { $cands += (Get-ItemProperty -Path 'HKCU:\Software\Valve\Steam' -ErrorAction Stop).SteamPath } catch { }
    try { $cands += (Get-ItemProperty -Path 'HKLM:\SOFTWARE\WOW6432Node\Valve\Steam' -ErrorAction Stop).InstallPath } catch { }
    try { $cands += (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Valve\Steam' -ErrorAction Stop).InstallPath } catch { }
    if (${env:ProgramFiles(x86)}) { $cands += (Join-Path ${env:ProgramFiles(x86)} 'Steam') }
    $cands += (Join-Path $env:ProgramFiles 'Steam')
    foreach ($c in $cands) {
        if ($c) {
            $p = ([string]$c) -replace '/', '\'
            if (Test-Path -LiteralPath (Join-Path $p 'steam.exe')) { return $p }
        }
    }
    $typed = Read-Host 'Steam folder not found. Type the full path to it (or press Enter to cancel)'
    if ($typed -and (Test-Path -LiteralPath (Join-Path $typed 'steam.exe'))) { return $typed }
    return $null
}

# ---------- Steam server list ----------
function Get-SteamEndpoints {
    $sources = @(
        @{ Name = 'GetCMListForConnect'; Url = 'https://api.steampowered.com/ISteamDirectory/GetCMListForConnect/v1/?cellid=0&maxcount=500&format=json' },
        @{ Name = 'GetCMList';           Url = 'https://api.steampowered.com/ISteamDirectory/GetCMList/v1/?cellid=0&maxcount=500&format=json' }
    )
    $names = New-Object 'System.Collections.Generic.HashSet[string]'
    try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch { }
    foreach ($src in $sources) {
        try {
            $resp = Invoke-RestMethod -Uri $src.Url -TimeoutSec 30
            foreach ($list in @($resp.response.serverlist, $resp.response.serverlist_websockets)) {
                foreach ($item in @($list)) {
                    if (-not $item) { continue }
                    if ($item -is [string]) { $ep = [string]$item }
                    else {
                        $ep = [string]$item.endpoint
                        if (-not $ep) { $ep = [string]$item.legacy_endpoint }
                    }
                    $ep = $ep -replace ':\d+$', ''
                    if ($ep) { [void]$names.Add($ep) }
                }
            }
        }
        catch { Write-Warning ('Could not read Steam''s ' + $src.Name + ' list: ' + $_.Exception.Message) }
    }
    return ,$names
}

# ---------- firewall rules ----------
function Get-SteamRules {
    $byGroup = @(Get-NetFirewallRule -Group $Prefix -ErrorAction SilentlyContinue)
    if ($byGroup.Count -gt 0) { return ,$byGroup }
    return ,@(Get-NetFirewallRule -DisplayName "$Prefix*" -ErrorAction SilentlyContinue)
}

function New-BlockRule([string]$name, [string]$exe, [string[]]$remote) {
    $common = @{
        DisplayName = $name
        Group       = $Prefix
        Description = 'Created by the Steam co-op firewall script - remove it with option [2].'
        Direction   = 'Outbound'
        Action      = 'Block'
        Program     = $exe
        Profile     = 'Any'
        Enabled     = 'True'
    }
    $v4 = @([string[]]$remote)
    try {
        New-NetFirewallRule @common -RemoteAddress ($v4 + $V6All) -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
        try {
            New-NetFirewallRule @common -RemoteAddress $v4 -ErrorAction Stop | Out-Null
            if (-not $V6Warned) {
                Write-Warning 'IPv6 could not be blocked on this system; IPv4 is still blocked.'
                $script:V6Warned = $true
            }
            return $true
        }
        catch {
            Write-Warning ('Could not create "' + $name + '": ' + $_.Exception.Message)
            return $false
        }
    }
}

function Disable-SteamBlock([switch]$Quiet) {
    $rules = Get-SteamRules
    $gone = 0
    foreach ($r in $rules) {
        try { Remove-NetFirewallRule -InputObject $r -ErrorAction Stop; $gone++ }
        catch { Write-Warning ('Could not remove "' + $r.DisplayName + '": ' + $_.Exception.Message) }
    }
    if ($Quiet) { return }
    if ($gone -gt 0) { Write-Host ('Removed {0} rule(s).' -f $gone) -ForegroundColor Green }
    else { Write-Host 'No rules from this script were found.' }
}

function Show-SteamBlock {
    $rules = Get-SteamRules
    if (@($rules).Count -eq 0) { Write-Host 'No Steam co-op firewall rules are active.'; return }
    $rows = foreach ($r in $rules) {
        $prog = ''
        $addr = @()
        try { $prog = (Get-NetFirewallApplicationFilter -AssociatedNetFirewallRule $r -ErrorAction Stop).Program } catch { }
        try { $addr = @((Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $r -ErrorAction Stop).RemoteAddress) } catch { }
        [pscustomobject]@{
            Enabled       = $r.Enabled
            Action        = $r.Action
            BlockedRanges = $addr.Count
            Program       = $prog
        }
    }
    $rows | Format-Table -AutoSize | Out-Host
    Write-Host ('{0} rule(s) active.' -f @($rules).Count)
}

function Enable-SteamBlock {
    $steam = Find-SteamDir
    if (-not $steam) { throw 'Could not find the Steam folder.' }
    Write-Host ('Steam folder: ' + $steam)

    # steamwebhelper = store/community/web UI: blocked completely.
    # Everything else in the Steam folder (steam.exe etc.): blocked except the allow list.
    $binDir = Join-Path $steam 'bin'
    $web = @(Get-ChildItem -LiteralPath $binDir -Filter 'steamwebhelper.exe' -File -Recurse -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
    $client = @()
    $client += @(Get-ChildItem -LiteralPath $steam -Filter '*.exe' -File -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
    $client += @(Get-ChildItem -LiteralPath $binDir -Filter '*.exe' -File -Recurse -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'steamwebhelper.exe' } | ForEach-Object { $_.FullName })
    if (${env:ProgramFiles(x86)}) {
        $svc = Join-Path ${env:ProgramFiles(x86)} 'Common Files\Steam\SteamService.exe'
        if (Test-Path -LiteralPath $svc) { $client += $svc }
    }
    $client = @($client | Select-Object -Unique)
    if (($web.Count + $client.Count) -eq 0) { throw 'No Steam programs were found.' }

    # 1) Steam's own login/matchmaking servers (needed for co-op)
    if ($UseSteamLoginServers) {
        Write-Host 'Getting the current Steam server list...'
        $names = Get-SteamEndpoints
        Write-Host ('  {0} name(s)/IP(s) found - resolving them (this can take a minute)...' -f $names.Count)
        foreach ($n in $names) { Add-Entry $n $ExpandToSlash24 }
    }

    # 2) your own entries
    if (-not (Test-Path -LiteralPath $AllowFile)) { New-AllowFile }
    $userCount = 0
    foreach ($line in (Get-Content -LiteralPath $AllowFile)) {
        $t = ($line -replace '#.*$', '').Trim()
        if ($t) { Add-Entry $t $false; $userCount++ }
    }
    Write-Host ('{0} entr(ies) read from {1}' -f $userCount, $AllowFile)

    if ($Skipped.Count -gt 0)    { Write-Warning ('Ignored (IPv6 is not supported here): ' + (($Skipped | Select-Object -First 10) -join ', ')) }
    if ($Unresolved.Count -gt 0) { Write-Warning ('{0} entr(ies) could not be used, e.g.: {1}' -f $Unresolved.Count, (($Unresolved | Select-Object -First 5) -join ', ')) }

    if ($Allowed.Count -eq 0) {
        Write-Warning 'The allow list is empty, so ALL Steam traffic would be blocked and co-op will not work.'
        $ans = Read-Host 'Continue anyway? (y/N)'
        if ($ans -notmatch '^[yY]') { Write-Host 'Cancelled - nothing was changed.'; return }
    }

    # 3) build the "everything else" ranges (loopback is never blocked)
    $loop     = @(,@([int64]2130706432, [int64]2147483647))      # 127.0.0.0 - 127.255.255.255
    $webBlock = Get-BlockRanges $loop
    $pairs    = New-Object System.Collections.Generic.List[object]
    $pairs.Add($loop[0])
    foreach ($a in $Allowed) { $pairs.Add($a) }
    $clientBlock = Get-BlockRanges $pairs
    Write-Host ('Blocking {0} address range(s) for the Steam programs.' -f @($clientBlock).Count)

    # 4) replace any old rules, then create the new ones
    Disable-SteamBlock -Quiet
    $made = 0
    $failed = 0
    $i = 0
    foreach ($exe in $web) {
        $i++
        $nm = '{0} {1} (no internet) #{2}' -f $Prefix, (Split-Path $exe -Leaf), $i
        if (New-BlockRule $nm $exe $webBlock) { $made++ } else { $failed++ }
    }
    foreach ($exe in $client) {
        $i++
        $nm = '{0} {1} (allow list only) #{2}' -f $Prefix, (Split-Path $exe -Leaf), $i
        if (New-BlockRule $nm $exe $clientBlock) { $made++ } else { $failed++ }
    }

    Write-Host ''
    if ($failed -gt 0) {
        Write-Warning ('{0} rule(s) could not be created. Run [2] Remove, then set $ExpandToSlash24 = $false at the top of the script and try again.' -f $failed)
    }
    Write-Host ('Done: {0} rule(s) created. Steam can now only reach its allow list.' -f $made) -ForegroundColor Green
    Write-Host 'Restart Steam so its connections start under the new rules.'
    Write-Host 'Game downloads/updates, store, community and cloud sync are blocked now.'
    Write-Host 'If Steam will not start, log in or find friends, choose [2] Remove, then try again.'
}

# ---------- run ----------
try {
    if ($Mode -eq '1') {
        if (-not $IsAdmin) { throw 'Administrator rights are needed to apply the rules.' }
        Enable-SteamBlock
    }
    elseif ($Mode -eq '2') {
        if (-not $IsAdmin) { throw 'Administrator rights are needed to remove the rules.' }
        Disable-SteamBlock
    }
    elseif ($Mode -eq '3') {
        Show-SteamBlock
    }
    else {
        Write-Host ('Unknown choice "' + $Mode + '" - nothing was changed.')
    }
}
catch {
    Write-Host ''
    Write-Host ('ERROR: ' + $_.Exception.Message) -ForegroundColor Red
}
