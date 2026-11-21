@echo off
setlocal EnableExtensions DisableDelayedExpansion
title Steam co-op firewall

set "SFW_SELF=%~f0"
set "SFW_DIR=%~dp0"
set "SFW_SELF=%SFW_SELF:"=%"

rem Do not continue unless Windows has administrator privileges.
fltmc.exe >nul 2>&1
if not errorlevel 1 goto :menu

echo Requesting administrator privileges...
for /f "usebackq delims=" %%I in (
    `powershell.exe -NoProfile -ExecutionPolicy Bypass -Command ^
        "$p=$env:SFW_SELF; ^
         if ($p) { try { Start-Process -FilePath $p -Verb RunAs -ErrorAction Stop | Out-Null; exit 0 } catch { exit 1 } }"`
) do rem

echo.
echo Administrator privileges were not granted, or the elevated window could not start.
pause
exit /b 1

:menu
cls
echo ============================================
echo   Steam co-op firewall
echo ============================================
echo.
echo   [1] Apply
echo   [2] Remove all rules made by this script
echo   [3] Status
echo   [4] Preview
echo   [5] Quit
echo.
choice /c 12345 /n /m "Choose 1-5: "
set "SFW_MODE=%errorlevel%"
if "%SFW_MODE%"=="5" exit /b 0
if "%SFW_MODE%"=="0" exit /b 0
if "%SFW_MODE%"=="255" exit /b 0
echo.

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command ^
    "$p=$env:SFW_SELF; ^
     if (-not $p) { exit 1 }; ^
     $t=[IO.File]::ReadAllText($p); ^
     $k='##PSBEGIN##'; ^
     $i=$t.IndexOf($k,[StringComparison]::Ordinal); ^
     if ($i -lt 0) { exit 1 }; ^
     $i=$t.IndexOf("`n",$i); ^
     if ($i -lt 0) { exit 1 }; ^
     $s=$t.Substring($i+1); ^
     Invoke-Expression $s"

if errorlevel 1 (
    echo.
    echo PowerShell reported an error.
)

echo.
pause
goto :menu

##PSBEGIN##
# =============================
# Steam co-op firewall settings
# =============================
$UseSteamLoginServers = $true
$ExpandCMServersToSlash24 = $true
$BlockIPv6 = $false
$Prefix = 'SteamCoopFW'
$Mode = [string]$env:SFW_MODE
$SelfPath = $env:SFW_SELF
$Dir = $env:SFW_DIR

$ErrorActionPreference = 'Stop'

if (-not $Dir -and $SelfPath) {
    $Dir = Split-Path -Parent $SelfPath
}
if (-not $Dir) {
    $Dir = (Get-Location).Path
}

$AllowFile = Join-Path $Dir 'steam_allow.txt'
$Allowed = New-Object System.Collections.Generic.List[object]
$Seen = New-Object 'System.Collections.Generic.HashSet[string]'
$Unresolved = New-Object System.Collections.Generic.List[string]
$Skipped = New-Object System.Collections.Generic.List[string]

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = [Security.Principal.WindowsPrincipal]::new($identity)
    return $principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
}

function IpToNum([System.Net.IPAddress]$Ip) {
    if ($Ip.AddressFamily -ne 'InterNetwork') {
        throw 'Only IPv4 addresses are supported.'
    }

    $bytes = $Ip.GetAddressBytes()
    return ([int64]$bytes[0] -shl 24) `
         -bor ([int64]$bytes[1] -shl 16) `
         -bor ([int64]$bytes[2] -shl 8) `
         -bor [int64]$bytes[3]
}

function NumToIp([int64]$Num) {
    return '{0}.{1}.{2}.{3}' -f `
        (($Num -shr 24) -band 255),
        (($Num -shr 16) -band 255),
        (($Num -shr 8) -band 255),
        ($Num -band 255)
}

function Format-Range([int64]$Start, [int64]$End) {
    if ($Start -eq $End) {
        return NumToIp $Start
    }
    return ((NumToIp $Start) + '-' + (NumToIp $End))
}

function Add-Range([int64]$Start, [int64]$End) {
    if ($End -lt $Start) {
        $temp = $Start
        $Start = $End
        $End = $temp
    }

    if ($Start -lt 1) { $Start = 1 }
    if ($End -gt 4294967294) { $End = 4294967294 }
    if ($End -lt $Start) { return }

    $key = '{0}-{1}' -f $Start, $End
    if ($Seen.Add($key)) {
        $Allowed.Add(@($Start, $End))
    }
}

function Add-IP([System.Net.IPAddress]$Address, [bool]$Expand) {
    $number = IpToNum $Address
    if ($Expand) {
        $subnetStart = $number - ($number % 256)
        Add-Range $subnetStart ($subnetStart + 255)
    }
    else {
        Add-Range $number $number
    }
}

function Merge-Ranges($Pairs) {
    $sorted = New-Object System.Collections.Generic.List[object]

    foreach ($pair in @($Pairs)) {
        if ($null -ne $pair) {
            $sorted.Add([object]@(
                [int64]$pair[0],
                [int64]$pair[1]
            ))
        }
    }

    if ($sorted.Count -eq 0) {
        return @()
    }

    $sorted = @($sorted | Sort-Object { $_[0] })

    $merged = New-Object System.Collections.Generic.List[object]
    $currentStart = [int64]$sorted[0][0]
    $currentEnd = [int64]$sorted[0][1]

    for ($i = 1; $i -lt $sorted.Count; $i++) {
        $start = [int64]$sorted[$i][0]
        $end = [int64]$sorted[$i][1]

        if ($start -le ($currentEnd + 1)) {
            if ($end -gt $currentEnd) {
                $currentEnd = $end
            }
        }
        else {
            $merged.Add([object]@($currentStart, $currentEnd))
            $currentStart = $start
            $currentEnd = $end
        }
    }

    $merged.Add([object]@($currentStart, $currentEnd))

    return ,@($merged)
}

function Get-BlockRanges($Pairs) {
    $merged = @(Merge-Ranges $Pairs)
    $out = New-Object System.Collections.Generic.List[string]
    $cursor = [int64]1
    $high = [int64]4294967294

    foreach ($range in $merged) {
        $start = [int64]$range[0]
        $end = [int64]$range[1]

        if ($start -gt $cursor) {
            $out.Add((Format-Range $cursor ($start - 1)))
        }

        $next = $end + 1
        if ($next -gt $cursor) {
            $cursor = $next
        }
    }

    if ($cursor -le $high) {
        $out.Add((Format-Range $cursor $high))
    }

    return ,@($out.ToArray())
}

function Add-Entry([string]$Entry, [bool]$Expand) {
    $entry = ([string]$Entry).Trim()

    if (-not $entry) { return }
    if ($entry -match '^#') { return }

    if ($entry -match '^(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})$') {
        $addressText = $Matches[1]
        $prefixLength = [int]$Matches[2]

        if ($prefixLength -lt 0 -or $prefixLength -gt 32) {
            $Unresolved.Add($entry)
            return
        }

        try {
            $address = [System.Net.IPAddress]::Parse($addressText)
            $base = IpToNum $address
            $hostBits = 32 - $prefixLength
            $blockSize = [int64][math]::Pow(2, $hostBits)
            $blockStart = $base - ($base % $blockSize)
            Add-Range $blockStart ($blockStart + $blockSize - 1)
        }
        catch {
            $Unresolved.Add($entry)
        }

        return
    }

    if ($entry -match '^(\d{1,3}(?:\.\d{1,3}){3})-(\d{1,3}(?:\.\d{1,3}){3})$') {
        try {
            $start = IpToNum ([System.Net.IPAddress]::Parse($Matches[1]))
            $end = IpToNum ([System.Net.IPAddress]::Parse($Matches[2]))
            Add-Range $start $end
        }
        catch {
            $Unresolved.Add($entry)
        }

        return
    }

    if ($entry -match '^\d{1,3}(?:\.\d{1,3}){3}$') {
        try {
            $address = [System.Net.IPAddress]::Parse($entry)
            Add-IP $address $Expand
        }
        catch {
            $Unresolved.Add($entry)
        }

        return
    }

    if ($entry.Contains(':')) {
        $Skipped.Add($entry)
        return
    }

    try {
        $found = $false
        foreach ($address in [System.Net.Dns]::GetHostAddresses($entry)) {
            if ($address.AddressFamily -eq 'InterNetwork') {
                Add-IP $address $Expand
                $found = $true
            }
        }

        if (-not $found) {
            $Unresolved.Add("$entry (no IPv4 address)")
        }
    }
    catch {
        $Unresolved.Add("$entry (DNS resolution failed)")
    }
}

function New-AllowFile {
    $lines = @(
        '# Steam co-op firewall allow list'
        '# One entry per line.'
        '# Comments begin with #.'
        '# Accepted entries:'
        '#   host.example.com'
        '#   192.0.2.10'
        '#   192.0.2.0/24'
        '#   192.0.2.10-192.0.2.99'
        '#'
        '# If Steam Networking/SDR relays are required, add them as'
        '# IPv4 addresses or CIDR ranges. IPv6 is not supported.'
        ''
    )

    Set-Content -LiteralPath $AllowFile -Value $lines -Encoding ASCII
}

function Find-SteamDir {
    $candidates = New-Object System.Collections.Generic.List[string]

    try {
        $path = (Get-ItemProperty `
            -Path 'HKCU:\Software\Valve\Steam' `
            -Name 'SteamPath' `
            -ErrorAction Stop).SteamPath
        if ($path) { $candidates.Add([string]$path) }
    } catch {}

    try {
        $path = (Get-ItemProperty `
            -Path 'HKLM:\SOFTWARE\WOW6432Node\Valve\Steam' `
            -Name 'InstallPath' `
            -ErrorAction Stop).InstallPath
        if ($path) { $candidates.Add([string]$path) }
    } catch {}

    try {
        $path = (Get-ItemProperty `
            -Path 'HKLM:\SOFTWARE\Valve\Steam' `
            -Name 'InstallPath' `
            -ErrorAction Stop).InstallPath
        if ($path) { $candidates.Add([string]$path) }
    } catch {}

    if (${env:ProgramFiles(x86)}) {
        $candidates.Add((Join-Path ${env:ProgramFiles(x86)} 'Steam'))
    }

    if ($env:ProgramFiles) {
        $candidates.Add((Join-Path $env:ProgramFiles 'Steam'))
    }

    foreach ($candidate in $candidates | Select-Object -Unique) {
        if ([string]::IsNullOrWhiteSpace($candidate)) { continue }

        $candidate = ([string]$candidate) -replace '/', '\'
        $steamExe = Join-Path $candidate 'steam.exe'

        if (Test-Path -LiteralPath $steamExe) {
            return $candidate
        }
    }

    $typed = Read-Host 'Steam folder not found. Enter its full path, or press Enter to cancel'

    if ($typed) {
        $typed = ([string]$typed).Trim('"').Trim()
        if (Test-Path -LiteralPath (Join-Path $typed 'steam.exe')) {
            return $typed
        }
    }

    return $null
}

function Get-SteamEndpoints {
    $sources = @(
        'https://api.steampowered.com/ISteamDirectory/GetCMListForConnect/v1/?cellid=0&maxcount=500&format=json',
        'https://api.steampowered.com/ISteamDirectory/GetCMList/v1/?cellid=0&maxcount=500&format=json'
    )

    $endpoints = New-Object 'System.Collections.Generic.HashSet[string]'

    try {
        [Net.ServicePointManager]::SecurityProtocol =
            [Net.SecurityProtocolType]::Tls12
    } catch {}

    foreach ($url in $sources) {
        try {
            $response = Invoke-RestMethod -Uri $url -TimeoutSec 30

            $lists = @(
                $response.response.serverlist
                $response.response.serverlist_websockets
            )

            foreach ($list in $lists) {
                foreach ($item in @($list)) {
                    if (-not $item) { continue }

                    if ($item -is [string]) {
                        $endpoint = [string]$item
                    }
                    else {
                        $endpoint = [string]$item.endpoint
                        if (-not $endpoint) {
                            $endpoint = [string]$item.legacy_endpoint
                        }
                    }

                    $endpoint = $endpoint -replace ':\d+$', ''
                    if ($endpoint) {
                        [void]$endpoints.Add($endpoint)
                    }
                }
            }
        }
        catch {
            Write-Warning "Could not retrieve a Steam CM list: $($_.Exception.Message)"
        }
    }

    return ,$endpoints
}

function Get-ScriptRules {
    $rules = New-Object System.Collections.Generic.List[object]

    foreach ($rule in @(Get-NetFirewallRule -ErrorAction SilentlyContinue)) {
        if ($rule.Group -eq $Prefix) {
            $rules.Add($rule)
            continue
        }

        if ($rule.DisplayName -like "$Prefix*") {
            $rules.Add($rule)
        }
    }

    return ,@($rules | Sort-Object DisplayName -Unique)
}

function Remove-ScriptRules([switch]$Quiet) {
    $removed = 0
    $failed = 0

    foreach ($rule in @(Get-ScriptRules)) {
        try {
            Remove-NetFirewallRule -InputObject $rule -ErrorAction Stop
            $removed++
        }
        catch {
            $failed++
            if (-not $Quiet) {
                Write-Warning "Could not remove '$($rule.DisplayName)': $($_.Exception.Message)"
            }
        }
    }

    if (-not $Quiet) {
        if ($removed -gt 0) {
            Write-Host "Removed $removed rule(s)." -ForegroundColor Green
        }
        elseif ($failed -eq 0) {
            Write-Host 'No rules made by this script were found.'
        }

        if ($failed -gt 0) {
            Write-Warning "$failed rule(s) could not be removed."
        }
    }

    return [int]$removed
}

function New-BlockRule(
    [string]$Name,
    [string]$Executable,
    [string[]]$RemoteIPv4
) {
    $parameters = @{
        DisplayName = $Name
        Group = $Prefix
        Description = 'Created by Steamwall.bat. Remove it using Steamwall.bat option [2].'
        Direction = 'Outbound'
        Action = 'Block'
        Protocol = 'Any'
        Program = $Executable
        Profile = 'Any'
        Enabled = 'True'
    }

    try {
        New-NetFirewallRule @parameters `
            -RemoteAddress $RemoteIPv4 `
            -ErrorAction Stop | Out-Null
        return $true
    }
    catch {
        Write-Warning "Could not create '$Name': $($_.Exception.Message)"
        return $false
    }
}

function Get-SteamExecutables([string]$SteamDir) {
    $paths = New-Object System.Collections.Generic.List[string]

    foreach ($root in @(
        $SteamDir
        (Join-Path $SteamDir 'bin')
        (Join-Path $SteamDir 'bin64')
        (Join-Path $SteamDir 'bin1')
        (Join-Path $SteamDir 'package')
    )) {
        if (-not (Test-Path -LiteralPath $root)) { continue }

        Get-ChildItem `
            -LiteralPath $root `
            -Filter '*.exe' `
            -File `
            -Recurse `
            -ErrorAction SilentlyContinue |
            Where-Object {
                $_.Name -in @(
                    'steam.exe',
                    'steamwebhelper.exe',
                    'steamservice.exe',
                    'crashhandler.exe',
                    'steamerrorreporter.exe',
                    'writingtool.exe',
                    'streaming_client.exe',
                    'cefprocess.exe'
                ) -or
                $_.FullName -like "$SteamDir\bin*"
            } |
            ForEach-Object {
                if (-not $paths.Contains($_.FullName)) {
                    $paths.Add($_.FullName)
                }
            }
    }

    if (${env:ProgramFiles(x86)}) {
        $service = Join-Path `
            ${env:ProgramFiles(x86)} `
            'Common Files\Steam\SteamService.exe'

        if (Test-Path -LiteralPath $service) {
            if (-not $paths.Contains($service)) {
                $paths.Add($service)
            }
        }
    }

    return ,@($paths | Sort-Object -Unique)
}

function Show-ScriptRules {
    $rules = @(Get-ScriptRules)

    if ($rules.Count -eq 0) {
        Write-Host 'No Steam co-op firewall rules are active.'
        return
    }

    $rows = foreach ($rule in $rules) {
        $program = ''
        $addresses = @()

        try {
            $filter = Get-NetFirewallApplicationFilter `
                -AssociatedNetFirewallRule $rule `
                -ErrorAction Stop
            $program = $filter.Program
        } catch {}

        try {
            $filter = Get-NetFirewallAddressFilter `
                -AssociatedNetFirewallRule $rule `
                -ErrorAction Stop
            $addresses = @($filter.RemoteAddress)
        } catch {}

        [pscustomobject]@{
            Enabled = $rule.Enabled
            Action = $rule.Action
            Direction = $rule.Direction
            Program = $program
            RemoteAddressCount = $addresses.Count
            DisplayName = $rule.DisplayName
        }
    }

    $rows | Format-Table -AutoSize | Out-Host
    Write-Host "$($rules.Count) script rule(s) active."
}

function Enable-SteamBlock {
    $steamDir = Find-Ste
