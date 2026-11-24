@echo off
setlocal EnableExtensions DisableDelayedExpansion
title Steam Lockdown for Elden Ring Seamless Coop

rem =====================================================================
rem  STEAM LOCKDOWN FOR ELDEN RING SEAMLESS COOP
rem
rem  Seamless Coop has no servers of its own. It runs on Steam's network:
rem  you must be logged in to Steam, sessions are found through Steam,
rem  and the game traffic goes peer to peer or through Valve relays.
rem  Valve does not publish a fixed list of server IPs, so this script
rem  limits steam.exe to the PORTS Steam needs for exactly that and cuts
rem  the rest of the Steam client off the internet.
rem
rem  Windows Firewall outbound rules, all named "SteamLock ...":
rem
rem    steam.exe  TCP  only 27015-27050 stays open (login, lobbies)
rem               UDP  only 27000-27100, 3478, 4379-4380 and 53
rem                    (Steam network, relays, P2P setup, DNS)
rem               HTTP and HTTPS (80 and 443) are blocked. That stops the
rem               store, downloads and updates. Level 2 re-opens 443,
rem               level 3 re-opens 80 as well, in case coop will not
rem               connect with the stricter level.
rem
rem    helpers    steamwebhelper, overlay, Steam service, error reporter
rem               and Remote Play are blocked completely.
rem
rem    eldenring.exe and ersc_launcher.exe are NOT touched.
rem
rem  Undo everything with menu option 4, or delete the rules named
rem  "SteamLock ..." under Windows Defender Firewall, Outbound Rules.
rem =====================================================================

rem ---------------------------------------------------------------------
rem  SETTINGS - only change STEAM_DIR if auto-detection fails.
rem  Example:  set "STEAM_DIR=D:\Games\Steam"
rem ---------------------------------------------------------------------
set "STEAM_DIR="
set "TAG=SteamLock"

rem ---------------------------------------------------------------------
rem  Administrator rights (re-launches itself elevated when needed)
rem ---------------------------------------------------------------------
fltmc >nul 2>&1
if not errorlevel 1 goto :haveadmin
echo Requesting administrator rights...
powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs" >nul 2>&1
if errorlevel 1 echo Could not start an elevated window. Right-click this file and choose Run as administrator.
if errorlevel 1 pause
exit /b

:haveadmin

rem ---------------------------------------------------------------------
rem  Find Steam
rem ---------------------------------------------------------------------
if not defined STEAM_DIR for /f "tokens=2,*" %%A in ('reg query "HKCU\Software\Valve\Steam" /v SteamPath 2^>nul') do set "STEAM_DIR=%%B"
if not defined STEAM_DIR for /f "tokens=2,*" %%A in ('reg query "HKLM\SOFTWARE\WOW6432Node\Valve\Steam" /v InstallPath 2^>nul') do set "STEAM_DIR=%%B"
if not defined STEAM_DIR if exist "%ProgramFiles(x86)%\Steam\steam.exe" set "STEAM_DIR=%ProgramFiles(x86)%\Steam"
if not defined STEAM_DIR goto :nosteam
set "STEAM_DIR=%STEAM_DIR:/=\%"
if "%STEAM_DIR:~-1%"=="\" set "STEAM_DIR=%STEAM_DIR:~0,-1%"
if not exist "%STEAM_DIR%\steam.exe" goto :nosteam
goto :menu

:nosteam
echo.
echo Could not find steam.exe.
echo Open this script in Notepad and put your Steam folder into the line
echo set "STEAM_DIR=" near the top, for example  set "STEAM_DIR=D:\Games\Steam"
echo.
pause
exit /b 1

rem ---------------------------------------------------------------------
rem  Menu
rem ---------------------------------------------------------------------
:menu
cls
echo ==============================================================
echo   Steam lockdown for Elden Ring Seamless Coop
echo ==============================================================
echo   Steam folder: %STEAM_DIR%
echo.
echo   Tip: log in to Steam first and tick Remember my password,
echo   then apply a level, then fully restart Steam.
echo.
echo   [1] Level 1  steam.exe may only use Steam ports   strictest
echo   [2] Level 2  Level 1 plus HTTPS 443
echo   [3] Level 3  Level 2 plus HTTP 80
echo   [4] Remove all lockdown rules
echo   [5] Show active rules
echo   [6] Exit
echo.
echo   Start with 1. If Seamless Coop cannot connect, or Steam hangs
echo   at startup, try 2 and then 3.
echo.
choice /c 123456 /n /m "Your choice: "
if errorlevel 6 exit /b 0
if errorlevel 5 goto :show
if errorlevel 4 goto :remove
set "LEVEL=%errorlevel%"
goto :apply

rem ---------------------------------------------------------------------
rem  Apply
rem ---------------------------------------------------------------------
:apply
cls
echo Applying level %LEVEL%...
echo.

rem  Start clean so rules never pile up
call :unblock_quiet

rem  The rules do nothing if Windows Firewall is switched off
powershell -NoProfile -Command "if (Get-NetFirewallProfile | Where-Object { $_.Enabled -eq 'False' }) { exit 1 }" >nul 2>&1
if errorlevel 1 echo WARNING: Windows Firewall looks switched off for at least one network profile.
if errorlevel 1 echo          The rules cannot work there. Switch it on first.
if errorlevel 1 echo.

rem  steam.exe TCP: block everything except 27015-27050 (+443 at level 2, +80 at level 3)
set "TCP_BLOCK=1-27014,27051-65535"
if %LEVEL% GEQ 2 set "TCP_BLOCK=1-442,444-27014,27051-65535"
if %LEVEL% GEQ 3 set "TCP_BLOCK=1-79,81-442,444-27014,27051-65535"

rem  steam.exe UDP: block everything except 53, 3478, 4379-4380 and 27000-27100
set "UDP_BLOCK=1-52,54-3477,3479-4378,4381-26999,27101-65535"

echo steam.exe (limited to Steam ports):
call :limit "%STEAM_DIR%\steam.exe"
for /f "delims=" %%F in ('dir /s /b "%STEAM_DIR%\bin\steam.exe" 2^>nul') do call :limit "%%F"

echo.
echo Helper programs (blocked completely):
for %%N in (steamwebhelper.exe steamservice.exe gameoverlayui.exe steamerrorreporter.exe steamerrorreporter64.exe streaming_client.exe) do call :findblock %%N

echo.
echo Level %LEVEL% is active.
echo.
echo   1. Fully exit Steam (tray icon, Exit) and start it again.
echo   2. Start Seamless Coop with ersc_launcher.exe as usual.
echo   3. If it cannot connect, run this script again and pick the next level.
echo.
pause
goto :menu

rem ---------------------------------------------------------------------
rem  Remove
rem ---------------------------------------------------------------------
:remove
cls
call :unblock_quiet
echo All SteamLock rules have been removed.
echo Steam can use the internet normally again. Restart Steam to be safe.
echo.
pause
goto :menu

rem ---------------------------------------------------------------------
rem  Show
rem ---------------------------------------------------------------------
:show
cls
echo Reading firewall rules, please wait...
echo.
netsh advfirewall firewall show rule name=all dir=out | findstr /c:"%TAG%"
if errorlevel 1 echo   No SteamLock rules are active.
echo.
echo Ports of the steam.exe TCP rule:
netsh advfirewall firewall show rule name="%TAG% steam.exe TCP" 2>nul | findstr /i "port"
echo.
pause
goto :menu

rem ---------------------------------------------------------------------
rem  Subroutines
rem ---------------------------------------------------------------------

rem  arg 1 = full path to a steam.exe that keeps limited network access
:limit
call :addrule "%TAG% steam.exe TCP" tcp "%TCP_BLOCK%" %1
call :addrule "%TAG% steam.exe UDP" udp "%UDP_BLOCK%" %1
exit /b 0

rem  arg 1 = rule name, arg 2 = tcp or udp, arg 3 = ports to BLOCK, arg 4 = program
:addrule
netsh advfirewall firewall add rule name=%1 dir=out action=block program=%4 protocol=%2 remoteport=%~3 profile=any enable=yes description="Added by steam_lockdown_seamless_coop.bat" >nul
if errorlevel 1 echo   FAILED  %2  %~4
if not errorlevel 1 echo   OK      %2  %~4
exit /b 0

rem  arg 1 = file name of a Steam helper, searched in the Steam folder and its bin folder
:findblock
if exist "%STEAM_DIR%\%1" call :blockall "%STEAM_DIR%\%1"
for /f "delims=" %%F in ('dir /s /b "%STEAM_DIR%\bin\%1" 2^>nul') do call :blockall "%%F"
exit /b 0

rem  arg 1 = full path of a program that gets no outbound access at all
:blockall
netsh advfirewall firewall add rule name="%TAG% helper" dir=out action=block program=%1 profile=any enable=yes description="Added by steam_lockdown_seamless_coop.bat" >nul
if errorlevel 1 echo   FAILED  %~1
if not errorlevel 1 echo   OK      %~1
exit /b 0

:unblock_quiet
netsh advfirewall firewall delete rule name="%TAG% steam.exe TCP" >nul 2>&1
netsh advfirewall firewall delete rule name="%TAG% steam.exe UDP" >nul 2>&1
netsh advfirewall firewall delete rule name="%TAG% helper" >nul 2>&1
exit /b 0
