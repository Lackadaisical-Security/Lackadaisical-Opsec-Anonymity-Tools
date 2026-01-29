<#
.SYNOPSIS
    Remove-Traces - Removes various system traces and logs
    Part of Lackadaisical Anonymity Toolkit

.DESCRIPTION
    Comprehensive trace removal for Windows systems including event logs,
    temporary files, browser data, and registry entries.

.PARAMETER All
    Remove all traces (requires admin rights)

.PARAMETER EventLogs
    Clear Windows event logs

.PARAMETER TempFiles
    Remove temporary files

.PARAMETER BrowserData
    Clear browser data for all browsers

.PARAMETER Registry
    Clean registry entries

.EXAMPLE
    .\Remove-Traces.ps1 -All
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$All,
    [switch]$EventLogs,
    [switch]$TempFiles,
    [switch]$BrowserData,
    [switch]$Registry,
    [switch]$DNSCache,
    [switch]$Prefetch,
    [switch]$RecentDocs
)

# Check for admin rights
function Test-Admin {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Clear Windows Event Logs
function Clear-EventLogs {
    if (-not (Test-Admin)) {
        Write-Warning "Admin rights required to clear event logs"
        return
    }
    
    Write-Host "Clearing Windows Event Logs..." -ForegroundColor Yellow
    
    $logs = Get-EventLog -List | Select-Object -ExpandProperty Log
    foreach ($log in $logs) {
        try {
            Clear-EventLog -LogName $log -ErrorAction Stop
            Write-Host "  Cleared: $log" -ForegroundColor Green
        }
        catch {
            Write-Warning "  Failed to clear: $log"
        }
    }
    
    # Clear modern event logs
    wevtutil el | ForEach-Object {
        try {
            wevtutil cl "$_" 2>$null
        }
        catch {}
    }
}

# Remove Temporary Files
function Remove-TempFiles {
    Write-Host "Removing temporary files..." -ForegroundColor Yellow
    
    $tempPaths = @(
        $env:TEMP,
        "$env:WINDIR\Temp",
        "$env:LOCALAPPDATA\Temp",
        "$env:USERPROFILE\AppData\Local\Temp"
    )
    
    foreach ($path in $tempPaths) {
        if (Test-Path $path) {
            try {
                Get-ChildItem -Path $path -Recurse -Force -ErrorAction SilentlyContinue | 
                    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
                Write-Host "  Cleaned: $path" -ForegroundColor Green
            }
            catch {
                Write-Warning "  Partial clean: $path"
            }
        }
    }
}

# Clear Browser Data
function Clear-BrowserData {
    Write-Host "Clearing browser data..." -ForegroundColor Yellow
    
    # Chrome
    $chromePaths = @(
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache",
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cookies",
        "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History"
    )
    
    foreach ($path in $chromePaths) {
        if (Test-Path $path) {
            try {
                Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
                Write-Host "  Cleared Chrome: $(Split-Path $path -Leaf)" -ForegroundColor Green
            }
            catch {
                Write-Warning "  Failed to clear Chrome: $(Split-Path $path -Leaf)"
            }
        }
    }
    
    # Firefox
    $firefoxProfile = "$env:APPDATA\Mozilla\Firefox\Profiles"
    if (Test-Path $firefoxProfile) {
        Get-ChildItem -Path $firefoxProfile -Directory | ForEach-Object {
            $profile = $_.FullName
            @("cache2", "cookies.sqlite", "places.sqlite") | ForEach-Object {
                $item = Join-Path $profile $_
                if (Test-Path $item) {
                    try {
                        Remove-Item -Path $item -Recurse -Force -ErrorAction Stop
                        Write-Host "  Cleared Firefox: $_" -ForegroundColor Green
                    }
                    catch {
                        Write-Warning "  Failed to clear Firefox: $_"
                    }
                }
            }
        }
    }
    
    # Edge
    $edgePaths = @(
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cache",
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Cookies",
        "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History"
    )
    
    foreach ($path in $edgePaths) {
        if (Test-Path $path) {
            try {
                Remove-Item -Path $path -Recurse -Force -ErrorAction Stop
                Write-Host "  Cleared Edge: $(Split-Path $path -Leaf)" -ForegroundColor Green
            }
            catch {
                Write-Warning "  Failed to clear Edge: $(Split-Path $path -Leaf)"
            }
        }
    }
}

# Clear DNS Cache
function Clear-DNSCache {
    Write-Host "Clearing DNS cache..." -ForegroundColor Yellow
    
    try {
        Clear-DnsClientCache
        ipconfig /flushdns | Out-Null
        Write-Host "  DNS cache cleared" -ForegroundColor Green
    }
    catch {
        Write-Warning "  Failed to clear DNS cache"
    }
}

# Clear Prefetch
function Clear-Prefetch {
    if (-not (Test-Admin)) {
        Write-Warning "Admin rights required to clear prefetch"
        return
    }
    
    Write-Host "Clearing prefetch..." -ForegroundColor Yellow
    
    $prefetchPath = "$env:WINDIR\Prefetch"
    if (Test-Path $prefetchPath) {
        try {
            Get-ChildItem -Path $prefetchPath -Filter "*.pf" | Remove-Item -Force
            Write-Host "  Prefetch cleared" -ForegroundColor Green
        }
        catch {
            Write-Warning "  Failed to clear prefetch"
        }
    }
}

# Clear Recent Documents
function Clear-RecentDocs {
    Write-Host "Clearing recent documents..." -ForegroundColor Yellow
    
    $recentPaths = @(
        "$env:APPDATA\Microsoft\Windows\Recent",
        "$env:APPDATA\Microsoft\Office\Recent"
    )
    
    foreach ($path in $recentPaths) {
        if (Test-Path $path) {
            try {
                Get-ChildItem -Path $path | Remove-Item -Force
                Write-Host "  Cleared: $path" -ForegroundColor Green
            }
            catch {
                Write-Warning "  Failed to clear: $path"
            }
        }
    }
    
    # Clear jump lists
    $jumpListPath = "$env:APPDATA\Microsoft\Windows\Recent\AutomaticDestinations"
    if (Test-Path $jumpListPath) {
        try {
            Get-ChildItem -Path $jumpListPath | Remove-Item -Force
            Write-Host "  Cleared jump lists" -ForegroundColor Green
        }
        catch {
            Write-Warning "  Failed to clear jump lists"
        }
    }
}

# Clean Registry
function Clear-Registry {
    if (-not (Test-Admin)) {
        Write-Warning "Admin rights required to clean registry"
        return
    }
    
    Write-Host "Cleaning registry entries..." -ForegroundColor Yellow
    
    # Clear run history
    try {
        Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU" -Name * -ErrorAction SilentlyContinue
        Write-Host "  Cleared run history" -ForegroundColor Green
    }
    catch {
        Write-Warning "  Failed to clear run history"
    }
    
    # Clear search history
    try {
        Remove-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\WordWheelQuery" -Recurse -ErrorAction SilentlyContinue
        Write-Host "  Cleared search history" -ForegroundColor Green
    }
    catch {
        Write-Warning "  Failed to clear search history"
    }
}

# Main execution
Write-Host "`nLackadaisical Anonymity Toolkit - Trace Remover" -ForegroundColor Cyan
Write-Host "============================================`n" -ForegroundColor Cyan

if ($All) {
    $EventLogs = $TempFiles = $BrowserData = $Registry = $DNSCache = $Prefetch = $RecentDocs = $true
}

if (-not ($EventLogs -or $TempFiles -or $BrowserData -or $Registry -or $DNSCache -or $Prefetch -or $RecentDocs)) {
    Write-Host "No options specified. Use -All or specific switches."
    Write-Host "Run 'Get-Help .\Remove-Traces.ps1' for more information."
    exit
}

if ($EventLogs) { Clear-EventLogs }
if ($TempFiles) { Remove-TempFiles }
if ($BrowserData) { Clear-BrowserData }
if ($DNSCache) { Clear-DNSCache }
if ($Prefetch) { Clear-Prefetch }
if ($RecentDocs) { Clear-RecentDocs }
if ($Registry) { Clear-Registry }

Write-Host "`nTrace removal complete!" -ForegroundColor Green
