#Requires -Version 5.1
# Run on Windows: powershell.exe -NoProfile -File .\tests\Test-ProfileDiscovery.ps1
# Runs the scanner against synthetic user profiles; no live host checks are used.
$ErrorActionPreference = 'Stop'
$scanner = Join-Path (Split-Path $PSScriptRoot -Parent) 'Check-Plex2Shell.ps1'
$fixture = Join-Path ([IO.Path]::GetTempPath()) ('PlexDiscovery-' + [guid]::NewGuid().ToString('N'))
$originalLocalAppData = $env:LOCALAPPDATA
try {
    $userProfile = Join-Path $fixture 'Users\PlexUser'
    $systemProfile = Join-Path $fixture 'Windows\System32\config\systemprofile'
    $userData = Join-Path $userProfile 'AppData\Local\Plex Media Server'
    $systemData = Join-Path $systemProfile 'AppData\Local\Plex Media Server'
    foreach ($data in @($userData, $systemData)) {
        $null = New-Item -ItemType Directory -Path (Join-Path $data 'Codecs') -Force
        $null = New-Item -ItemType Directory -Path (Join-Path $data 'Logs') -Force
        'Normal startup' | Set-Content -LiteralPath (Join-Path $data 'Logs\Plex Media Server.log')
    }
    $env:LOCALAPPDATA = Join-Path $systemProfile 'AppData\Local'
    & {
        param($ScannerPath, $FixturePath, $UserPath, $SystemPath)
        $userSid = 'S-1-5-21-100-200-300-1001'
        $simulateCustomPath = $false
        function Get-CimInstance($ClassName) {
            switch ($ClassName) {
                'Win32_UserProfile' {
                    [pscustomobject]@{SID=$userSid; LocalPath=$UserPath; Special=$false}
                    [pscustomobject]@{SID='S-1-5-18'; LocalPath=$SystemPath; Special=$true}
                }
                'Win32_Process' {
                    [pscustomobject]@{Name='Plex Media Server.exe'; ProcessId=42; ParentProcessId=0; CreationDate=(Get-Date); CommandLine='Plex Media Server.exe'; ExecutablePath=$null}
                }
                default { throw 'Unexpected CIM class' }
            }
        }
        function Invoke-CimMethod { [pscustomobject]@{ReturnValue=0; Sid=$userSid} }
        function Get-NetTCPConnection { }
        function Get-DnsClientCache { }
        function Get-ItemProperty {
            if ($simulateCustomPath) { return [pscustomobject]@{LocalAppDataPath='%localappdata%'} }
            throw 'Synthetic registry is empty'
        }
        function Test-Path {
            param($LiteralPath, $PathType)
            if ($LiteralPath -like 'Registry::*') {
                return ($simulateCustomPath -and $LiteralPath -eq ('Registry::HKEY_USERS\' + $userSid + '\Software\Plex, Inc.\Plex Media Server'))
            }
            if (-not $LiteralPath.StartsWith($FixturePath)) { return $false }
            if ($PathType) { return Microsoft.PowerShell.Management\Test-Path -LiteralPath $LiteralPath -PathType $PathType }
            return Microsoft.PowerShell.Management\Test-Path -LiteralPath $LiteralPath
        }
        function Get-ChildItem {
            param($LiteralPath, [switch]$Force, [switch]$File)
            if ($LiteralPath -like 'Registry::*') { return }
            Microsoft.PowerShell.Management\Get-ChildItem -LiteralPath $LiteralPath -Force:$Force -File:$File
        }
        $output = Join-Path $FixturePath 'Report'
        & $ScannerPath -OutputDirectory $output
        $report = Get-Content -LiteralPath (Join-Path $output 'report.json') -Raw | ConvertFrom-Json
        $expected = Join-Path $UserPath 'AppData\Local\Plex Media Server'
        if (@($report.DataFolders).Count -ne 1 -or $report.DataFolders[0] -ne $expected) {
            throw ('Wrong profile discovery: ' + ($report.DataFolders -join ', '))
        }
        $summary = Get-Content -LiteralPath (Join-Path $output 'report.txt') -Raw
        if (-not $summary.Contains('PLEX DATA FOLDERS INSPECTED') -or -not $summary.Contains($expected)) {
            throw 'Text report does not identify the inspected user data folder'
        }
        if (@($report.CoverageGaps | Where-Object { $_ -like '*systemprofile*' }).Count) {
            throw 'Unrelated SYSTEM profile appeared in coverage gaps'
        }
        # Explicit paths must still override automatic profile discovery.
        $explicitOutput = Join-Path $FixturePath 'ExplicitReport'
        $explicitData = Join-Path $SystemPath 'AppData\Local\Plex Media Server'
        & $ScannerPath -DataPath $explicitData -OutputDirectory $explicitOutput
        $explicit = Get-Content -LiteralPath (Join-Path $explicitOutput 'report.json') -Raw | ConvertFrom-Json
        if (@($explicit.DataFolders).Count -ne 1 -or $explicit.DataFolders[0] -ne $explicitData) {
            throw 'Explicit -DataPath did not override discovery'
        }
        # Expand another user's registry variables using their profile, with any casing.
        $simulateCustomPath = $true
        $customOutput = Join-Path $FixturePath 'CustomReport'
        & $ScannerPath -OutputDirectory $customOutput
        $custom = Get-Content -LiteralPath (Join-Path $customOutput 'report.json') -Raw | ConvertFrom-Json
        if (@($custom.DataFolders).Count -ne 1 -or $custom.DataFolders[0] -ne $expected -or -not @($custom.RegistryKeysInspected).Count) {
            throw 'Registry data path was not resolved using the Plex user profile'
        }
    } $scanner $fixture $userProfile $systemProfile
    Write-Host 'PASS: user discovery, SYSTEM exclusion, report paths, explicit override and registry expansion.'
} finally {
    $env:LOCALAPPDATA = $originalLocalAppData
    if (Test-Path -LiteralPath $fixture) { Remove-Item -LiteralPath $fixture -Recurse -Force }
}
