#Requires -Version 5.1
# SPDX-License-Identifier: GPL-3.0-only
# Synthetic checks only. No live host inspection or network requests.
$ErrorActionPreference = 'Stop'
$scanner = Join-Path (Split-Path $PSScriptRoot -Parent) 'Check-Plex2Shell.ps1'
$tokens = $null; $parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($scanner, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }

# Exercise the actual version functions and report builder without inspecting
# this PC. Keeping their AST extents avoids duplicating the production logic.
foreach ($name in @('Add-Finding', 'Add-Version')) {
    $functionAst = $ast.Find({ param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $name
    }, $false)
    if (-not $functionAst) { throw ('Missing scanner function: ' + $name) }
    . ([scriptblock]::Create($functionAst.Extent.Text))
}
$assignments = @($ast.EndBlock.Statements | Where-Object { $_ -is [System.Management.Automation.Language.AssignmentStatementAst] })
$start = $assignments | Where-Object { $_.Left.Extent.Text -eq '$vulnerableExecutables' } | Select-Object -First 1
$end = $assignments | Where-Object { $_.Left.Extent.Text -eq '$report' } | Select-Object -First 1
if (-not $start -or -not $end) { throw 'Report builder not found' }
$source = Get-Content -LiteralPath $scanner -Raw
$buildReport = [scriptblock]::Create($source.Substring($start.Extent.StartOffset, $end.Extent.EndOffset - $start.Extent.StartOffset))
$fixed = [version]'1.43.3.10861'
$cases = @(
    @{Name='Historical vulnerable log'; Version='1.43.2.10000'; Source='HistoricalLog'; Count=0; Inspected=$true},
    @{Name='Vulnerable executable'; Version='1.43.3.10828'; Source='Executable'; Count=1; Inspected=$true},
    @{Name='Fixed executable'; Version='1.43.3.10861'; Source='Executable'; Count=0; Inspected=$true},
    @{Name='Newer executable'; Version='1.43.5.11029'; Source='Executable'; Count=0; Inspected=$true},
    @{Name='Vulnerable executable without data'; Version='1.43.3.10828'; Source='Executable'; Count=1; Inspected=$false}
)
foreach ($case in $cases) {
    $findings = New-Object 'System.Collections.Generic.List[object]'
    $versions = New-Object 'System.Collections.Generic.List[object]'
    $gaps = New-Object 'System.Collections.Generic.List[string]'
    $inventory = New-Object 'System.Collections.Generic.List[object]'
    $registryChecked = New-Object 'System.Collections.Generic.List[string]'
    $checked = @()
    if ($case.Inspected) { $checked = @('SyntheticPlexData') }
    # Running and installed checks may report the same executable; count once.
    Add-Version $case.Version 'SyntheticPlex.exe' $case.Source
    Add-Version $case.Version 'SyntheticPlex.exe' $case.Source
    . $buildReport
    if ($report.VulnerableExecutableCount -ne $case.Count -or $report.HighPriorityCount -ne $case.Count) {
        throw ('Wrong version warning count: ' + $case.Name)
    }
    if (($report.Status -like 'WARNING:*') -ne [bool]$case.Count) { throw ('Wrong warning status: ' + $case.Name) }
    if (-not $case.Inspected -and $report.Status -notlike '*INCOMPLETE*') { throw 'Incomplete status was lost' }
}

$fixture = Join-Path ([IO.Path]::GetTempPath()) ('PlexReporting-' + [guid]::NewGuid().ToString('N'))
try {
    $data = Join-Path $fixture 'Data'
    $logs = Join-Path $data 'Logs'
    $codecs = Join-Path $data 'Codecs'
    $output = Join-Path $fixture 'Report'
    $null = New-Item -ItemType Directory -Path $logs,$codecs -Force
    $privateMarker = 'synthetic-private-marker-not-for-export'
    @('Plex Media Server v1.43.2.10000', ('dump-yuv ' + $privateMarker)) |
        Set-Content -LiteralPath (Join-Path $logs 'Plex Media Server.log')
    # A hostile XML document must be rejected without expanding its entity.
    '<!DOCTYPE Preferences [<!ENTITY test "synthetic-entity">]><Preferences TranscoderH264Options="&test;" />' |
        Set-Content -LiteralPath (Join-Path $data 'Preferences.xml')
    $payload = New-Object byte[] 131072
    $payload[0] = 77; $payload[1] = 90
    [IO.File]::WriteAllBytes((Join-Path $codecs 'myawesomeproxy.dll'), $payload)
    & $scanner -Offline -DataPath $data -OutputDirectory $output
    $json = Get-Content -LiteralPath (Join-Path $output 'report.json') -Raw
    $text = Get-Content -LiteralPath (Join-Path $output 'report.txt') -Raw
    $result = $json | ConvertFrom-Json
    if ($json.Contains($privateMarker) -or $text.Contains($privateMarker)) { throw 'Raw log content leaked into reports' }
    foreach ($check in @('Payload filename', 'Uniform executable tail', 'Log: Transcoder file-write option')) {
        if (-not @($result.Findings | Where-Object { $_.Check -eq $check }).Count) { throw ('Missing finding: ' + $check) }
    }
    if ($result.VulnerableExecutableCount -ne 0) { throw 'Historical offline version treated as an installed executable' }
    if (-not @($result.CoverageGaps | Where-Object { $_ -like 'Preferences.xml could not be parsed*' }).Count) {
        throw 'Hostile XML was not reported as a coverage gap'
    }
    if (@($result.CodecFiles).Count -ne 1 -or $result.CodecFiles[0].SHA256 -notmatch '^[A-Fa-f0-9]{64}$') {
        throw 'Codec hash inventory is missing'
    }
    Write-Host 'PASS: version warnings, duplicate observations, offline indicators, XML rejection and report privacy.'
} finally {
    if (Test-Path -LiteralPath $fixture) { Remove-Item -LiteralPath $fixture -Recurse -Force }
}
