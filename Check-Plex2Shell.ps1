#Requires -Version 5.1
<#
.SYNOPSIS
Read-only Windows Plex2Shell indicator triage. Writes reports only.
.DESCRIPTION
No exploit requests, network lookups, downloads, cleanup or setting changes.
No result proves absence of a previous compromise. See README.md.
#>
[CmdletBinding()]
param(
    [string[]]$DataPath,
    [string]$OutputDirectory = (Join-Path (Get-Location) ('Plex-Triage-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))),
    [ValidateRange(1,4096)][int]$MaxLogMB = 64,
    [switch]$Offline
)
$ErrorActionPreference = 'Stop'
$findings = New-Object 'System.Collections.Generic.List[object]'
$gaps = New-Object 'System.Collections.Generic.List[string]'
$inventory = New-Object 'System.Collections.Generic.List[object]'
$versions = New-Object 'System.Collections.Generic.List[object]'
$registryChecked = New-Object 'System.Collections.Generic.List[string]'
$registrySeen = @{}
$fixed = [version]'1.43.3.10861'
function Add-Finding($Level, $Check, $Location, $Detail) {
    $findings.Add([pscustomobject]@{Level=$Level; Check=$Check; Location=$Location; Detail=$Detail})
}
function Add-Version($Text, $Location) {
    if ($Text -match '(?<!\d)(1\.\d+\.\d+\.\d+)') {
        $v = $Matches[1]
        $versions.Add([pscustomobject]@{Version=$v; Location=$Location; BelowFixedVersion=([version]$v -lt $fixed)})
    }
}
$rules = [ordered]@{
    'Known payload name or proxy domain' = '(?i)myawesomeproxy|mylovelyminer|x12345|proxystream\.st'
    'Miner name (not specific to Plex2Shell)' = '(?i)\bxmrig\b'
    'Transcoder file-write option' = '(?i)dump(?:-|%2d)yuv'
    'Exploit tool marker' = '(?i)plex2shell|vfyclient01'
    'Agent function abuse candidate' = '(?i)GetResultFromNetwork'
    'Mining protocol (not specific to Plex2Shell)' = '(?i)stratum\+(tcp|ssl)|\bcryptonight\b'
    'External transcode URL (can be legitimate)' = '(?i)transcode/universal[^\s]*[?&]url=(https?|ftp|gopher)(:|%3a)'
    'Unusual timeline or token marker' = '(?i)GET /player/timeline\?\$|\$X-Plex-Token'
    'Timeline URL protocol request (attempt only)' = '(?i)/player/timeline/subscribe\?[^\s]*\bprotocol=[a-z][a-z0-9+.-]*:'
    'Agent function URL injection candidate' = '(?i)searchOne\?[^\s]*identifier=[^&\s]*/function/'
    'Transcoder stats file-write candidate' = '(?i)TranscoderH264Options[^\s]*stats='
}
function Check-Options($Name, $Value, $Location) {
    if ($Name -notmatch '^Transcoder.*Options$') { return }
    $s = [string]$Value
    if ([string]::IsNullOrWhiteSpace($s)) { return }
    # Deliberately do not export the value, which may contain credentials/URLs.
    if ($s -match '(?i)dump(?:-|%2d)yuv') {
        Add-Finding 'High' 'Transcoder file-write setting' $Location ($Name + ' contains dump-yuv; investigate unauthorized file writes.')
    } elseif ($s -match '(?i)(^|[:\s])stats=') {
        Add-Finding 'Review' 'Transcoder stats file-write setting' $Location ($Name + ' contains stats=; this can write a file. Confirm that you configured it. Value omitted.')
    } else {
        Add-Finding 'Review' 'Custom transcoder setting' $Location ($Name + ' is nonempty. Custom settings can be legitimate; inspect locally.')
    }
}
$roots = New-Object 'System.Collections.Generic.List[string]'
$profiles = @()
function Get-PlexProfilePath($Sid) {
    if (-not $Sid) { return $null }
    $profile = $profiles | Where-Object { $_.SID -eq $Sid } | Select-Object -First 1
    if ($profile.LocalPath) { return $profile.LocalPath }
    try {
        $key = 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\' + $Sid
        $value = (Get-ItemProperty -LiteralPath $key -Name ProfileImagePath).ProfileImagePath
        if ($value) { return [Environment]::ExpandEnvironmentVariables($value) }
    } catch { }
    return $null
}
function Add-PlexProfileFolder($ProfilePath) {
    if (-not $ProfilePath) { return }
    $candidate = Join-Path $ProfilePath 'AppData\Local\Plex Media Server'
    try {
        if (Test-Path -LiteralPath $candidate -PathType Container) { $roots.Add($candidate) }
    } catch { $gaps.Add('Could not check user data folder: ' + $candidate) }
}
function Check-CodecContent($File) {
    # Read bytes as data only. Never load the library or execute its code.
    # Large uniform tails can also occur in legitimate binaries.
    if ($File.Length -lt 131072) { return }
    $stream = $null
    try {
        $stream = [IO.File]::Open($File.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
        $a = $stream.ReadByte(); $b = $stream.ReadByte()
        $binary = ($a -eq 77 -and $b -eq 90)
        if ($a -eq 127 -and $b -eq 69) {
            $binary = ($stream.ReadByte() -eq 76 -and $stream.ReadByte() -eq 70)
        }
        if (-not $binary) { return }
        $null = $stream.Seek(-65536, [IO.SeekOrigin]::End)
        $buffer = New-Object byte[] 65536
        $read = 0
        while ($read -lt $buffer.Length) {
            $n = $stream.Read($buffer, $read, $buffer.Length - $read)
            if ($n -eq 0) { throw 'File changed during read' }
            $read += $n
        }
        $uniform = $true
        for ($i=1; $i -lt $buffer.Length; $i++) {
            if ($buffer[$i] -ne $buffer[0]) { $uniform = $false; break }
        }
        if ($uniform) {
            Add-Finding 'Review' 'Uniform executable tail' $File.FullName 'Executable header and 64 KiB of identical trailing bytes. Consistent with some dump-yuv payloads, but legitimate padding is also possible; requires further examination.'
        }
    } catch { $gaps.Add('Codec content check incomplete: ' + $File.FullName) }
    finally { if ($stream) { $stream.Dispose() } }
}
function Read-PlexRegistry($Key) {
    if ($registrySeen.ContainsKey($Key)) { return $registrySeen[$Key] }
    $registrySeen[$Key] = $false
    try {
        if (Test-Path -LiteralPath $Key) {
            $r = Get-ItemProperty -LiteralPath $Key
            foreach ($prop in $r.PSObject.Properties) { Check-Options $prop.Name $prop.Value $Key }
            if (-not $DataPath -and $r.LocalAppDataPath) {
                $base = [string]$r.LocalAppDataPath
                if ($base -match '%') {
                    $sid = $null
                    if ($Key -match 'HKEY_USERS\\(S-[^\\]+)\\') { $sid = $Matches[1] }
                    elseif ($Key -match 'HKEY_CURRENT_USER\\') { $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value }
                    $profilePath = Get-PlexProfilePath $sid
                    if ($profilePath) {
                        $variables = @{USERPROFILE=$profilePath; LOCALAPPDATA=(Join-Path $profilePath 'AppData\Local'); APPDATA=(Join-Path $profilePath 'AppData\Roaming')}
                        foreach ($token in [regex]::Matches($base, '%([^%]+)%')) {
                            if ($variables.ContainsKey($token.Groups[1].Value)) { $base = $base.Replace($token.Value, $variables[$token.Groups[1].Value]) }
                        }
                    }
                    # Do not expand another account's variables in the scanner's environment.
                    if ($base -match '%') {
                        $gaps.Add('Custom data path has unresolved environment variables; supply -DataPath for ' + $Key)
                    }
                }
                if ($base -notmatch '%') { $roots.Add((Join-Path $base 'Plex Media Server')) }
            }
            $registryChecked.Add($Key)
            $registrySeen[$Key] = $true
        }
    } catch { $gaps.Add('Could not read Plex settings at ' + $Key) }
    return $registrySeen[$Key]
}
if ($DataPath) { foreach ($p in $DataPath) { $roots.Add($p) } }
$processes = @()
$related = @{}
if (-not $Offline) {
    try { $profiles = @(Get-CimInstance Win32_UserProfile) }
    catch {
        $gaps.Add('User profiles could not be enumerated via CIM; trying the Windows profile registry.')
        try {
            $profiles = @(Get-ChildItem 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList' | Where-Object {
                $_.PSChildName -match '^S-1-(5-21|12-1)-'
            } | ForEach-Object {
                $value = Get-ItemProperty -LiteralPath $_.PSPath -Name ProfileImagePath
                [pscustomobject]@{SID=$_.PSChildName; LocalPath=[Environment]::ExpandEnvironmentVariables($value.ProfileImagePath); Special=$false}
            })
        } catch { $gaps.Add('Windows profile registry discovery failed; supply -DataPath with the Plex user data folder.') }
    }
    # Inspect only loaded user hives. Never load or modify another user's hive.
    $keys = @('Registry::HKEY_CURRENT_USER\Software\Plex, Inc.\Plex Media Server')
    try {
        $keys += @(Get-ChildItem 'Registry::HKEY_USERS' | Where-Object { $_.PSChildName -match '^S-1-(5-21|12-1)-' -and $_.PSChildName -notmatch '_Classes$' } | ForEach-Object {
            'Registry::HKEY_USERS\' + $_.PSChildName + '\Software\Plex, Inc.\Plex Media Server'
        })
    } catch { $gaps.Add('Could not enumerate loaded user registry hives.') }
    foreach ($key in ($keys | Select-Object -Unique)) {
        $null = Read-PlexRegistry $key
    }
    try {
        $processes = @(Get-CimInstance Win32_Process)
        foreach ($p in $processes) {
            if ($p.Name -ieq 'Plex Media Server.exe') {
                $related[[int]$p.ProcessId] = $true
                try {
                    $owner = Invoke-CimMethod -InputObject $p -MethodName GetOwnerSid
                    if ($owner.ReturnValue -ne 0 -or -not $owner.Sid) { throw 'Owner SID unavailable' }
                    if (-not $DataPath) { Add-PlexProfileFolder (Get-PlexProfilePath $owner.Sid) }
                    $ownerKey = 'Registry::HKEY_USERS\' + $owner.Sid + '\Software\Plex, Inc.\Plex Media Server'
                    if (Read-PlexRegistry $ownerKey) {
                        Add-Finding 'Info' 'Running Plex account settings inspected' ('PID ' + $p.ProcessId) $ownerKey
                    } else { $gaps.Add('Running Plex account settings were NOT inspected (key absent, hive unloaded, or access denied): ' + $ownerKey) }
                } catch { $gaps.Add('Could not verify the registry settings of the running Plex account for PID ' + $p.ProcessId) }
            }
        }
        # Creation-time comparison reduces PID-reuse false positives.
        $changed = $true
        while ($changed) {
            $changed = $false
            foreach ($p in $processes) {
                if ($related.ContainsKey([int]$p.ParentProcessId) -and -not $related.ContainsKey([int]$p.ProcessId)) {
                    $parent = $processes | Where-Object { $_.ProcessId -eq $p.ParentProcessId } | Select-Object -First 1
                    if ($parent -and $p.CreationDate -ge $parent.CreationDate) {
                        $related[[int]$p.ProcessId] = $true; $changed = $true
                    }
                }
            }
        }
        foreach ($p in $processes) {
            $where = 'PID ' + $p.ProcessId + ' (' + $p.Name + ')'
            $combined = [string]$p.Name + ' ' + [string]$p.CommandLine
            if ($combined -match '(?i)myawesomeproxy|mylovelyminer|x12345|\bxmrig\b|proxystream\.st|dump-yuv') {
                Add-Finding 'High' 'Process indicator' $where 'Known suspicious name, domain or file-write option. Command line omitted for privacy.'
            }
            if ($combined -match '(?i)stratum\+(tcp|ssl)|\bcryptonight\b|\bminerd(?:\.exe)?\b') {
                Add-Finding 'Review' 'Mining process marker' $where 'Mining protocol or miner marker in process name/arguments; may be intentionally installed. Arguments omitted.'
            }
            if ($related.ContainsKey([int]$p.ProcessId)) {
                if (-not $p.CommandLine) { $gaps.Add('Command line unavailable for ' + $where + '; argument-based checks incomplete.') }
                Add-Finding 'Info' 'Plex process tree' $where 'Currently running Plex process or descendant; review unfamiliar names.'
                if ($p.Name -match '^(cmd|powershell|pwsh|wscript|cscript|mshta|rundll32|curl|certutil)\.exe$') {
                    Add-Finding 'High' 'Shell or utility under Plex' $where 'Unexpected for ordinary Plex operation; investigate parentage and purpose.'
                }
                if (-not $p.ExecutablePath) { $gaps.Add('Executable path unavailable for ' + $where + '; try elevation.') }
                elseif ($p.Name -ieq 'Plex Media Server.exe') {
                    Add-Version ([Diagnostics.FileVersionInfo]::GetVersionInfo($p.ExecutablePath).FileVersion) $p.ExecutablePath
                }
            }
        }
        if ($related.Count -eq 0) { $gaps.Add('Plex was not running. Live process and connection checks cannot describe its prior activity.') }
    } catch { $gaps.Add('Live process inspection failed: ' + $_.Exception.GetType().Name) }
    if (-not $DataPath) {
        foreach ($profile in $profiles) {
            if (-not $profile.Special) { Add-PlexProfileFolder $profile.LocalPath }
        }
    }
    try {
        foreach ($c in (Get-NetTCPConnection -State Established)) {
            if ($c.RemotePort -in @(3333,14444,14433,45700)) {
                $cp = $processes | Where-Object { $_.ProcessId -eq $c.OwningProcess } | Select-Object -First 1
                Add-Finding 'Review' 'Connection on a possible mining port' ('PID ' + $c.OwningProcess + ' (' + $cp.Name + ')') ($c.RemoteAddress + ':' + $c.RemotePort + '; port alone is not proof of mining or Plex involvement.')
            }
            if ($related.ContainsKey([int]$c.OwningProcess)) {
                Add-Finding 'Info' 'Live Plex TCP connection' ('PID ' + $c.OwningProcess) ($c.RemoteAddress + ':' + $c.RemotePort + '; not by itself evidence of compromise.')
            }
        }
    } catch { $gaps.Add('Live TCP connection check unavailable.') }
    try {
        # Cache only: no DNS queries or contact with the indicator domain.
        $dns = @(Get-DnsClientCache | Where-Object { $_.Entry -match '(^|\.)proxystream\.st\.?$' -or $_.RecordName -match '(^|\.)proxystream\.st\.?$' })
        if ($dns.Count) { Add-Finding 'Review' 'Known domain in DNS cache' 'Windows DNS cache' 'proxystream.st was cached; this does not attribute the lookup to Plex.' }
    } catch { $gaps.Add('DNS cache check unavailable.') }
    foreach ($base in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
        if ($base) {
            $exe = Join-Path $base 'Plex\Plex Media Server\Plex Media Server.exe'
            try { if (Test-Path -LiteralPath $exe) { Add-Version ([Diagnostics.FileVersionInfo]::GetVersionInfo($exe).FileVersion) $exe } }
            catch { $gaps.Add('Could not read installed version at ' + $exe) }
        }
    }
} else { $gaps.Add('Offline mode: registry, processes, installed versions, TCP and DNS cache were not inspected.') }

$checked = @()
foreach ($root in ($roots | Select-Object -Unique)) {
    try {
        if (-not (Test-Path -LiteralPath $root -PathType Container)) { $gaps.Add('Data folder missing or inaccessible: ' + $root); continue }
    } catch { $gaps.Add('Could not access data folder: ' + $root); continue }
    $checked += $root
    Write-Host ('Inspecting ' + $root)
    $pref = Join-Path $root 'Preferences.xml'
    if (Test-Path -LiteralPath $pref) {
        try {
            # Disable DTDs/external entities when inspecting potentially hostile XML.
            $settings = New-Object System.Xml.XmlReaderSettings
            $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
            $settings.XmlResolver = $null
            $reader = [System.Xml.XmlReader]::Create($pref, $settings)
            try {
                $doc = New-Object System.Xml.XmlDocument
                $doc.XmlResolver = $null; $doc.Load($reader)
                foreach ($a in $doc.DocumentElement.Attributes) { Check-Options $a.Name $a.Value $pref }
            } finally { $reader.Dispose() }
        } catch { $gaps.Add('Preferences.xml could not be parsed at ' + $root) }
    }
    $codec = Join-Path $root 'Codecs'
    if (Test-Path -LiteralPath $codec) {
        try {
            # Enumerate without following directory junctions or symbolic links.
            $pending = New-Object 'System.Collections.Generic.Queue[string]'
            $pending.Enqueue($codec)
            while ($pending.Count) {
                foreach ($f in (Get-ChildItem -LiteralPath $pending.Dequeue() -Force)) {
                    if ($f.Attributes -band [IO.FileAttributes]::ReparsePoint) { $gaps.Add('Skipped linked codec entry: ' + $f.FullName); continue }
                    if ($f.PSIsContainer) { $pending.Enqueue($f.FullName); continue }
                    $hash = $null
                    try { $hash = (Get-FileHash -LiteralPath $f.FullName -Algorithm SHA256).Hash }
                    catch { $gaps.Add('Could not hash codec file: ' + $f.FullName) }
                    $inventory.Add([pscustomobject]@{Path=$f.FullName; Bytes=$f.Length; CreatedUtc=$f.CreationTimeUtc.ToString('o'); ModifiedUtc=$f.LastWriteTimeUtc.ToString('o'); SHA256=$hash})
                    Check-CodecContent $f
                    if ($f.Name -match '(?i)myawesomeproxy|mylovelyminer|x12345|xmrig') {
                        Add-Finding 'High' 'Payload filename' $f.FullName 'Filename matches a reported payload indicator; validate the file.'
                    } elseif ($f.Extension -match '^\.(exe|ps1|bat|cmd|vbs|so)$') {
                        Add-Finding 'Review' 'Unusual Windows codec file' $f.FullName 'Unexpected file type for a Windows codec cache; investigate. Filename alone is not proof.'
                    } elseif ($f.Extension -ieq '.dll' -and $f.Name -notmatch '^(lib)?[a-z0-9_]+_(encoder|decoder)\.dll$') {
                        Add-Finding 'Review' 'Unfamiliar codec DLL name' $f.FullName 'Name differs from common Plex encoder/decoder naming. This is a heuristic, not a trusted allowlist; normal names can also be spoofed.'
                    }
                }
            }
        } catch { $gaps.Add('Codec enumeration incomplete at ' + $codec) }
    } else { $gaps.Add('No Codecs folder at ' + $root) }
    $logDir = Join-Path $root 'Logs'
    if (-not (Test-Path -LiteralPath $logDir)) { $gaps.Add('No Logs folder at ' + $root); continue }
    try {
        $logs = @(Get-ChildItem -LiteralPath $logDir -File | Where-Object { $_.Name -match '\.(log|txt)(\.\d+)?$' })
        if (-not $logs.Count) { $gaps.Add('No uncompressed log files found at ' + $logDir) }
        foreach ($log in $logs) {
            if ($log.Length -gt ([long]$MaxLogMB * 1MB)) { $gaps.Add('Skipped oversized log (raise -MaxLogMB): ' + $log.FullName); continue }
            $lineNo = 0; $seenVersions = @{}; $hits = @{}
            $logStream = $null; $logReader = $null
            try {
                # Plex may hold its active logs open for writing. Allow sharing
                # with the writer and rotation; never lock or modify the log.
                $logStream = [IO.File]::Open($log.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
                $logReader = New-Object IO.StreamReader($logStream)
                while ($null -ne ($line = $logReader.ReadLine())) {
                    $lineNo++
                    if ($line -match 'Plex Media Server v?(1\.\d+\.\d+\.\d+)') {
                        $v = $Matches[1]
                        if (-not $seenVersions.ContainsKey($v)) { Add-Version $v ($log.FullName + ':' + $lineNo); $seenVersions[$v]=$true }
                    }
                    try { $decoded = [Uri]::UnescapeDataString($line) } catch { $decoded = $line }
                    foreach ($rule in $rules.Keys) {
                        if ($decoded -match $rules[$rule]) {
                            if (-not $hits.ContainsKey($rule)) { $hits[$rule] = @{Count=0; Lines=(New-Object 'System.Collections.Generic.List[int]')} }
                            $hits[$rule].Count++
                            if ($hits[$rule].Lines.Count -lt 20) { $hits[$rule].Lines.Add($lineNo) }
                        }
                    }
                }
                foreach ($rule in $hits.Keys) {
                    Add-Finding 'Review' ('Log: ' + $rule) $log.FullName ('Matches: ' + $hits[$rule].Count + '; first line numbers: ' + ($hits[$rule].Lines -join ', ') + '. May indicate an attempt, not successful execution. Raw text omitted.')
                }
            } catch { $gaps.Add('Log read incomplete: ' + $log.FullName + ' (' + $_.Exception.GetType().Name + ')') }
            finally {
                if ($logReader) { $logReader.Dispose() }
                elseif ($logStream) { $logStream.Dispose() }
            }
        }
    } catch { $gaps.Add('Could not enumerate logs at ' + $logDir) }
}
if (-not $checked.Count) { $gaps.Add('NO PLEX DATA FOLDER INSPECTED. Supply -DataPath with the actual Plex server data directory.') }
$high = @($findings | Where-Object { $_.Level -eq 'High' }).Count
$review = @($findings | Where-Object { $_.Level -eq 'Review' }).Count
$status = 'No configured indicators detected; this is NOT a clean bill of health.'
if ($high -or $review) { $status = 'Indicators or review items found. Investigate before concluding whether compromise occurred.' }
if ($gaps.Count) { $status += ' Coverage is incomplete; read CoverageGaps.' }
if (-not $checked.Count) { $status = 'INCOMPLETE: no Plex data folder inspected.' }
$report = [ordered]@{
    GeneratedUtc=[DateTime]::UtcNow.ToString('o'); Status=$status
    HighPriorityCount=$high; ReviewCount=$review; DataFolders=$checked
    Limitations=@('A snapshot cannot rule out historical compromise, removed payloads or expired logs.', 'Codec hashes are inventory only; no known-good baseline or malware hash database is used.', 'Ordinary DLL files are not flagged solely for being DLLs. Their presence is neither proof of infection nor proof of safety.', 'Live descendants may disappear; persistent tasks, services, registry autoruns, memory and all other users are not comprehensively inspected.', 'Historical vulnerable versions do not prove the server was reachable or exploited at that time.', 'No raw log lines, command lines or Plex tokens are intentionally exported. Paths, addresses and filenames can still be private.')
    CoverageGaps=$gaps.ToArray(); RegistryKeysInspected=$registryChecked.ToArray(); Versions=@($versions | Sort-Object Version,Location -Unique)
    Findings=$findings.ToArray(); CodecFiles=$inventory.ToArray()
    Sources=@('https://forums.plex.tv/t/important-security-update-for-plex-media-server-v1-43-2-and-earlier/942319/3', 'https://support.plex.tv/articles/202915258-where-is-the-plex-media-server-data-directory-located/', 'https://support.plex.tv/articles/201105343-advanced-hidden-server-settings/', 'https://github.com/code-zm/plex2shell/blob/main/plex2shell.py', 'https://github.com/ChrisLPJones/plex2shell-check')
}
$null = New-Item -ItemType Directory -Path $OutputDirectory -Force
$report | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $OutputDirectory 'report.json') -Encoding UTF8
$summary = @('PLEX2SHELL WINDOWS TRIAGE', $status, ('High priority: ' + $high + '; review items: ' + $review), '', 'COVERAGE GAPS')
$summary += $gaps.ToArray()
$summary += @('', 'PLEX DATA FOLDERS INSPECTED')
$summary += $checked
$summary += @('', 'PLEX REGISTRY KEYS SUCCESSFULLY INSPECTED')
$summary += $registryChecked.ToArray()
$summary += @('', 'VERSION OBSERVATIONS (historical versions are not current exposure)', ($report.Versions | Format-Table -AutoSize | Out-String -Width 240), 'FINDINGS', ($findings | Format-List | Out-String -Width 240), 'LIMITATIONS')
$summary += $report.Limitations
$summary | Set-Content -LiteralPath (Join-Path $OutputDirectory 'report.txt') -Encoding UTF8
Write-Host $status
Write-Host ('High priority: ' + $high + '; review items: ' + $review + '; coverage gaps: ' + $gaps.Count)
Write-Host ('Reports saved to: ' + [IO.Path]::GetFullPath($OutputDirectory))
