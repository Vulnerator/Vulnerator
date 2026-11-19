# Starts the built Vulnerator.exe as a user would (fresh settings) and checks that a window appears within the timeout.
# On failure it reports whether the process exited or is running without a window, plus the .NET / application crash
# entries from the Windows event log and any Vulnerator error log, as GitHub annotations.
#
# Windows PowerShell 5.1. Pure ASCII; no PowerShell 7 syntax.
# Usage: powershell -NoProfile -ExecutionPolicy Bypass -File tools\tests\Test-Launch.ps1 -BinDir bin\Release
param([Parameter(Mandatory = $true)][string]$BinDir, [int]$TimeoutSeconds = 60)
$ErrorActionPreference = 'Stop'

function Note([string]$Level, [string]$Text) {
    Write-Host ($Level.ToUpper() + ' ' + $Text)
    if ($env:GITHUB_ACTIONS -eq 'true') {
        $clean = ($Text -replace '%', '%25' -replace "`r", '' -replace "`n", '%0A')
        if ($clean.Length -gt 4000) { $clean = $clean.Substring(0, 4000) }
        Write-Host ('::' + $Level + '::' + $clean)
    }
}

$binPath = (Resolve-Path $BinDir).Path
$exe = Join-Path $binPath 'Vulnerator.exe'
$started = Get-Date
$process = Start-Process -FilePath $exe -WorkingDirectory $binPath -PassThru
$window = $false
$deadline = $started.AddSeconds($TimeoutSeconds)
while ((Get-Date) -lt $deadline) {
    Start-Sleep -Milliseconds 500
    $process.Refresh()
    if ($process.HasExited) { break }
    if ($process.MainWindowHandle -ne [IntPtr]::Zero) { $window = $true; break }
}

if ($window) {
    Note 'notice' ('Vulnerator started: window "' + $process.MainWindowTitle + '" after ' + [int]((Get-Date) - $started).TotalSeconds + ' s')
    Start-Sleep -Seconds 3
    $process.Refresh()
    if ($process.HasExited) { Note 'error' ('Vulnerator closed right after showing its window (exit code ' + $process.ExitCode + ')') }
    else { Stop-Process -Id $process.Id -Force; exit 0 }
}
elseif ($process.HasExited) { Note 'error' ('Vulnerator exited without showing a window (exit code ' + $process.ExitCode + ')') }
else {
    Note 'error' ('Vulnerator is running (pid ' + $process.Id + ') but showed no window within ' + $TimeoutSeconds + ' s')
    Stop-Process -Id $process.Id -Force -ErrorAction SilentlyContinue
}

# Why: .NET Runtime (1026) and Application Error (1000) entries since launch, then Vulnerator's own logs.
try {
    $events = @(Get-WinEvent -FilterHashtable @{ LogName = 'Application'; StartTime = $started.AddSeconds(-5) } -ErrorAction SilentlyContinue |
        Where-Object { $_.ProviderName -in '.NET Runtime', 'Application Error', 'Windows Error Reporting' } | Select-Object -First 4)
    foreach ($entry in $events) { Note 'error' ('Event log ' + $entry.ProviderName + ' ' + $entry.Id + ': ' + $entry.Message) }
    if ($events.Count -eq 0) { Note 'warning' 'No .NET / application crash entries in the event log' }
}
catch { Note 'warning' ('Could not read the event log: ' + $_.Exception.Message) }
$logs = @((Join-Path ([Environment]::GetFolderPath('Desktop')) 'Vulnerator_ErrorLog.txt'), (Join-Path $binPath 'Logs\V6Log.txt'),
    (Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Vulnerator\Logs\V6Log.txt'))
foreach ($log in $logs) {
    if (Test-Path $log) { Note 'error' ('Log ' + $log + ': ' + ((Get-Content $log -Tail 40) -join "`n")) }
}
# Name the missing piece: build the object App.xaml creates first, in this process, and report what fails to load.
try {
    [System.IO.Directory]::SetCurrentDirectory($binPath)
    $app = [System.Reflection.Assembly]::LoadFrom($exe)
    # Every assembly the program references, followed through the program folder: report what is neither there nor in the GAC.
    $seen = @{}
    $queue = New-Object System.Collections.Queue
    $queue.Enqueue($app)
    while ($queue.Count -gt 0) {
        $assembly = $queue.Dequeue()
        foreach ($reference in $assembly.GetReferencedAssemblies()) {
            if ($seen.ContainsKey($reference.FullName)) { continue }
            $seen[$reference.FullName] = $true
            $local = Join-Path $binPath ($reference.Name + '.dll')
            try {
                if (Test-Path $local) {
                    $loaded = [System.Reflection.Assembly]::LoadFrom($local)
                    if ($loaded.GetName().Version -lt $reference.Version) { Note 'error' ('Older than referenced: ' + $reference.FullName + ' (folder has ' + $loaded.GetName().Version + ', needed by ' + $assembly.GetName().Name + ')') }
                    $queue.Enqueue($loaded)
                }
                else { [void][System.Reflection.Assembly]::Load($reference) }
            }
            catch { Note 'error' ('Missing: ' + $reference.FullName + ' (needed by ' + $assembly.GetName().Name + ')') }
        }
    }
    $config = Join-Path $binPath 'Vulnerator.exe.config'
    Note 'warning' ('Vulnerator.exe.config present: ' + (Test-Path $config) + '; CommonServiceLocator redirect: ' + ((Test-Path $config) -and ((Get-Content $config -Raw) -match 'CommonServiceLocator')))
    foreach ($name in 'CommonServiceLocator', 'GalaSoft.MvvmLight', 'GalaSoft.MvvmLight.Extras', 'GalaSoft.MvvmLight.Platform', 'MahApps.Metro', 'ControlzEx') {
        $path = Join-Path $binPath ($name + '.dll')
        if (Test-Path $path) { Note 'warning' ($name + '.dll ' + [System.Reflection.AssemblyName]::GetAssemblyName($path).Version + ' refs: ' + ((@([System.Reflection.Assembly]::ReflectionOnlyLoadFrom($path).GetReferencedAssemblies()) | ForEach-Object { $_.Name + ' ' + $_.Version }) -join ', ')) }
        else { Note 'error' ($name + '.dll is not in the program folder') }
    }
    # Same objects in a separate domain that uses Vulnerator.exe.config (its binding redirects), as the real program does.
    $setup = New-Object System.AppDomainSetup
    $setup.ApplicationBase = $binPath
    $setup.ConfigurationFile = $config
    $domain = [AppDomain]::CreateDomain('VulneratorProbe', $null, $setup)
    try { [void]$domain.CreateInstanceFromAndUnwrap($exe, 'Vulnerator.ViewModel.ViewModelLocator') ; Note 'warning' 'ViewModelLocator builds with the program configuration' }
    catch {
        $inner = $_.Exception
        while ($null -ne $inner.InnerException) { $inner = $inner.InnerException }
        $file = if ($inner -is [System.IO.FileNotFoundException]) { $inner.FileName } else { '' }
        Note 'error' ('ViewModelLocator: ' + $inner.GetType().FullName + ': ' + $inner.Message + ' FILE=' + $file + ' FUSION=' + $inner.FusionLog)
    }
}
catch {
    $inner = $_.Exception
    while ($null -ne $inner.InnerException) { $inner = $inner.InnerException }
    Note 'error' ('Probe failed: ' + $inner.GetType().FullName + ': ' + $inner.Message)
}
exit 1
