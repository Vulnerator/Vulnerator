# Imports every checklist and scan in a folder with Vulnerator's real importers, into a throwaway
# database, and prints one line per file (status, host, findings). Nothing is sent anywhere and your
# Vulnerator database is not touched. Use it to check real files before relying on a build.
#
# Usage (from the unzipped build folder, Windows PowerShell 5.1):
#   powershell -NoProfile -ExecutionPolicy Bypass -File .\Test-RealData.ps1 -InputDir "C:\path\to\files"
#   add -IgApFile "C:\path\to\IGAPsExport.xlsx" (or a .csv with CCI and AP columns) to also try the assessment procedure import
# Supported: *.ckl, *.cklb, *.nessus, ACAS *.csv, SCAP/SCC XCCDF results *.xml, and STIG library *.zip or
# benchmark *.xml (loaded first, so checklists and results find their rules). Pure ASCII; no PowerShell 7 syntax.
param(
    [Parameter(Mandatory = $true)][string]$InputDir,
    [string]$BinDir = '',
    [string]$IgApFile = ''
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

# The build is 64-bit (x64): relaunch in 64-bit Windows PowerShell when started from a 32-bit one.
if ([IntPtr]::Size -eq 4) {
    $ps32 = Join-Path $env:SystemRoot 'Sysnative\WindowsPowerShell\v1.0\powershell.exe'
    $relaunch = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $PSCommandPath, '-InputDir', $InputDir)
    if ($BinDir -ne '') { $relaunch += @('-BinDir', $BinDir) }
    if ($IgApFile -ne '') { $relaunch += @('-IgApFile', $IgApFile) }
    & $ps32 @relaunch
    exit $LASTEXITCODE
}

if ($BinDir -eq '') { $BinDir = $PSScriptRoot }
$binPath = (Resolve-Path $BinDir).Path
$inputPath = (Resolve-Path $InputDir).Path
$workDir = Join-Path ([System.IO.Path]::GetTempPath()) ('VulneratorRealData_' + [Guid]::NewGuid().ToString('N'))
[void][System.IO.Directory]::CreateDirectory($workDir)
$dbPath = Join-Path $workDir 'realdata.sqlite'

Add-Type -AssemblyName System.Configuration
[System.IO.Directory]::SetCurrentDirectory($binPath)
$app = [System.Reflection.Assembly]::LoadFrom((Join-Path $binPath 'Vulnerator.exe'))
[void][System.Reflection.Assembly]::LoadFrom((Join-Path $binPath 'System.Data.SQLite.dll'))
$settingsType = $app.GetType('Vulnerator.Properties.Settings', $true)
$defaultSettings = $settingsType.GetProperty('Default', [System.Reflection.BindingFlags]'Public,Static').GetValue($null, $null)
$indexer = [System.Configuration.ApplicationSettingsBase].GetProperty('Item', [Type[]]@([string]))
$indexer.SetValue($defaultSettings, $dbPath, [object[]]@('Database'))
$indexer.SetValue($defaultSettings, 'real-data-test', [object[]]@('ActiveUser'))
[void](New-Object Vulnerator.Model.DataAccess.DatabaseBuilder)

function Get-Scalar {
    param([string]$Sql)
    $connection = New-Object System.Data.SQLite.SQLiteConnection ('Data Source=' + $dbPath + ';Version=3;DateTimeFormat=Ticks;Foreign Keys=False;')
    $connection.Open()
    try { $command = $connection.CreateCommand(); $command.CommandText = $Sql; return $command.ExecuteScalar() }
    finally { $connection.Dispose() }
}

$all = @(Get-ChildItem -LiteralPath $inputPath -Recurse -File)
# STIG libraries and benchmarks first: they fill the rule library the other files refer to.
$library = @($all | Where-Object { $_.Extension -ieq '.zip' })
$files = @($all | Where-Object { @('.ckl', '.cklb', '.nessus', '.csv', '.xml') -contains $_.Extension.ToLowerInvariant() })
foreach ($item in $library) {
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $importer = New-Object Vulnerator.Model.BusinessLogic.StigLibraryImporter
    $summary = $importer.Import($item.FullName)
    $watch.Stop()
    Write-Host ('{0,-34} {1,6:N1}s  {2}' -f 'STIG library', $watch.Elapsed.TotalSeconds, ($item.Name + ': ' + $summary))
}
Write-Host ('Importing ' + $files.Count + ' file(s) from ' + $inputPath + ' into a scratch database')
Write-Host ''
$failed = 0
foreach ($item in $files) {
    $before = [int](Get-Scalar 'SELECT COUNT(*) FROM UniqueFindings')
    $watch = [System.Diagnostics.Stopwatch]::StartNew()
    $extension = $item.Extension.ToLowerInvariant()
    if ($extension -eq '.nessus') {
        $file = New-Object Vulnerator.Model.Object.File ($item.BaseName, 'ACAS - Nessus', 'Ready', $item.FullName, 'True')
        $status = (New-Object Vulnerator.Model.BusinessLogic.AcasNessusReader).ReadAcasNessusFile($file, 'All')
    }
    elseif ($extension -eq '.csv') {
        $file = New-Object Vulnerator.Model.Object.File ($item.BaseName, 'ACAS - CSV', 'Ready', $item.FullName, 'True')
        $status = (New-Object Vulnerator.Model.BusinessLogic.AcasCsvReader).ReadAcasCsvFile($file, 'All')
    }
    elseif ($extension -eq '.xml') {
        $file = New-Object Vulnerator.Model.Object.File ($item.BaseName, 'SCAP Benchmark', 'Ready', $item.FullName, 'True')
        $status = (New-Object Vulnerator.Model.BusinessLogic.XccdfReader).ReadXccdfFile($file, 'All')
        if ($status -eq 'Failed; No XCCDF Results') {
            # A benchmark without results: load it into the library instead.
            $importer = New-Object Vulnerator.Model.BusinessLogic.StigLibraryImporter
            $status = 'STIG benchmark: ' + $importer.Import($item.FullName)
            if ($importer.Failed -eq 0) { $status = 'Processed; ' + $status }
        }
    }
    else {
        $file = New-Object Vulnerator.Model.Object.File ($item.BaseName, 'Checklist', 'Ready', $item.FullName, 'True')
        if ($extension -eq '.cklb') { $status = (New-Object Vulnerator.Model.BusinessLogic.CklbReader).ReadCklbFile($file, 'All') }
        else { $status = (New-Object Vulnerator.Model.BusinessLogic.CklReader).ReadCklFile($file, 'All') }
    }
    $watch.Stop()
    $added = [int](Get-Scalar 'SELECT COUNT(*) FROM UniqueFindings') - $before
    if (-not ([string]$status).StartsWith('Processed')) { $failed++ }
    Write-Host ('{0,-34} {1,7} findings {2,6:N1}s  {3}' -f $status, $added, $watch.Elapsed.TotalSeconds, $item.Name)
}

if ($IgApFile -ne '') {
    $igapPath = (Resolve-Path $IgApFile).Path
    Write-Host ''
    Write-Host ('Assessment procedures: ' + [Vulnerator.Model.BusinessLogic.EmassAssessmentProcedureImporter]::Import($igapPath))
}

Write-Host ''
Write-Host ('Hosts: ' + (Get-Scalar 'SELECT COUNT(*) FROM Hardware') + '; findings: ' + (Get-Scalar 'SELECT COUNT(*) FROM UniqueFindings') +
    '; open: ' + (Get-Scalar "SELECT COUNT(*) FROM UniqueFindings WHERE Status = 'Ongoing'") + '; software: ' + (Get-Scalar 'SELECT COUNT(*) FROM Software'))
Write-Host ('Scratch database (delete when done): ' + $dbPath)
Write-Host ('Failures are explained in the Vulnerator log: ' + [string]$indexer.GetValue($defaultSettings, [object[]]@('LogPath')))
if ($failed -gt 0) { exit 1 }
exit 0
