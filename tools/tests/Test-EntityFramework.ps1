# Checks the Entity Framework 6 path the screens use to load data (System.Data.SQLite.EF6 provider), which the
# import tests do not touch. Runs with Vulnerator.exe.config as the configuration file, builds a scratch database,
# imports one synthetic checklist, then runs the same EF queries as the Vulnerability Management screen.
#
# Windows PowerShell 5.1, 64-bit (the build is x64). Pure ASCII; no PowerShell 7 syntax.
# Usage: %SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -File tools\tests\Test-EntityFramework.ps1 -BinDir bin\Release
param([Parameter(Mandatory = $true)][string]$BinDir)
$ErrorActionPreference = 'Stop'

$binPath = (Resolve-Path $BinDir).Path
$fixtures = Join-Path $PSScriptRoot 'fixtures'
$workDir = Join-Path ([System.IO.Path]::GetTempPath()) ('VulneratorEf_' + [Guid]::NewGuid().ToString('N'))
[void][System.IO.Directory]::CreateDirectory($workDir)

function Fail([string]$Message) {
    Write-Host ('FAIL ' + $Message)
    if ($env:GITHUB_ACTIONS -eq 'true') { Write-Host ('::error::' + ($Message -replace "`r?`n", ' ')) }
    exit 1
}

try {
    # Use the application's configuration (EF provider, DbProviderFactories) instead of powershell.exe.config.
    [AppDomain]::CurrentDomain.SetData('APP_CONFIG_FILE', (Join-Path $binPath 'Vulnerator.exe.config'))
    Add-Type -AssemblyName System.Configuration
    $manager = [System.Configuration.ConfigurationManager]
    $manager.GetField('s_initState', [System.Reflection.BindingFlags]'NonPublic,Static').SetValue($null, 0)
    $manager.GetField('s_configSystem', [System.Reflection.BindingFlags]'NonPublic,Static').SetValue($null, $null)
    ($manager.Assembly.GetTypes() | Where-Object { $_.FullName -eq 'System.Configuration.ClientConfigPaths' }).GetField('s_current', [System.Reflection.BindingFlags]'NonPublic,Static').SetValue($null, $null)

    [System.IO.Directory]::SetCurrentDirectory($binPath)
    foreach ($name in 'Vulnerator.exe', 'EntityFramework.dll', 'System.Data.SQLite.dll', 'System.Data.SQLite.EF6.dll', 'log4net.dll') {
        [void][System.Reflection.Assembly]::LoadFrom((Join-Path $binPath $name))
    }

    $probe = @'
using System;
using System.Data.Entity;
using System.Linq;
using Vulnerator.Model.DataAccess;

public static class EntityFrameworkProbe
{
    // The app's binding redirects (Vulnerator.exe.config) do not apply to this host: hand back the loaded copies.
    public static void RedirectToLoadedAssemblies()
    {
        AppDomain.CurrentDomain.AssemblyResolve += (sender, args) =>
        {
            string name = new System.Reflection.AssemblyName(args.Name).Name;
            return AppDomain.CurrentDomain.GetAssemblies().FirstOrDefault(a => a.GetName().Name == name);
        };
    }

    // The queries VulnerabilityViewModel runs when the Vulnerability Management screen opens.
    public static string Run()
    {
        using (DatabaseContext databaseContext = new DatabaseContext())
        {
            int vulnerabilities = databaseContext.Vulnerabilities
                .Include(v => v.CCIs.Select(c => c.NIST_ControlsCCIs))
                .Include(v => v.VulnerabilitySources)
                .AsNoTracking().ToList().Count;
            int mappings = databaseContext.NIST_ControlsCCIs.Include(n => n.CCI).AsNoTracking().ToList().Count;
            int groups = databaseContext.Groups.AsNoTracking().ToList().Count;
            int hardware = databaseContext.Hardwares.AsNoTracking().ToList().Count;
            int withCcis = databaseContext.Vulnerabilities.Include(v => v.CCIs).AsNoTracking().ToList().Count(v => v.CCIs.Count > 0);
            return vulnerabilities + "|" + mappings + "|" + groups + "|" + hardware + "|" + withCcis;
        }
    }

}
'@
    # Add-Type only takes .dll references: compile against a copy; at run time the loaded Vulnerator.exe is used.
    $reference = Join-Path $workDir 'Vulnerator.dll'
    Copy-Item (Join-Path $binPath 'Vulnerator.exe') $reference
    $mvvm = @(Get-ChildItem $binPath -Filter 'GalaSoft.MvvmLight*.dll' | ForEach-Object { $_.FullName })
    foreach ($dll in $mvvm) { [void][System.Reflection.Assembly]::LoadFrom($dll) }
    $references = @($reference, (Join-Path $binPath 'EntityFramework.dll'), 'System.Data.dll', 'System.Core.dll', 'System.ComponentModel.DataAnnotations.dll', 'System.ObjectModel.dll')
    Add-Type -TypeDefinition $probe -ReferencedAssemblies $references
    [EntityFrameworkProbe]::RedirectToLoadedAssemblies()

    $app = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GetName().Name -eq 'Vulnerator' } | Select-Object -First 1
    $settingsType = $app.GetType('Vulnerator.Properties.Settings', $true)
    $defaultSettings = $settingsType.GetProperty('Default', [System.Reflection.BindingFlags]'Public,Static').GetValue($null, $null)
    $indexer = [System.Configuration.ApplicationSettingsBase].GetProperty('Item', [Type[]]@([string]))
    $indexer.SetValue($defaultSettings, (Join-Path $workDir 'ef.sqlite'), [object[]]@('Database'))
    $indexer.SetValue($defaultSettings, 'ef-test', [object[]]@('ActiveUser'))
    [void](New-Object Vulnerator.Model.DataAccess.DatabaseBuilder)

    $ckl = Join-Path $fixtures 'multi-stig.ckl'
    $file = New-Object Vulnerator.Model.Object.File ('multi-stig', 'Checklist', 'Ready', $ckl, 'True')
    $status = (New-Object Vulnerator.Model.BusinessLogic.CklReader).ReadCklFile($file, 'All')
    if ($status -ne 'Processed') { Fail ('fixture checklist did not import (got "' + $status + '")') }

    $scan = New-Object Vulnerator.Model.Object.File ('scan', 'ACAS - Nessus', 'Ready', (Join-Path $fixtures 'scan.nessus'), 'True')
    $scanStatus = (New-Object Vulnerator.Model.BusinessLogic.AcasNessusReader).ReadAcasNessusFile($scan, 'All')
    if ($scanStatus -ne 'Processed') { Fail ('fixture scan did not import (got "' + $scanStatus + '")') }

    $counts = [EntityFrameworkProbe]::Run().Split('|') | ForEach-Object { [int]$_ }
    Write-Host ('EF counts: vulnerabilities ' + $counts[0] + ', CCI mappings ' + $counts[1] + ', groups ' + $counts[2] + ', hardware ' + $counts[3] + ', vulnerabilities with CCIs ' + $counts[4])
    if ($counts[0] -lt 3 -or $counts[1] -lt 3000 -or $counts[2] -lt 1 -or $counts[3] -lt 1 -or $counts[4] -lt 1) { Fail ('unexpected EF counts ' + ($counts -join '|')) }
    # The Configuration Management > Ports, Protocols, Services tab, built as the screen builds it.
    $tab = New-Object Vulnerator.ViewModel.ConfigurationManagement.Tabs.PortsProtocolsServices
    $list = @($tab.PortsProtocolsServicesList)
    $withHosts = @($list | Where-Object { $_.HardwarePortsProtocolsServices.Count -gt 0 -and @($_.HardwarePortsProtocolsServices | Where-Object { $null -eq $_.Hardware }).Count -eq 0 }).Count
    $ports = '' + $list.Count + '|' + $withHosts + '|' + @($list | Where-Object { $_.Port -eq 0 }).Count
    Write-Host ('Ports, Protocols, Services tab: ' + $ports + ' (services | with hosts | port 0)')
    $portCounts = $ports.Split('|')
    if ($portCounts.Count -ne 3 -or [int]$portCounts[0] -lt 2 -or [int]$portCounts[1] -ne [int]$portCounts[0] -or [int]$portCounts[2] -ne 0) { Fail ('Ports, Protocols, Services tab did not load the scan''s services (got ' + $ports + ')') }
    $hardwareTab = New-Object Vulnerator.ViewModel.ConfigurationManagement.Tabs.Hardware
    $softwareTab = New-Object Vulnerator.ViewModel.ConfigurationManagement.Tabs.Software
    $hwCount = @($hardwareTab.Hardwares).Count
    $swHosts = @($softwareTab.Hardwares).Count
    Write-Host ('Hardware tab: ' + $hwCount + ' host(s); Software tab host list: ' + $swHosts + '; software: ' + @($softwareTab.Softwares).Count)
    if ($hwCount -lt 1 -or $swHosts -ne $hwCount) { Fail ('Hardware / Software tabs did not load (hosts ' + $hwCount + ', software tab hosts ' + $swHosts + ')') }
    foreach ($name in 'ClearSelectedHardwareCommand', 'DeleteHardwareCommand', 'ModifyHardwareCommand', 'RemoveGroupFromHardwareCommand', 'RemoveMacAddressFromHardwareCommand', 'AssociatePpsToHardwareCommand') {
        if ($null -eq $hardwareTab.GetType().GetProperty($name)) { Fail ('Hardware tab has no ' + $name) }
    }
    foreach ($name in 'ClearSelectedSoftwareCommand', 'DeleteSoftwareCommand', 'ModifySoftwareCommand', 'AddHardwareToSoftwareCommand', 'RemoveHardwareFromSoftwareCommand') {
        if ($null -eq $softwareTab.GetType().GetProperty($name)) { Fail ('Software tab has no ' + $name) }
    }
    $shown = [Vulnerator.Helper.AppVersion]::Display
    Write-Host ('Version shown on About / Help: ' + $shown)
    if ($env:VULNERATOR_VERSION -and $shown -ne $env:VULNERATOR_VERSION) { Fail ('About / Help show "' + $shown + '", expected "' + $env:VULNERATOR_VERSION + '"') }
    Write-Host 'Entity Framework (System.Data.SQLite.EF6) queries passed.'
    exit 0
}
catch {
    $inner = $_.Exception
    while ($null -ne $inner.InnerException) { $inner = $inner.InnerException }
    Fail ('Entity Framework check failed: ' + $_.Exception.Message + ' / innermost: ' + $inner.GetType().FullName + ': ' + $inner.Message)
}
