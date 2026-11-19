# Checks the add-on mechanism with throw-away add-ons compiled here (none of them ship): a working add-on, one in a
# subfolder with its own dependency, and add-ons that must be skipped without stopping Vulnerator (throws while
# starting, needs a newer interface, needs a newer Vulnerator, not an add-on, wrong entry type, not a .NET file,
# duplicate id). Then checks the read-only data the add-ons get, the data-changed event, the menu pages and the
# Settings > Integrations section (no license section). Last, loads the free Dashboards add-on that ships in the release (Add-ons\Dashboards)
# against the test database: it must load, build its dashboards from the real data and have no license handling.
#
# Windows PowerShell 5.1, 64-bit (the build is x64), STA. Pure ASCII; no PowerShell 7 syntax.
# Usage: %SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -File tools\tests\Test-AddOns.ps1 -BinDir bin\Release
param([Parameter(Mandatory = $true)][string]$BinDir)
$ErrorActionPreference = 'Stop'

$binPath = (Resolve-Path $BinDir).Path
$fixtures = Join-Path $PSScriptRoot 'fixtures'
$workDir = Join-Path ([System.IO.Path]::GetTempPath()) ('VulneratorAddOns_' + [Guid]::NewGuid().ToString('N'))
$addOnDir = Join-Path $workDir 'Add-ons'
$subDir = Join-Path $addOnDir 'nested'
[void][System.IO.Directory]::CreateDirectory($subDir)
$failures = New-Object System.Collections.Generic.List[string]

function Fail([string]$Message) {
    Write-Host ('FAIL ' + $Message)
    if ($env:GITHUB_ACTIONS -eq 'true') { Write-Host ('::error::' + ($Message -replace "`r?`n", ' ')) }
    exit 1
}
function Check([bool]$Condition, [string]$Message) {
    if ($Condition) { Write-Host ('ok   ' + $Message) }
    else { Write-Host ('FAIL ' + $Message); $failures.Add($Message) }
}

try {
    if ([System.Threading.Thread]::CurrentThread.GetApartmentState() -ne 'STA') { Fail 'the test needs an STA thread (Windows PowerShell 5.1 default)' }
    $contract = Join-Path $binPath 'Vulnerator.AddOns.dll'
    if (-not (Test-Path $contract)) { Fail 'Vulnerator.AddOns.dll is not in the program folder' }
    $shippedFolder = Join-Path $binPath 'Add-ons'
    Check (Test-Path (Join-Path $shippedFolder 'README.txt')) 'the release has an Add-ons folder with README.txt'
    $shippedAddOns = @(Get-ChildItem $binPath -Recurse -Filter '*.AddOn.dll' | ForEach-Object { $_.FullName.Substring($binPath.Length + 1) })
    Check ($shippedAddOns.Count -eq 1 -and $shippedAddOns[0] -eq 'Add-ons\Dashboards\Vulnerator.Dashboards.AddOn.dll') ('the release ships one add-on, Dashboards (' + ($shippedAddOns -join ', ') + ')')
    Check ((Test-Path (Join-Path $shippedFolder 'Dashboards\README.txt')) -and -not (Test-Path (Join-Path $shippedFolder 'Dashboards\LICENSE.txt'))) 'Dashboards ships with its README.txt (MIT: the release LICENSE.txt covers it)'

    # Same set-up as Test-EntityFramework.ps1: the application's configuration, then the program's assemblies.
    [AppDomain]::CurrentDomain.SetData('APP_CONFIG_FILE', (Join-Path $binPath 'Vulnerator.exe.config'))
    Add-Type -AssemblyName System.Configuration
    $manager = [System.Configuration.ConfigurationManager]
    $manager.GetField('s_initState', [System.Reflection.BindingFlags]'NonPublic,Static').SetValue($null, 0)
    $manager.GetField('s_configSystem', [System.Reflection.BindingFlags]'NonPublic,Static').SetValue($null, $null)
    ($manager.Assembly.GetTypes() | Where-Object { $_.FullName -eq 'System.Configuration.ClientConfigPaths' }).GetField('s_current', [System.Reflection.BindingFlags]'NonPublic,Static').SetValue($null, $null)
    [System.IO.Directory]::SetCurrentDirectory($binPath)
    Add-Type -AssemblyName PresentationFramework, PresentationCore, WindowsBase, System.Xaml
    foreach ($name in 'Vulnerator.exe', 'Vulnerator.AddOns.dll', 'EntityFramework.dll', 'System.Data.SQLite.dll', 'System.Data.SQLite.EF6.dll', 'log4net.dll',
                      'ControlzEx.dll', 'Microsoft.Xaml.Behaviors.dll', 'MahApps.Metro.dll', 'MahApps.Metro.IconPacks.Core.dll', 'MahApps.Metro.IconPacks.Material.dll') {
        $path = Join-Path $binPath $name
        if (Test-Path $path) { [void][System.Reflection.Assembly]::LoadFrom($path) }
    }
    foreach ($dll in @(Get-ChildItem $binPath -Filter 'GalaSoft.MvvmLight*.dll')) { [void][System.Reflection.Assembly]::LoadFrom($dll.FullName) }
    # The app's binding redirects do not apply to this host: hand back the loaded copies.
    $redirect = @'
using System;
using System.Linq;
public static class AddOnTestRedirect
{
    public static void Install()
    {
        AppDomain.CurrentDomain.AssemblyResolve += (sender, args) =>
        {
            string name = new System.Reflection.AssemblyName(args.Name).Name;
            return AppDomain.CurrentDomain.GetAssemblies().FirstOrDefault(a => a.GetName().Name == name);
        };
    }
}
'@
    Add-Type -TypeDefinition $redirect -ReferencedAssemblies 'System.Core.dll'
    [AddOnTestRedirect]::Install()

    # A scratch database with one checklist and one scan.
    $app = [AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GetName().Name -eq 'Vulnerator' } | Select-Object -First 1
    $settingsType = $app.GetType('Vulnerator.Properties.Settings', $true)
    $defaultSettings = $settingsType.GetProperty('Default', [System.Reflection.BindingFlags]'Public,Static').GetValue($null, $null)
    $indexer = [System.Configuration.ApplicationSettingsBase].GetProperty('Item', [Type[]]@([string]))
    $database = Join-Path $workDir 'addons.sqlite'
    $indexer.SetValue($defaultSettings, $database, [object[]]@('Database'))
    $indexer.SetValue($defaultSettings, 'addon-test', [object[]]@('ActiveUser'))
    $indexer.SetValue($defaultSettings, 'UNCLASSIFIED', [object[]]@('EmassClassificationMarking'))
    [void](New-Object Vulnerator.Model.DataAccess.DatabaseBuilder)
    $file = New-Object Vulnerator.Model.Object.File ('multi-stig', 'Checklist', 'Ready', (Join-Path $fixtures 'multi-stig.ckl'), 'True')
    if ((New-Object Vulnerator.Model.BusinessLogic.CklReader).ReadCklFile($file, 'All') -ne 'Processed') { Fail 'fixture checklist did not import' }
    $scan = New-Object Vulnerator.Model.Object.File ('scan', 'ACAS - Nessus', 'Ready', (Join-Path $fixtures 'scan.nessus'), 'True')
    if ((New-Object Vulnerator.Model.BusinessLogic.AcasNessusReader).ReadAcasNessusFile($scan, 'All') -ne 'Processed') { Fail 'fixture scan did not import' }

    # Throw-away add-ons.
    $wpf = @([System.Windows.Controls.TextBlock].Assembly.Location, [System.Windows.UIElement].Assembly.Location,
             [System.Windows.DependencyObject].Assembly.Location, [System.Xaml.XamlReader].Assembly.Location)
    function Build([string]$Path, [string]$Source, [string[]]$Extra = @()) {
        $references = @($contract, 'System.dll', 'System.Core.dll') + $wpf + $Extra
        Add-Type -TypeDefinition $Source -OutputAssembly $Path -OutputType Library -ReferencedAssemblies $references
    }
    $template = @'
using System;
using Vulnerator.AddOns;
__ATTRIBUTE__
namespace __NS__
{
    public class Entry : IAddOn
    {
        public static IAddOnHost Host;
        public static int Changes;
        public string Id { get { return "__ID__"; } }
        public string Name { get { return "__NAME__"; } }
        public string Version { get { return "1.0.0"; } }
        public string Description { get { return "Test add-on (not shipped)."; } }
        public void Initialize(IAddOnHost host)
        {
            Host = host;
            host.DataChanged += (sender, e) => Changes++;
            __BODY__
        }
    }
    public class NotAnAddOn { }
}
'@
    function AddOnSource([string]$Ns, [string]$Id, [string]$Name, [string]$Body, [string]$Attribute = '') {
        if ($Attribute -eq '') { $Attribute = '[assembly: VulneratorAddOn(typeof(' + $Ns + '.Entry))]' }
        return $template.Replace('__ATTRIBUTE__', $Attribute).Replace('__NS__', $Ns).Replace('__ID__', $Id).Replace('__NAME__', $Name).Replace('__BODY__', $Body)
    }
    $pageBody = 'host.AddPage("Sample Dashboard", "ChartBar", () => new System.Windows.Controls.TextBlock { Text = "sample page" }); host.AddSettingsSection("Sample settings", () => new System.Windows.Controls.TextBlock { Text = "sample settings" }); host.Log.Info("started");'
    $licensing = 'public static int LicenseChanges; public string LicenseStatus { get { return Host.Licenses.Count + " license(s)"; } } public string DescribeLicense(string text) { return text.StartsWith("SAMPLE-") ? "Sample: valid" : null; }'
    $sampleSource = (AddOnSource 'TestSample' 'test.sample' 'Sample' ($pageBody + ' host.LicensesChanged += (sender, e) => LicenseChanges++;')).Replace('public class Entry : IAddOn', 'public class Entry : IAddOn, IAddOnLicensing').Replace('public static int Changes;', 'public static int Changes; ' + $licensing)
    Build (Join-Path $addOnDir 'Sample.AddOn.dll') $sampleSource
    Build (Join-Path $addOnDir 'Legacy.AddOn.dll') (AddOnSource 'TestLegacy' 'test.legacy' 'Legacy' '' '[assembly: VulneratorAddOn(typeof(TestLegacy.Entry), ApiVersion = 1)]')

    $helper = Join-Path $subDir 'TestHelperLib.dll'
    Add-Type -TypeDefinition 'namespace TestHelperLib { public static class Util { public static string Value() { return "helper ok"; } } }' -OutputAssembly $helper -OutputType Library
    $nestedBody = 'Value = TestHelperLib.Util.Value(); host.AddPage("Nested Page", "NoSuchIconName", () => new System.Windows.Controls.TextBlock { Text = Value });'
    Build (Join-Path $subDir 'Nested.AddOn.dll') ((AddOnSource 'TestNested' 'test.nested' 'Nested' $nestedBody).Replace('public static int Changes;', 'public static int Changes; public static string Value;')) @($helper)

    Build (Join-Path $addOnDir 'Broken.AddOn.dll') (AddOnSource 'TestBroken' 'test.broken' 'Broken' 'host.AddPage("Broken Page", "Bug", () => null); throw new InvalidOperationException("boom");')
    Build (Join-Path $addOnDir 'Future.AddOn.dll') (AddOnSource 'TestFuture' 'test.future' 'Future' '' '[assembly: VulneratorAddOn(typeof(TestFuture.Entry), ApiVersion = 99)]')
    Build (Join-Path $addOnDir 'NeedsCore.AddOn.dll') (AddOnSource 'TestNeedsCore' 'test.needscore' 'NeedsCore' '' '[assembly: VulneratorAddOn(typeof(TestNeedsCore.Entry), MinimumCoreVersion = "99.0.0")]')
    Build (Join-Path $addOnDir 'Plain.AddOn.dll') (AddOnSource 'TestPlain' 'test.plain' 'Plain' '' '// no attribute')
    Build (Join-Path $addOnDir 'WrongType.AddOn.dll') (AddOnSource 'TestWrongType' 'test.wrongtype' 'WrongType' '' '[assembly: VulneratorAddOn(typeof(TestWrongType.NotAnAddOn))]')
    Build (Join-Path $addOnDir 'Zz.Duplicate.AddOn.dll') (AddOnSource 'TestDuplicate' 'test.sample' 'Duplicate' '')
    [System.IO.File]::WriteAllBytes((Join-Path $addOnDir 'Garbage.AddOn.dll'), [byte[]](1..200))
    # A dependency that is not an add-on and must not be loaded as one.
    Copy-Item $helper (Join-Path $addOnDir 'NotAnAddOnLibrary.dll')

    # Load them.
    $loaded = @([Vulnerator.Model.AddOns.AddOnManager]::LoadFrom($addOnDir))
    foreach ($entry in $loaded) { Write-Host ('     ' + [System.IO.Path]::GetFileName($entry.File) + ': ' + $entry.Summary) }
    $byFile = @{}
    foreach ($entry in $loaded) { $byFile[[System.IO.Path]::GetFileName($entry.File)] = $entry }
    Check ($loaded.Count -eq 10) ('10 add-on files found (got ' + $loaded.Count + ')')
    $expected = [ordered]@{
        'Sample.AddOn.dll' = 'Loaded'; 'Nested.AddOn.dll' = 'Loaded'; 'Legacy.AddOn.dll' = 'Loaded'; 'Broken.AddOn.dll' = 'Failed'; 'Future.AddOn.dll' = 'Skipped';
        'NeedsCore.AddOn.dll' = 'Skipped'; 'Plain.AddOn.dll' = 'Skipped'; 'WrongType.AddOn.dll' = 'Failed'; 'Zz.Duplicate.AddOn.dll' = 'Skipped'; 'Garbage.AddOn.dll' = 'Skipped'
    }
    foreach ($key in $expected.Keys) {
        $state = if ($byFile.ContainsKey($key)) { '' + $byFile[$key].State } else { 'missing' }
        Check ($state -eq $expected[$key]) ($key + ' is ' + $expected[$key] + ' (got ' + $state + ')')
    }
    Check ($byFile['Future.AddOn.dll'].Message -like '*newer Vulnerator*') 'Future: the message says a newer Vulnerator is needed'
    Check ($byFile['Broken.AddOn.dll'].Message -like '*boom*') 'Broken: the message carries the error'
    Check ($byFile['Broken.AddOn.dll'].Pages.Count -eq 0) 'Broken: the page it registered before failing is dropped'
    Check ($byFile['Zz.Duplicate.AddOn.dll'].Message -like '*already loaded*') 'Duplicate id: skipped with a clear message'
    Check ([TestNested.Entry]::Value -eq 'helper ok') 'Nested: its dependency in its own folder was found'

    # Read-only data.
    $hostApi = [TestSample.Entry]::Host
    Check ($hostApi.ApiVersion -eq [Vulnerator.AddOns.AddOnApi]::Version) 'host reports the interface version'
    Check (-not [string]::IsNullOrWhiteSpace($hostApi.CoreVersion)) ('host reports the core version (' + $hostApi.CoreVersion + ')')
    Check ($hostApi.ClassificationMarking -eq 'UNCLASSIFIED') 'host passes the classification marking'
    $dataFolder = $hostApi.DataFolder
    Check ((Test-Path $dataFolder) -and $dataFolder.StartsWith($workDir, [StringComparison]::OrdinalIgnoreCase) -and $dataFolder -like '*Add-on data*test.sample') ('data folder next to the database (' + $dataFolder + ')')

    $findings = @($hostApi.Data.GetFindings())
    $hardware = @($hostApi.Data.GetHardware())
    $direct = New-Object System.Data.SQLite.SQLiteConnection ([Vulnerator.Model.DataAccess.DatabaseBuilder]::ConnectionStringFor($database))
    $direct.Open()
    $command = $direct.CreateCommand()
    $command.CommandText = 'SELECT COUNT(*) FROM UniqueFindings'
    $findingRows = [int]$command.ExecuteScalar()
    $command.CommandText = 'SELECT COUNT(*) FROM Hardware'
    $hardwareRows = [int]$command.ExecuteScalar()
    $direct.Close()
    Write-Host ('     findings ' + $findings.Count + ' (database ' + $findingRows + '), hardware ' + $hardware.Count + ' (database ' + $hardwareRows + ')')
    Check ($findings.Count -gt 0 -and $findings.Count -eq $findingRows) 'GetFindings returns every finding, unfiltered'
    Check ($hardware.Count -gt 0 -and $hardware.Count -eq $hardwareRows) 'GetHardware returns every hardware asset'
    $severities = (@($findings | ForEach-Object { $_.Severity } | Sort-Object -Unique) -join ', ')
    Check (@($findings | Where-Object { $_.FindingType -eq 'CKL' -and $_.Severity -notin 'I', 'II', 'III' }).Count -eq 0) ('checklist findings have CAT I-III severities (all values: ' + $severities + ')')
    Check (@($findings | Where-Object { $_.Status -eq 'Ongoing' -or $_.Status -eq 'Completed' }).Count -eq 0) 'statuses use checklist wording (Open, Not a Finding, ...)'
    Check (@($findings | Where-Object { $_.FindingType -eq 'CKL' }).Count -gt 0 -and @($findings | Where-Object { $_.FindingType -eq 'ACAS' }).Count -gt 0) 'findings from both the checklist and the scan'
    Check (@($findings | Where-Object { $_.NistControls.Count -gt 0 }).Count -gt 0) 'findings carry NIST controls'
    $readOnlyRecord = $false
    try { $findings[0].Title = 'changed' } catch { $readOnlyRecord = $true }
    Check ($readOnlyRecord -and $findings[0].Title -ne 'changed') 'finding records cannot be changed'

    # Interface version 3: dashboard data. A scan with a Critical finding and IAVB/IAVT references, and a checklist
    # from an older release of a STIG already loaded (its results attach to the newer release; the submission is kept).
    $dashScan = New-Object Vulnerator.Model.Object.File ('dashboard-scan', 'ACAS - Nessus', 'Ready', (Join-Path $fixtures 'dashboard-scan.nessus'), 'True')
    if ((New-Object Vulnerator.Model.BusinessLogic.AcasNessusReader).ReadAcasNessusFile($dashScan, 'All') -ne 'Processed') { Fail 'dashboard fixture scan did not import' }
    $olderCkl = New-Object Vulnerator.Model.Object.File ('older-release', 'Checklist', 'Ready', (Join-Path $fixtures 'older-release.ckl'), 'True')
    if ((New-Object Vulnerator.Model.BusinessLogic.CklReader).ReadCklFile($olderCkl, 'All') -ne 'Processed') { Fail 'older-release checklist did not import' }
    $v3 = @($hostApi.Data.GetFindings())
    $hardwareNow = @($hostApi.Data.GetHardware())
    $critical = @($v3 | Where-Object { $_.Title -eq 'Synthetic Critical Remote Vulnerability' })
    $c = if ($critical.Count -gt 0) { $critical[0] } else { $null }
    $cInfo = if ($null -eq $c) { 'missing' } else { 'level=' + $c.SeverityLevel + ' cat=' + $c.Severity + ' risk=' + $c.RiskFactor + ' second=' + $c.SecondarySeverity + ' refs=' + ($c.References -join ' ') + ' hw=' + $c.HardwareId }
    Check ($critical.Count -eq 1 -and $c.SeverityLevel -eq 'Very High' -and $c.Severity -eq 'I' -and $c.RiskFactor -eq 'Critical') ('Nessus Critical: CAT I and severity level Very High (' + $cInfo + ')')
    Check ($null -ne $c -and $c.SecondarySeverity -eq 'I') ('Nessus stig_severity is passed on (' + $cInfo + ')')
    Check ($null -ne $c -and ($c.References -contains 'IAVB:2026-B-0002') -and ($c.References -contains 'IAVT:2026-T-0003') -and ($c.References -contains 'CVE:CVE-2026-0001')) ('IAVB, IAVT and CVE references (' + $cInfo + ')')
    $dashHost = @($hardwareNow | Where-Object { $null -ne $c -and $_.Id -eq $c.HardwareId })
    Check ($dashHost.Count -eq 1 -and $null -ne $c.FirstDiscovered) ('a finding names its hardware record and first-seen date (' + $cInfo + ')')
    $high = @($v3 | Where-Object { $_.Title -eq 'Synthetic OpenSSH Vulnerability' })
    Check ($high.Count -ge 1 -and $high[0].SeverityLevel -eq 'High' -and ($high[0].References -contains 'IAVA:2026-A-0001')) ('Nessus High: level High with its IAVA (' + $(if ($high.Count) { $high[0].SeverityLevel + ' ' + ($high[0].References -join ' ') } else { 'missing' }) + ')')
    $low = @($v3 | Where-Object { $_.Title -eq 'Synthetic Low Finding' })
    Check ($low.Count -eq 1 -and $low[0].SeverityLevel -eq 'Low') 'Nessus Low: level Low'
    $levels = (@($v3 | ForEach-Object { $_.SeverityLevel } | Sort-Object -Unique) -join ', ')
    Check (@($v3 | Where-Object { $_.FindingType -eq 'CKL' -and $_.SeverityLevel -notin 'High', 'Moderate', 'Low' }).Count -eq 0) ('checklist findings: levels High, Moderate or Low (all levels: ' + $levels + ')')
    Check (@($v3 | Where-Object { [string]::IsNullOrEmpty($_.SeverityLevel) }).Count -eq 0) ('every finding has a severity level (' + $levels + ')')

    $subs = @($hostApi.Data.GetStigSubmissions())
    $subInfo = (@($subs | ForEach-Object { $_.FindingType + ' ' + $_.StigName + ' ' + $_.SubmittedVersion + '/' + $_.LatestVersion + ' outdated=' + $_.IsOutdated + ' host=' + $_.HostName + ' hw=' + $_.HardwareId + ' date=' + $(if ($_.BenchmarkDate) { $_.BenchmarkDate.ToString('yyyy-MM-dd') } else { '-' }) + ' file=' + $_.SourceFile }) -join ' | ')
    Write-Host ('     submissions: ' + $subInfo)
    $oldSub = @($subs | Where-Object { $_.StigName -like '*Server*' -and $_.SubmittedVersion -eq 'V2R4' })
    Check ($oldSub.Count -eq 1 -and $oldSub[0].IsOutdated -and $oldSub[0].LatestVersion -eq 'V2R5' -and $oldSub[0].BenchmarkDate -eq [datetime]'2025-10-15') ('older-release checklist: submitted V2R4, outdated, latest V2R5 (' + $subInfo + ')')
    $newSub = @($subs | Where-Object { $_.StigName -like '*Server*' -and $_.SubmittedVersion -eq 'V2R5' })
    Check ($newSub.Count -eq 1 -and -not $newSub[0].IsOutdated -and $newSub[0].BenchmarkDate -eq [datetime]'2026-01-04') ('current checklist: V2R5, not outdated (' + $subInfo + ')')
    Check (@($subs | Where-Object { $_.StigName -like '*Browser*' -and $_.SubmittedVersion -eq 'V1R3' -and -not $_.IsOutdated }).Count -eq 1) ('second STIG in the same checklist is listed (' + $subInfo + ')')
    Check (@($subs | Where-Object { $_.HostName -eq 'TESTHOST01' -and $null -ne $_.HardwareId -and $_.FindingType -eq 'CKL' }).Count -eq $subs.Count -and $subs.Count -eq 3) ('submissions name the host and its hardware record (' + $subInfo + ')')

    $poam = @($hostApi.Data.GetPoamItems())
    $poamInfo = (@($poam | Select-Object -First 4 | ForEach-Object { $_.Status + ' ' + $_.RawSeverity + ' id=' + $(if ($_.DateIdentified) { $_.DateIdentified.ToString('yyyy-MM-dd') } else { '-' }) + ' due=' + $(if ($_.ScheduledCompletion) { $_.ScheduledCompletion.ToString('yyyy-MM-dd') } else { '-' }) + ' devices=' + ($_.DevicesAffected -join ',') + ' milestones=' + $_.Milestones.Count }) -join ' | ')
    Write-Host ('     POA&M items ' + $poam.Count + ': ' + $poamInfo)
    Check ($poam.Count -gt 0) ('POA&M items are returned (' + $poam.Count + ')')
    Check (@($poam | Where-Object { $_.Status -notin 'Ongoing', 'Completed', 'Risk Accepted' }).Count -eq 0) ('POA&M statuses use eMASS wording (' + $poamInfo + ')')
    Check (@($poam | Where-Object { $null -eq $_.DateIdentified -or $_.DevicesAffected.Count -eq 0 -or $_.Milestones.Count -eq 0 }).Count -eq 0) ('POA&M items have a date identified, devices and a milestone (' + $poamInfo + ')')
    Check (@($poam | Where-Object { $_.RawSeverity -notin 'Very High', 'High', 'Moderate', 'Low', 'Very Low' }).Count -eq 0) ('POA&M raw severities use eMASS levels (' + $poamInfo + ')')
    $libraryError = ''
    $library = 'not called'
    try { $library = $hostApi.Data.GetLastStigLibraryImport() } catch { $libraryError = $_.Exception.Message }
    Check ($libraryError -eq '' -and $null -eq $library) ('no STIG library imported: GetLastStigLibraryImport returns null (' + $libraryError + ')')

    # The connection add-ons read through refuses writes.
    $ro = New-Object System.Data.SQLite.SQLiteConnection ([Vulnerator.Model.DataAccess.DatabaseBuilder]::ConnectionStringFor($database) + 'Read Only=True;')
    $ro.Open()
    $write = $ro.CreateCommand()
    $write.CommandText = "UPDATE UniqueFindings SET Comments = 'changed'"
    $refused = $false
    try { [void]$write.ExecuteNonQuery() } catch { $refused = $true }
    $ro.Close()
    Check $refused 'the read-only connection refuses writes'

    $lateRefused = $false
    try { $hostApi.AddPage('Late', 'Bug', [Func[object]] { 'x' }) } catch { $lateRefused = $true }
    Check $lateRefused 'pages cannot be added after Initialize'

    [Vulnerator.Model.AddOns.AddOnManager]::NotifyDataChanged()
    Check ([TestSample.Entry]::Changes -eq 1 -and [TestBroken.Entry]::Changes -eq 0) 'DataChanged reaches loaded add-ons only'

    # Menu and Settings.
    $pageList = @([Vulnerator.Model.AddOns.AddOnManager]::Pages)
    $pageInfo = 'pages ' + $pageList.Count + ' [' + (@($pageList | ForEach-Object { $_.Title }) -join ', ') + ']; per add-on: ' + (@($loaded | ForEach-Object { $_.Name + '=' + $_.State + '/' + $_.Pages.Count }) -join ', ')
    Write-Host ('     ' + $pageInfo)
    Check ($pageList.Count -eq 2) ('two add-on pages registered (' + $pageInfo + ')')
    $menu = New-Object MahApps.Metro.Controls.HamburgerMenu
    $items = New-Object MahApps.Metro.Controls.HamburgerMenuItemCollection
    foreach ($label in 'Vulnerability Management', 'Reporting', 'News') {
        $item = New-Object MahApps.Metro.Controls.HamburgerMenuIconItem
        $item.Label = $label
        [void]$items.Add($item)
    }
    $menu.ItemsSource = $items
    [Vulnerator.View.UI.AddOnUi]::AddPages($menu)
    $labels = @($items | ForEach-Object { $_.Label }) -join ' | '
    Write-Host ('     menu: ' + $labels)
    Check ($labels -eq 'Vulnerability Management | Reporting | Nested Page | Sample Dashboard | News') ('add-on pages go before News in file order; the broken one is left out (menu: ' + $labels + ')')
    Check ($items[2].Icon.Kind -eq [MahApps.Metro.IconPacks.PackIconMaterialKind]::PuzzleOutline -and $items[3].Icon.Kind -eq [MahApps.Metro.IconPacks.PackIconMaterialKind]::ChartBar) 'icons: the named one, else the default'
    Check ($items[2].Tag -is [Vulnerator.View.UI.AddOnViewHost]) 'pages are created on first display'
    $view = $null
    $viewError = ''
    try { $view = @($pageList | Where-Object { $_.Title -eq 'Sample Dashboard' })[0].CreateView.Invoke() } catch { $viewError = $_.Exception.Message }
    Check ($view -is [System.Windows.Controls.TextBlock] -and $view.Text -eq 'sample page') ('the add-on creates its page (' + $(if ($null -eq $view) { 'null ' + $viewError } else { $view.GetType().FullName }) + ')')

    $panel = New-Object System.Windows.Controls.StackPanel
    [Vulnerator.View.UI.AddOnUi]::FillIntegrations($panel)
    $boxes = @($panel.Children | Where-Object { $_ -is [System.Windows.Controls.GroupBox] })
    Check ($panel.Children.Count -eq 12 -and $boxes.Count -eq 1 -and $boxes[0].Header -eq 'Sample settings') ('Settings > Integrations lists every add-on file and the settings section, with no Licenses box (' + $panel.Children.Count + ' items)')

    # No licenses since 7.5.0: add-ons built for interface 2-3 still load; Licenses is empty and nothing is shown.
    function Texts($element) {
        $found = New-Object System.Collections.Generic.List[string]
        if ($element -is [System.Windows.Controls.TextBlock]) { $found.Add($element.Text) }
        elseif ($element -is [System.Windows.Controls.Panel]) { foreach ($child in $element.Children) { foreach ($t in (Texts $child)) { $found.Add($t) } } }
        elseif ($element -is [System.Windows.Controls.ContentControl]) { foreach ($t in (Texts $element.Content)) { $found.Add($t) } }
        return ,$found
    }
    Check (@($hostApi.Licenses).Count -eq 0) 'add-ons get no licenses (Vulnerator 2.0 uses none)'
    Check ($null -eq [Vulnerator.Model.AddOns.AddOnManager].Assembly.GetType('Vulnerator.Model.AddOns.AddOnLicenses')) 'no license store in Vulnerator'
    [Vulnerator.View.UI.AddOnUi]::FillIntegrations($panel)
    $all = (Texts $panel) -join ' || '
    Check ($all -notlike '*License:*' -and $all -notlike '*Add license*') ('Settings > Integrations shows no license section (' + $all.Length + ' chars)')

    # The bundled Dashboards add-on (MIT, built from AddOns/Dashboards), loaded from the release's own Add-ons folder against the test database.
    $shipped = @([Vulnerator.Model.AddOns.AddOnManager]::LoadFrom($shippedFolder))
    $dash = @($shipped | Where-Object { $_.Id -eq 'dashboards' })
    $dashInfo = (@($shipped | ForEach-Object { [System.IO.Path]::GetFileName($_.File) + ': ' + $_.Summary }) -join ' | ')
    Write-Host ('     shipped: ' + $dashInfo)
    Check ($shipped.Count -eq 1 -and $dash.Count -eq 1 -and $dash[0].State -eq 'Loaded') ('the bundled Dashboards add-on loads (' + $dashInfo + ')')
    if ($dash.Count -eq 1 -and $dash[0].State -eq 'Loaded') {
        Check ($dash[0].Version -like '1.*') ('Dashboards version 1.x (' + $dash[0].Version + ')')
        $instance = [Vulnerator.Model.AddOns.LoadedAddOn].GetProperty('Instance', [System.Reflection.BindingFlags]'NonPublic,Instance').GetValue($dash[0], $null)
        Check (-not ($instance -is [Vulnerator.AddOns.IAddOnLicensing])) 'Dashboards has no license handling'
        $dashPages = @($dash[0].Pages)
        Check ($dashPages.Count -eq 1 -and $dashPages[0].Title -eq 'Dashboards') 'Dashboards adds its menu page'
        $dashView = $null
        $dashViewError = ''
        try { $dashView = $dashPages[0].CreateView.Invoke() } catch { $dashViewError = $_.Exception.Message }
        Check ($null -ne $dashView -and $dashView.GetType().FullName -eq 'Vulnerator.Dashboards.DashboardView') ('the Dashboards page opens without a license (' + $(if ($null -eq $dashView) { 'null ' + $dashViewError } else { $dashView.GetType().FullName }) + ')')
        # What the page loads: every view's data, from the real database through the add-on contract.
        $model = $null
        $modelError = ''
        try { $model = $instance.GetType().GetMethod('Load', [System.Reflection.BindingFlags]'NonPublic,Instance').Invoke($instance, $null) }
        catch { $inner = $_.Exception; while ($null -ne $inner.InnerException) { $inner = $inner.InnerException }; $modelError = $inner.GetType().FullName + ': ' + $inner.Message }
        $dbFindings = @($hostApi.Data.GetFindings()).Count
        $iavms = if ($null -ne $model) { (@($model.Iavms | ForEach-Object { $_.Iavm }) -join ', ') } else { '' }
        $modelInfo = if ($null -eq $model) { 'error ' + $modelError } else { 'findings ' + $model.FindingCount + ' of ' + $dbFindings + ', families ' + $model.Compliance.Count + ', coverage ' + $model.Coverage.Count + ', IAVMs ' + $iavms + ', marking ' + $model.Marking }
        Write-Host ('     dashboards: ' + $modelInfo)
        Check ($null -ne $model -and $model.FindingCount -eq $dbFindings -and $dbFindings -gt 0) ('Dashboards reads every finding from the database (' + $modelInfo + ')')
        Check ($null -ne $model -and $model.Coverage.Count -gt 0 -and $model.Marking -eq 'UNCLASSIFIED') ('Dashboards lists assets and carries the marking (' + $modelInfo + ')')
        Check ($null -ne $model -and $iavms -like '*2026-B-0002*') ('Dashboards lists the scan IAVMs (' + $modelInfo + ')')
        $trend = @(Get-ChildItem $workDir -Recurse -Filter 'trend.json' | Where-Object { $_.FullName -like '*Add-on data*dashboards*' })
        Check ($trend.Count -eq 1) 'Dashboards keeps its trend in its data folder next to the database'
        [Vulnerator.View.UI.AddOnUi]::FillIntegrations($panel)
        $dashTexts = (Texts $panel) -join ' || '
        Check ($dashTexts -like '*Dashboards*' -and $dashTexts -notlike '*License:*') 'Settings > Integrations lists Dashboards without a license line'
    }

    # No add-ons folder at all: nothing loaded, no error.
    $none = @([Vulnerator.Model.AddOns.AddOnManager]::LoadFrom((Join-Path $workDir 'missing')))
    Check ($none.Count -eq 0) 'no Add-ons folder: nothing loaded, no error'

    if ($failures.Count -gt 0) { Fail ('' + $failures.Count + ' add-on check(s) failed: ' + ($failures -join '; ')) }
    Write-Host 'Add-on checks passed.'
    exit 0
}
catch {
    $inner = $_.Exception
    while ($null -ne $inner.InnerException) { $inner = $inner.InnerException }
    Fail ('Add-on check failed: ' + $_.Exception.Message + ' / innermost: ' + $inner.GetType().FullName + ': ' + $inner.Message + ' at ' + $_.InvocationInfo.PositionMessage)
}
