using System;
using System.Collections.Generic;
using System.Runtime.CompilerServices;

// The host fills the read-only records; add-ons can only read them.
[assembly: InternalsVisibleTo("Vulnerator")]

namespace Vulnerator.AddOns
{
    /// <summary>The version of this contract. The host loads add-ons built for this version or an older supported one.</summary>
    public static class AddOnApi
    {
        /// <summary>
        /// Current contract version. 1 = Vulnerator 7.4.0-beta.1; 2 = adds licenses (<see cref="IAddOnHost.Licenses"/>,
        /// <see cref="IAddOnHost.LicensesChanged"/>, <see cref="IAddOnLicensing"/>), Vulnerator 7.4.0-beta.2;
        /// 3 = adds dashboard data (more <see cref="FindingRecord"/> fields, <see cref="IFindingsData.GetStigSubmissions"/>,
        /// <see cref="IFindingsData.GetPoamItems"/>, <see cref="IFindingsData.GetLastStigLibraryImport"/>), Vulnerator 7.4.0-beta.3.
        /// An add-on built against a newer version is refused, with a clear message, by an older Vulnerator.
        /// </summary>
        public const int Version = 3;

        /// <summary>Oldest contract version the host still loads.</summary>
        public const int MinimumSupportedVersion = 1;
    }

    /// <summary>
    /// Marks an assembly as a Vulnerator add-on and names its entry type. The file must be named "*.AddOn.dll" and sit
    /// in the "Add-ons" folder next to Vulnerator.exe (or one folder below it).
    /// </summary>
    [AttributeUsage(AttributeTargets.Assembly, AllowMultiple = false)]
    public sealed class VulneratorAddOnAttribute : Attribute
    {
        public VulneratorAddOnAttribute(Type addOnType)
        { AddOnType = addOnType; }

        /// <summary>The type that implements <see cref="IAddOn"/>; it needs a public parameterless constructor.</summary>
        public Type AddOnType { get; }

        /// <summary>The contract version the add-on was built against. Defaults to the version it was compiled with.</summary>
        public int ApiVersion { get; set; } = AddOnApi.Version;

        /// <summary>Optional lowest Vulnerator version the add-on works with, for example "7.4.0".</summary>
        public string MinimumCoreVersion { get; set; }
    }

    /// <summary>An add-on's entry point.</summary>
    public interface IAddOn
    {
        /// <summary>Stable, unique identifier, for example "vulnerator.dashboards". Used for the add-on's data folder.</summary>
        string Id { get; }

        /// <summary>Name shown to people.</summary>
        string Name { get; }

        /// <summary>Version shown to people, for example "1.0.0".</summary>
        string Version { get; }

        /// <summary>One short line describing the add-on.</summary>
        string Description { get; }

        /// <summary>
        /// Called once at startup on the UI thread. Register pages and settings sections here. If this throws, the add-on
        /// is skipped and nothing it registered is shown.
        /// </summary>
        void Initialize(IAddOnHost host);
    }

    /// <summary>What Vulnerator offers an add-on.</summary>
    public interface IAddOnHost
    {
        /// <summary>The contract version the host implements (<see cref="AddOnApi.Version"/> of the running Vulnerator).</summary>
        int ApiVersion { get; }

        /// <summary>The Vulnerator release, for example "7.4.0-beta.1".</summary>
        string CoreVersion { get; }

        /// <summary>
        /// A folder the add-on may write to (created on first use): next to the database, so a portable copy keeps it.
        /// Never write into the program folder.
        /// </summary>
        string DataFolder { get; }

        /// <summary>The classification marking set in Vulnerator (Settings); exports should carry it.</summary>
        string ClassificationMarking { get; }

        /// <summary>Writes to the Vulnerator log, tagged with the add-on's id.</summary>
        IAddOnLog Log { get; }

        /// <summary>Read-only access to the data in the open database.</summary>
        IFindingsData Data { get; }

        /// <summary>
        /// Adds a page to the main navigation menu. <paramref name="createView"/> is called the first time the page is
        /// shown and must return a WPF element (for example a UserControl). <paramref name="iconName"/> is a Material
        /// Design icon name as used by MahApps.Metro.IconPacks (for example "ChartBar"); an unknown name gets a default icon.
        /// </summary>
        void AddPage(string title, string iconName, Func<object> createView);

        /// <summary>Adds a section under Settings &gt; Integrations. <paramref name="createView"/> returns a WPF element.</summary>
        void AddSettingsSection(string title, Func<object> createView);

        /// <summary>
        /// Raised after files are imported or the database changes. May be raised on a background thread: use the
        /// view's Dispatcher before touching the UI.
        /// </summary>
        event EventHandler DataChanged;

        /// <summary>
        /// (Version 2) No longer used: Vulnerator 2.0 needs no licenses (since 7.5.0), so this is always empty. Kept so
        /// add-ons built for interface versions 2 and 3 still load.
        /// </summary>
        IReadOnlyList<string> Licenses { get; }

        /// <summary>(Version 2) No longer raised (no licenses since 7.5.0). Kept for compatibility.</summary>
        event EventHandler LicensesChanged;
    }

    /// <summary>
    /// (Version 2, optional) No longer used: Vulnerator 2.0 needs no licenses and does not call it (since 7.5.0).
    /// Kept so add-ons built for interface versions 2 and 3 still load.
    /// </summary>
    public interface IAddOnLicensing
    {
        /// <summary>One line next to the add-on, for example "Licensed to Example Org until 2027-11-30" or "No license".</summary>
        string LicenseStatus { get; }

        /// <summary>
        /// Describes one entered license, for example "Dashboards: valid until 2027-11-30", "Dashboards: expired
        /// 2026-10-01" or "Dashboards: signature not valid". Return null when the license is not for this add-on.
        /// </summary>
        string DescribeLicense(string licenseText);
    }

    /// <summary>Log writer for an add-on.</summary>
    public interface IAddOnLog
    {
        void Info(string message);
        void Warning(string message);
        void Error(string message, Exception exception = null);
    }

    /// <summary>
    /// Read-only data. Each call reads the database again through a read-only connection and returns new, read-only
    /// objects; an add-on cannot change Vulnerator's data through them. Calls can be slow on large databases: run them off the UI thread.
    /// </summary>
    public interface IFindingsData
    {
        /// <summary>Every finding (one host or software item and one rule or plugin), without the Reporting filters.</summary>
        IReadOnlyList<FindingRecord> GetFindings();

        /// <summary>Every hardware asset (Configuration Management &gt; Hardware).</summary>
        IReadOnlyList<HardwareRecord> GetHardware();

        /// <summary>
        /// (Version 3) Every STIG checklist (CKL, CKLB) and SCAP result (XCCDF) imported by 7.4.0-beta.3 or later, one per
        /// file, host and STIG, with the release it was submitted with and the newest release Vulnerator has loaded.
        /// </summary>
        IReadOnlyList<StigSubmissionRecord> GetStigSubmissions();

        /// <summary>
        /// (Version 3) The eMASS POA&amp;M items as the eMASS POA&amp;M export builds them (same grouping, statuses and
        /// scheduled completion dates, from the Settings), without the Reporting filters.
        /// </summary>
        IReadOnlyList<PoamItemRecord> GetPoamItems();

        /// <summary>(Version 3) When the DISA STIG library was last imported (Settings), or null if never.</summary>
        DateTime? GetLastStigLibraryImport();
    }

    /// <summary>One finding.</summary>
    public sealed class FindingRecord
    {
        internal FindingRecord() { }

        /// <summary>ACAS, CKL, XCCDF, WASSP, Fortify and so on.</summary>
        public string FindingType { get; internal set; }

        /// <summary>STIG or scan source name.</summary>
        public string SourceName { get; internal set; }

        /// <summary>"V2R3" style STIG version, when the source has one.</summary>
        public string SourceVersion { get; internal set; }

        public string HostName { get; internal set; }
        public string IpAddress { get; internal set; }
        public string SoftwareName { get; internal set; }

        /// <summary>The host, or the software item for software-only findings.</summary>
        public string Asset { get; internal set; }

        /// <summary>Vulnerability ID (V-12345) or plugin ID.</summary>
        public string VulnerabilityId { get; internal set; }

        /// <summary>Rule ID with revision (SV-12345r2_rule).</summary>
        public string RuleId { get; internal set; }

        public string Title { get; internal set; }

        /// <summary>"I", "II", "III" or "IV" (the override when one is set, else the raw value).</summary>
        public string Severity { get; internal set; }

        /// <summary>The severity as the source file gave it.</summary>
        public string RawSeverity { get; internal set; }

        /// <summary>"Open", "Not a Finding", "Not Applicable", "Not Reviewed" or "Error".</summary>
        public string Status { get; internal set; }

        public bool IsOpen { get; internal set; }

        /// <summary>Status of the mitigation or condition, when one is recorded.</summary>
        public string MitigatedStatus { get; internal set; }

        public string Description { get; internal set; }
        public string CheckContent { get; internal set; }
        public string FixText { get; internal set; }
        public string FindingDetails { get; internal set; }
        public string Comments { get; internal set; }
        public string SourceFile { get; internal set; }

        /// <summary>When the finding was last seen in an imported file.</summary>
        public DateTime? LastObserved { get; internal set; }

        public IReadOnlyList<string> Groups { get; internal set; }

        /// <summary>NIST SP 800-53 Rev 5 controls, for example "AC-2(1)".</summary>
        public IReadOnlyList<string> NistControls { get; internal set; }

        public IReadOnlyList<string> Ccis { get; internal set; }

        /// <summary>(Version 3) The hardware record (<see cref="HardwareRecord.Id"/>); null for software-only findings.</summary>
        public long? HardwareId { get; internal set; }

        /// <summary>(Version 3) When the finding was first seen.</summary>
        public DateTime? FirstDiscovered { get; internal set; }

        /// <summary>
        /// (Version 3) eMASS severity level: "Very High", "High", "Moderate", "Low" or "Very Low". A severity override wins
        /// (by CAT); ACAS uses the Nessus risk factor (Critical = Very High); otherwise CAT I = High, II = Moderate,
        /// III = Low, IV = Very Low. ACAS scans imported before 7.4.0-beta.3 have no risk factor, so Critical shows as High
        /// until the scan is imported again.
        /// </summary>
        public string SeverityLevel { get; internal set; }

        /// <summary>(Version 3) ACAS only: the Nessus risk factor (Critical, High, Medium, Low, None), when kept.</summary>
        public string RiskFactor { get; internal set; }

        /// <summary>(Version 3) The second severity the source gives; for ACAS, DISA's stig_severity (for example for IAVMs).</summary>
        public string SecondarySeverity { get; internal set; }

        /// <summary>
        /// (Version 3) References as "TYPE:value", for example "IAVA:2026-A-0001", "IAVB:2026-B-0002", "IAVT:2026-T-0003",
        /// "CVE:CVE-2026-0001" or "CWE:79".
        /// </summary>
        public IReadOnlyList<string> References { get; internal set; }
    }

    /// <summary>(Version 3) One STIG checklist or SCAP result as submitted: one file, host and STIG.</summary>
    public sealed class StigSubmissionRecord
    {
        internal StigSubmissionRecord() { }

        /// <summary>CKL (checklists, including CKLB) or XCCDF (SCAP results).</summary>
        public string FindingType { get; internal set; }

        public string StigName { get; internal set; }

        /// <summary>"V2R4" style, as submitted.</summary>
        public string SubmittedVersion { get; internal set; }

        /// <summary>The benchmark date as submitted, when the file has one.</summary>
        public DateTime? BenchmarkDate { get; internal set; }

        /// <summary>The newest release of this STIG Vulnerator has loaded (library or newer checklists), "V2R5" style.</summary>
        public string LatestVersion { get; internal set; }

        /// <summary>The submitted release is older than <see cref="LatestVersion"/>.</summary>
        public bool IsOutdated { get; internal set; }

        public string HostName { get; internal set; }

        /// <summary>The hardware record, when the host is in the Hardware list.</summary>
        public long? HardwareId { get; internal set; }

        public string SourceFile { get; internal set; }
        public DateTime ImportedOn { get; internal set; }
    }

    /// <summary>(Version 3) One eMASS POA&amp;M item: one rule or plugin, in one status, across the affected assets.</summary>
    public sealed class PoamItemRecord
    {
        internal PoamItemRecord() { }

        /// <summary>"Ongoing", "Completed" or "Risk Accepted".</summary>
        public string Status { get; internal set; }

        /// <summary>The control vulnerability description (eMASS column D).</summary>
        public string Summary { get; internal set; }

        public IReadOnlyList<string> SecurityChecks { get; internal set; }
        public IReadOnlyList<string> Controls { get; internal set; }

        /// <summary>eMASS raw severity: "Very High", "High", "Moderate", "Low" or "Very Low".</summary>
        public string RawSeverity { get; internal set; }

        public DateTime? DateIdentified { get; internal set; }
        public DateTime? ScheduledCompletion { get; internal set; }
        public DateTime? CompletionDate { get; internal set; }
        public IReadOnlyList<string> DevicesAffected { get; internal set; }
        public IReadOnlyList<PoamMilestoneRecord> Milestones { get; internal set; }
    }

    /// <summary>(Version 3) One POA&amp;M milestone.</summary>
    public sealed class PoamMilestoneRecord
    {
        internal PoamMilestoneRecord() { }

        public string Description { get; internal set; }

        /// <summary>"Open" or "Completed".</summary>
        public string Status { get; internal set; }

        public DateTime? ScheduledCompletion { get; internal set; }
        public DateTime? CompletionDate { get; internal set; }
    }

    /// <summary>One hardware asset.</summary>
    public sealed class HardwareRecord
    {
        internal HardwareRecord() { }

        public long Id { get; internal set; }
        public string HostName { get; internal set; }
        public string Fqdn { get; internal set; }
        public string NetBios { get; internal set; }
        public string IpAddress { get; internal set; }
        public string OperatingSystem { get; internal set; }
        public string Manufacturer { get; internal set; }
        public string Model { get; internal set; }
        public string SerialNumber { get; internal set; }
        public string Role { get; internal set; }
        public bool IsVirtual { get; internal set; }
        public IReadOnlyList<string> Groups { get; internal set; }
    }
}
