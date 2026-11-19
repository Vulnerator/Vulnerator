// Copyright (c) 2026 Hector L. Bones. MIT License (see LICENSE in the repository root).
// Shared metrics layer: plain data the calculations work on. The Dashboards and Elastic add-ons fill it from the
// Vulnerator add-on contract (see Contract/ContractAdapter.cs); tests fill it with synthetic data.
using System;
using System.Collections.Generic;

namespace Vulnerator.Metrics
{
    /// <summary>Where a finding came from.</summary>
    public enum SourceGroup
    {
        Acas,
        Stig,
        Scap,
        Other
    }

    /// <summary>eMASS five-level severity, worst first.</summary>
    public enum SeverityLevel
    {
        VeryHigh = 0,
        High = 1,
        Moderate = 2,
        Low = 3,
        VeryLow = 4,
        Unknown = 5
    }

    /// <summary>
    /// Status used by every view so counts agree. ACAS findings the host's latest scan no longer reports are
    /// Unverified: never counted as closed (Nessus does not report fixes).
    /// </summary>
    public enum EffectiveStatus
    {
        Open,
        Unverified,
        NotAFinding,
        NotApplicable,
        NotReviewed,
        Other
    }

    public sealed class MetricFinding
    {
        public string FindingType { get; set; } = string.Empty;
        public string SourceName { get; set; } = string.Empty;
        public string SourceVersion { get; set; } = string.Empty;
        public long? HardwareId { get; set; }
        public string HostName { get; set; } = string.Empty;
        public string SoftwareName { get; set; } = string.Empty;
        public string Asset { get; set; } = string.Empty;
        public string VulnerabilityId { get; set; } = string.Empty;
        public string RuleId { get; set; } = string.Empty;
        public string Title { get; set; } = string.Empty;

        /// <summary>"I", "II", "III" or "IV".</summary>
        public string Cat { get; set; } = string.Empty;

        /// <summary>"Very High" ... "Very Low" (from the core); empty = derive from Cat.</summary>
        public string SeverityLevelName { get; set; } = string.Empty;

        public string RiskFactor { get; set; } = string.Empty;

        /// <summary>For ACAS, DISA's stig_severity (CAT) of the plugin, used for IAVM severity.</summary>
        public string SecondarySeverity { get; set; } = string.Empty;

        /// <summary>Checklist wording: Open, Not a Finding, Not Applicable, Not Reviewed.</summary>
        public string Status { get; set; } = string.Empty;

        public DateTime? FirstDiscovered { get; set; }
        public DateTime? LastObserved { get; set; }
        public IList<string> NistControls { get; set; } = new List<string>();

        /// <summary>"IAVA:2026-A-0001", "CVE:CVE-2026-0001" and so on.</summary>
        public IList<string> References { get; set; } = new List<string>();

        public IList<string> Groups { get; set; } = new List<string>();

        public SourceGroup Source => Definitions.SourceGroupOf(FindingType);

        public SeverityLevel Level => Definitions.LevelOf(SeverityLevelName, Cat);

        /// <summary>Set by <see cref="EffectiveStatusResolver.Resolve"/>.</summary>
        public EffectiveStatus EffectiveStatus { get; set; } = EffectiveStatus.Other;

        /// <summary>Stable identity across imports: type, asset and rule.</summary>
        public string Key =>
            FindingType + "|" + (HardwareId.HasValue ? "hw" + HardwareId.Value : (Asset ?? string.Empty).ToLowerInvariant()) + "|" +
            (string.IsNullOrEmpty(RuleId) ? VulnerabilityId : RuleId);

        /// <summary>The host (hardware record, else host name) for per-host views; null for software-only findings.</summary>
        public string HostKey =>
            HardwareId.HasValue ? "hw" + HardwareId.Value : string.IsNullOrWhiteSpace(HostName) ? null : HostName.Trim().ToLowerInvariant();
    }

    public sealed class MetricHardware
    {
        public long Id { get; set; }
        public string HostName { get; set; } = string.Empty;
        public string IpAddress { get; set; } = string.Empty;
        public string OperatingSystem { get; set; } = string.Empty;
        public IList<string> Groups { get; set; } = new List<string>();
    }

    public sealed class MetricSubmission
    {
        public string FindingType { get; set; } = string.Empty;
        public string StigName { get; set; } = string.Empty;
        public string SubmittedVersion { get; set; } = string.Empty;
        public string LatestVersion { get; set; } = string.Empty;
        public bool IsOutdated { get; set; }
        public DateTime? BenchmarkDate { get; set; }
        public string HostName { get; set; } = string.Empty;
        public long? HardwareId { get; set; }
        public string SourceFile { get; set; } = string.Empty;
        public DateTime ImportedOn { get; set; }
    }

    public sealed class MetricPoamItem
    {
        /// <summary>"Ongoing", "Completed" or "Risk Accepted".</summary>
        public string Status { get; set; } = string.Empty;

        public string Summary { get; set; } = string.Empty;
        public string SeverityName { get; set; } = string.Empty;
        public DateTime? DateIdentified { get; set; }
        public DateTime? ScheduledCompletion { get; set; }
        public DateTime? CompletionDate { get; set; }
        public IList<string> SecurityChecks { get; set; } = new List<string>();
        public IList<string> Devices { get; set; } = new List<string>();

        public SeverityLevel Level => Definitions.LevelOf(SeverityName, null);
    }
}
