// Copyright (c) 2026 Hector L. Bones. MIT License (see LICENSE in the repository root).
using System;
using System.Collections.Generic;
using System.Linq;
using Vulnerator.Metrics;

namespace Vulnerator.Dashboards
{
    /// <summary>Where the page gets its data (the add-on host; tests use synthetic data).</summary>
    public interface IDashboardSource
    {
        /// <summary>Called off the UI thread.</summary>
        DashboardModel Load();
    }

    /// <summary>A source that can keep the device matching settings (the add-on host; tests may leave it out).</summary>
    public interface IDeviceMatchEditor
    {
        /// <summary>Saves the settings; the next Load uses them.</summary>
        void SaveMatching(DeviceMatchSettings settings);
    }

    public sealed class DashboardInput
    {
        public IList<MetricFinding> Findings { get; set; } = new List<MetricFinding>();
        public IList<MetricHardware> Hardware { get; set; } = new List<MetricHardware>();
        public IList<MetricSubmission> Submissions { get; set; } = new List<MetricSubmission>();
        public IList<MetricPoamItem> PoamItems { get; set; } = new List<MetricPoamItem>();
        public IList<TrendSnapshot> Trend { get; set; } = new List<TrendSnapshot>();
        public DateTime? LibraryImported { get; set; }
        /// <summary>How hardware records are matched into devices for Coverage (default: same short name).</summary>
        public DeviceMatchSettings Matching { get; set; } = new DeviceMatchSettings();
        public DateTime Now { get; set; } = DateTime.Now;
    }

    /// <summary>Everything the views show, computed once per refresh with the shared metrics layer.</summary>
    public sealed class DashboardModel
    {
        public string Marking { get; private set; }
        public DateTime BuiltAt { get; private set; }
        public int FindingCount { get; private set; }
        public IList<SeverityCounts> Severity { get; private set; }
        public IList<MetricFinding> Findings { get; private set; }
        public IList<FamilyCompliance> Compliance { get; private set; }
        public PoamAgingReport Poam { get; private set; }
        public IList<TrendSnapshot> Trend { get; private set; }
        public IList<AssetCoverage> Coverage { get; private set; }
        public DeviceMatchSettings Matching { get; private set; }
        /// <summary>Every hardware host name, for linking devices by hand.</summary>
        public IList<string> HostNames { get; private set; }
        public StigCurrencyReport Stigs { get; private set; }
        public IList<IavmRow> Iavms { get; private set; }
        public IDictionary<string, int[]> IavmCounts { get; private set; }

        public IList<HostRisk> TopHosts(HostSourceFilter filter, int count) => DashboardMetrics.TopHosts(Findings, filter, count);

        public static DashboardModel Build(DashboardInput input, string marking)
        {
            if (input == null) throw new ArgumentNullException(nameof(input));
            List<MetricFinding> findings = input.Findings.ToList();
            if (findings.Any(f => f.EffectiveStatus == EffectiveStatus.Other)) EffectiveStatusResolver.Resolve(findings);
            DateTime today = input.Now.Date;
            IList<IavmRow> iavms = DashboardMetrics.ActiveIavms(findings);
            return new DashboardModel
            {
                Marking = string.IsNullOrWhiteSpace(marking) ? string.Empty : marking.Trim(),
                BuiltAt = input.Now,
                FindingCount = findings.Count,
                Findings = findings,
                Severity = DashboardMetrics.OpenBySeverity(findings),
                Compliance = DashboardMetrics.ComplianceByFamily(findings),
                Poam = DashboardMetrics.PoamAging(input.PoamItems, today),
                Trend = input.Trend.ToList(),
                Coverage = DashboardMetrics.Coverage(input.Hardware, findings, input.Submissions, today, input.Matching ?? DeviceMatchSettings.None),
                Matching = input.Matching ?? DeviceMatchSettings.None,
                HostNames = input.Hardware.Select(h => h.HostName).Where(h => !string.IsNullOrWhiteSpace(h)).Distinct(StringComparer.OrdinalIgnoreCase)
                    .OrderBy(h => h, StringComparer.OrdinalIgnoreCase).ToList(),
                Stigs = DashboardMetrics.StigCurrency(input.Submissions, input.LibraryImported, today),
                Iavms = iavms,
                IavmCounts = DashboardMetrics.IavmCounts(iavms)
            };
        }
    }
}
