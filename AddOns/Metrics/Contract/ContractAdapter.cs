// Copyright (c) 2026 Hector L. Bones. MIT License (see LICENSE in the repository root).
// Fills the metrics model from the Vulnerator add-on contract (interface version 3, Vulnerator 7.4.0 and later).
using System.Collections.Generic;
using System.Linq;
using Vulnerator.AddOns;

namespace Vulnerator.Metrics
{
    public static class ContractAdapter
    {
        /// <summary>Every finding, with the effective status already resolved.</summary>
        public static List<MetricFinding> Findings(IFindingsData data)
        {
            List<MetricFinding> findings = data.GetFindings().Select(ToMetric).ToList();
            EffectiveStatusResolver.Resolve(findings);
            return findings;
        }

        public static List<MetricHardware> Hardware(IFindingsData data)
        {
            return data.GetHardware().Select(h => new MetricHardware
            {
                Id = h.Id,
                HostName = h.HostName ?? string.Empty,
                IpAddress = h.IpAddress ?? string.Empty,
                OperatingSystem = h.OperatingSystem ?? string.Empty,
                Groups = (h.Groups ?? new string[0]).ToList()
            }).ToList();
        }

        public static List<MetricSubmission> Submissions(IFindingsData data)
        {
            return data.GetStigSubmissions().Select(s => new MetricSubmission
            {
                FindingType = s.FindingType ?? string.Empty,
                StigName = s.StigName ?? string.Empty,
                SubmittedVersion = s.SubmittedVersion ?? string.Empty,
                LatestVersion = s.LatestVersion ?? string.Empty,
                IsOutdated = s.IsOutdated,
                BenchmarkDate = s.BenchmarkDate,
                HostName = s.HostName ?? string.Empty,
                HardwareId = s.HardwareId,
                SourceFile = s.SourceFile ?? string.Empty,
                ImportedOn = s.ImportedOn
            }).ToList();
        }

        public static List<MetricPoamItem> PoamItems(IFindingsData data)
        {
            return data.GetPoamItems().Select(p => new MetricPoamItem
            {
                Status = p.Status ?? string.Empty,
                Summary = p.Summary ?? string.Empty,
                SeverityName = p.RawSeverity ?? string.Empty,
                DateIdentified = p.DateIdentified,
                ScheduledCompletion = p.ScheduledCompletion,
                CompletionDate = p.CompletionDate,
                SecurityChecks = (p.SecurityChecks ?? new string[0]).ToList(),
                Devices = (p.DevicesAffected ?? new string[0]).ToList()
            }).ToList();
        }

        public static MetricFinding ToMetric(FindingRecord r)
        {
            return new MetricFinding
            {
                FindingType = r.FindingType ?? string.Empty,
                SourceName = r.SourceName ?? string.Empty,
                SourceVersion = r.SourceVersion ?? string.Empty,
                HardwareId = r.HardwareId,
                HostName = r.HostName ?? string.Empty,
                SoftwareName = r.SoftwareName ?? string.Empty,
                Asset = r.Asset ?? string.Empty,
                VulnerabilityId = r.VulnerabilityId ?? string.Empty,
                RuleId = r.RuleId ?? string.Empty,
                Title = r.Title ?? string.Empty,
                Cat = r.Severity ?? string.Empty,
                SeverityLevelName = r.SeverityLevel ?? string.Empty,
                RiskFactor = r.RiskFactor ?? string.Empty,
                SecondarySeverity = r.SecondarySeverity ?? string.Empty,
                Status = r.Status ?? string.Empty,
                FirstDiscovered = r.FirstDiscovered,
                LastObserved = r.LastObserved,
                NistControls = (r.NistControls ?? new string[0]).ToList(),
                References = (r.References ?? new string[0]).ToList(),
                Groups = (r.Groups ?? new string[0]).ToList()
            };
        }
    }
}
