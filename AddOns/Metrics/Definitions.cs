// Copyright (c) 2026 Hector L. Bones. MIT License (see LICENSE in the repository root).
using System;
using System.Collections.Generic;
using System.Linq;

namespace Vulnerator.Metrics
{
    /// <summary>The shared definitions (one place, so Dashboards and Elastic name and count things the same way).</summary>
    public static class Definitions
    {
        /// <summary>ACAS scans older than this many days are stale (decided 2026-11-06).</summary>
        public const int StaleScanDays = 30;

        /// <summary>The DISA STIG library is flagged as old after this many days (DISA releases quarterly).</summary>
        public const int StaleLibraryDays = 90;

        /// <summary>
        /// An ACAS finding last seen more than this before the host's newest ACAS result is Unverified. Findings of one
        /// scan share one time; the margin allows for scans that run across midnight or several scanners.
        /// </summary>
        public static readonly TimeSpan SameScanTolerance = TimeSpan.FromHours(12);

        public static readonly string[] IavmTypes = { "IAVA", "IAVB", "IAVT" };

        /// <summary>NIST SP 800-53 Rev 5 control families.</summary>
        public static readonly IReadOnlyList<KeyValuePair<string, string>> Rev5Families = new[]
        {
            Family("AC", "Access Control"),
            Family("AT", "Awareness and Training"),
            Family("AU", "Audit and Accountability"),
            Family("CA", "Assessment, Authorization, and Monitoring"),
            Family("CM", "Configuration Management"),
            Family("CP", "Contingency Planning"),
            Family("IA", "Identification and Authentication"),
            Family("IR", "Incident Response"),
            Family("MA", "Maintenance"),
            Family("MP", "Media Protection"),
            Family("PE", "Physical and Environmental Protection"),
            Family("PL", "Planning"),
            Family("PM", "Program Management"),
            Family("PS", "Personnel Security"),
            Family("PT", "PII Processing and Transparency"),
            Family("RA", "Risk Assessment"),
            Family("SA", "System and Services Acquisition"),
            Family("SC", "System and Communications Protection"),
            Family("SI", "System and Information Integrity"),
            Family("SR", "Supply Chain Risk Management")
        };

        private static readonly HashSet<string> FamilyCodes =
            new HashSet<string>(Rev5Families.Select(f => f.Key), StringComparer.OrdinalIgnoreCase);

        public static SourceGroup SourceGroupOf(string findingType)
        {
            switch ((findingType ?? string.Empty).Trim().ToUpperInvariant())
            {
                case "ACAS": return SourceGroup.Acas;
                case "CKL": case "CKLB": return SourceGroup.Stig;
                case "XCCDF": return SourceGroup.Scap;
                default: return SourceGroup.Other;
            }
        }

        public static string SourceGroupName(SourceGroup group)
        {
            switch (group)
            {
                case SourceGroup.Acas: return "ACAS";
                case SourceGroup.Stig: return "STIG";
                case SourceGroup.Scap: return "SCAP";
                default: return "Other";
            }
        }

        /// <summary>The level from the core's name; else from the CAT (I = High ... IV = Very Low).</summary>
        public static SeverityLevel LevelOf(string levelName, string cat)
        {
            switch ((levelName ?? string.Empty).Trim().ToUpperInvariant())
            {
                case "VERY HIGH": case "CRITICAL": return SeverityLevel.VeryHigh;
                case "HIGH": return SeverityLevel.High;
                case "MODERATE": case "MEDIUM": return SeverityLevel.Moderate;
                case "LOW": return SeverityLevel.Low;
                case "VERY LOW": case "INFO": case "NONE": return SeverityLevel.VeryLow;
            }
            return LevelOfCat(cat);
        }

        public static SeverityLevel LevelOfCat(string cat)
        {
            string c = (cat ?? string.Empty).Trim().ToUpperInvariant();
            if (c.StartsWith("CAT ", StringComparison.Ordinal)) c = c.Substring(4).Trim();
            switch (c)
            {
                case "I": return SeverityLevel.High;
                case "II": return SeverityLevel.Moderate;
                case "III": return SeverityLevel.Low;
                case "IV": return SeverityLevel.VeryLow;
                default: return SeverityLevel.Unknown;
            }
        }

        public static string LevelName(SeverityLevel level)
        {
            switch (level)
            {
                case SeverityLevel.VeryHigh: return "Very High";
                case SeverityLevel.High: return "High";
                case SeverityLevel.Moderate: return "Moderate";
                case SeverityLevel.Low: return "Low";
                case SeverityLevel.VeryLow: return "Very Low";
                default: return "Unknown";
            }
        }

        /// <summary>"AC-2(1)" -> "AC"; null when not a Rev 5 family.</summary>
        public static string FamilyOf(string control)
        {
            if (string.IsNullOrWhiteSpace(control)) return null;
            string code = control.Trim();
            int dash = code.IndexOf('-');
            if (dash > 0) code = code.Substring(0, dash);
            code = code.Trim().ToUpperInvariant();
            return FamilyCodes.Contains(code) ? code : null;
        }

        public static EffectiveStatus FromStatus(string status)
        {
            switch ((status ?? string.Empty).Trim().ToUpperInvariant())
            {
                case "OPEN": case "ONGOING": return EffectiveStatus.Open;
                case "NOT A FINDING": case "NOTAFINDING": case "COMPLETED": return EffectiveStatus.NotAFinding;
                case "NOT APPLICABLE": case "NOT_APPLICABLE": return EffectiveStatus.NotApplicable;
                case "NOT REVIEWED": case "NOT_REVIEWED": return EffectiveStatus.NotReviewed;
                default: return EffectiveStatus.Other;
            }
        }

        /// <summary>"IAVA:2026-A-0001" -> ("IAVA", "2026-A-0001"); null when not an IAVM reference.</summary>
        public static KeyValuePair<string, string>? ParseIavm(string reference)
        {
            if (string.IsNullOrWhiteSpace(reference)) return null;
            int colon = reference.IndexOf(':');
            if (colon <= 0) return null;
            string type = reference.Substring(0, colon).Trim().ToUpperInvariant();
            string id = reference.Substring(colon + 1).Trim();
            if (id.Length == 0 || Array.IndexOf(IavmTypes, type) < 0) return null;
            return new KeyValuePair<string, string>(type, id);
        }

        private static KeyValuePair<string, string> Family(string code, string name)
        {
            return new KeyValuePair<string, string>(code, name);
        }
    }

    /// <summary>Applies the effective-status rule to a set of findings.</summary>
    public static class EffectiveStatusResolver
    {
        /// <summary>
        /// Sets EffectiveStatus on each finding. An Open ACAS finding is Unverified when the host has a newer ACAS result
        /// (more than <see cref="Definitions.SameScanTolerance"/> later) that no longer reports it. A host with only one
        /// scan keeps its findings Open.
        /// </summary>
        public static void Resolve(IEnumerable<MetricFinding> findings)
        {
            List<MetricFinding> list = findings.ToList();
            var newestAcas = new Dictionary<string, DateTime>();
            foreach (MetricFinding f in list)
            {
                if (f.Source != SourceGroup.Acas || !f.LastObserved.HasValue || f.HostKey == null) continue;
                DateTime known;
                if (!newestAcas.TryGetValue(f.HostKey, out known) || f.LastObserved.Value > known) newestAcas[f.HostKey] = f.LastObserved.Value;
            }
            foreach (MetricFinding f in list)
            {
                EffectiveStatus status = Definitions.FromStatus(f.Status);
                if (status == EffectiveStatus.Open && f.Source == SourceGroup.Acas && f.LastObserved.HasValue && f.HostKey != null
                    && newestAcas[f.HostKey] - f.LastObserved.Value > Definitions.SameScanTolerance)
                {
                    status = EffectiveStatus.Unverified;
                }
                f.EffectiveStatus = status;
            }
        }
    }
}
