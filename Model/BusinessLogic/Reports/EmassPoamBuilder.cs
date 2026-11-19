using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;

namespace Vulnerator.Model.BusinessLogic.Reports
{
    /// <summary>One row of the POA&amp;M query: a rule or plugin as found on one host.</summary>
    public class EmassPoamFinding
    {
        public string SourceName = string.Empty;
        public string SourceVersion = string.Empty;
        public string SourceRelease = string.Empty;
        public string VulnerabilityIdentifier = string.Empty;
        public string VulnerabilityVersion = string.Empty;
        public string Title = string.Empty;
        public string Description = string.Empty;
        public string Controls = string.Empty;          // comma-separated, e.g. "AC-2(1),CM-6"
        public string RawStatus = string.Empty;         // Vulnerator status: Ongoing, Completed, Not Applicable, Not Reviewed
        public string MitigatedStatus = string.Empty;   // user-set status from a mitigation, wins over RawStatus
        public string RawRisk = string.Empty;           // I, II, III, IV
        public string Hosts = string.Empty;             // comma-separated
        public string Software = string.Empty;          // comma-separated
        public string Comments = string.Empty;
        public string FindingDetails = string.Empty;
        public string TechnicalMitigation = string.Empty;
        public string PredisposingConditions = string.Empty;
        public string Severity = string.Empty;
        public string ThreatRelevance = string.Empty;
        public string ThreatDescription = string.Empty;
        public string Likelihood = string.Empty;
        public string Impact = string.Empty;
        public string ImpactDescription = string.Empty;
        public string ResidualRisk = string.Empty;
        public string ProposedMitigation = string.Empty;
        public string FixText = string.Empty;
        public string SeverityOverride = string.Empty;
        public string SeverityJustification = string.Empty;
        public DateTime? FirstDiscovered;
        public DateTime? LastObserved;
        public DateTime? EstimatedCompletion;
    }

    public class EmassMilestone
    {
        public string Description = string.Empty;
        public string Status = string.Empty;
        public DateTime? ScheduledCompletion;
        public DateTime? CompletionDate;
    }

    /// <summary>One eMASS POA&amp;M item: one rule or plugin, in one eMASS status, across all affected hosts.</summary>
    public class EmassPoamItem
    {
        public string Status = string.Empty;
        public string Summary = string.Empty;
        public string Description = string.Empty;
        public List<string> Controls = new List<string>();
        public List<string> SecurityChecks = new List<string>();
        public DateTime? DateIdentified;
        public DateTime? ScheduledCompletion;
        public DateTime? CompletionDate;
        public List<EmassMilestone> Milestones = new List<EmassMilestone>();
        public string IdentificationSource = string.Empty;
        public string IdentificationSourceDetails = string.Empty;
        public string OfficeOrg = string.Empty;
        public string Comments = string.Empty;
        public string RawSeverity = string.Empty;
        public List<string> DevicesAffected = new List<string>();
        public string Mitigations = string.Empty;
        public string Severity = string.Empty;
        public string RelevanceOfThreat = string.Empty;
        public string Likelihood = string.Empty;
        public string Impact = string.Empty;
        public string ImpactDescription = string.Empty;
        public string ResidualRiskLevel = string.Empty;
        public string Recommendations = string.Empty;
        public string Resources = string.Empty;
        internal int RawRiskRank;
        internal string SortKey = string.Empty;
    }

    /// <summary>Defaults follow the CKL-CKLB-Processor POA&amp;M rulings (config.json Poam section).</summary>
    public class EmassPoamOptions
    {
        public const string Placeholder = "Organizationally Defined";
        public string OfficeOrg = Placeholder;
        public string Resources = Placeholder;
        public string IdentificationSource = "Security Control Deficiencies";
        public string MitigationPlaceholder = "Analyst Must Complete";
        public string DefaultMilestone = string.Empty;   // OQ-01: written by the analyst after the report
        /// <summary>Days from Date Identified to scheduled completion, by raw severity level (POAM-06).</summary>
        public Dictionary<string, int> CompletionDays = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase)
        { { "Very High", 30 }, { "High", 30 }, { "Moderate", 60 }, { "Low", 180 }, { "Very Low", 180 } };
        public DateTime ExportDate = DateTime.Today;

        /// <summary>
        /// Reads "30;60;180" (High;Moderate;Low) or a single number for every level. Blank or invalid keeps the defaults.
        /// </summary>
        public void SetCompletionDays(string setting)
        {
            if (string.IsNullOrWhiteSpace(setting))
            { return; }
            string[] parts = setting.Split(new[] { ';', ',', '/' }, StringSplitOptions.RemoveEmptyEntries);
            int[] days = new int[parts.Length];
            for (int i = 0; i < parts.Length; i++)
            {
                if (!int.TryParse(parts[i].Trim(), NumberStyles.Integer, CultureInfo.InvariantCulture, out days[i]) || days[i] < 0)
                { return; }
            }
            if (days.Length == 1)
            { days = new[] { days[0], days[0], days[0] }; }
            if (days.Length != 3)
            { return; }
            CompletionDays["Very High"] = days[0];
            CompletionDays["High"] = days[0];
            CompletionDays["Moderate"] = days[1];
            CompletionDays["Low"] = days[2];
            CompletionDays["Very Low"] = days[2];
        }
    }

    /// <summary>
    /// Turns POA&amp;M query rows into eMASS RMF Standard POA&amp;M items. Template rules: one milestone for Ongoing and
    /// Completed items, none for Risk Accepted; controls and security checks semicolon-separated. Content rules follow
    /// the owner's CKL-CKLB-Processor rulings (docs/DECISIONS.md): only open findings (POAM-05, R-19), dates by
    /// severity from Date Identified (POAM-06, AD-916), and the field derivations noted below. Mitigation data entered
    /// in Vulnerator takes precedence over the derived values.
    /// </summary>
    public static class EmassPoamBuilder
    {
        public const string Ongoing = "Ongoing";
        public const string Completed = "Completed";
        public const string RiskAccepted = "Risk Accepted";
        public const string ListSeparator = "; ";

        private static readonly string[] Levels = { "Very Low", "Low", "Moderate", "High", "Very High" };

        /// <summary>
        /// eMASS POA&amp;M status for a finding, or null when it does not belong on a POA&amp;M. Only open findings are
        /// weaknesses (POAM-05); not-reviewed checks are an incomplete assessment, not a weakness (R-19); passing
        /// checks never become Completed items. A mitigation entered in Vulnerator can mark an open finding
        /// Completed or Risk Accepted, or take it off (Not Applicable).
        /// </summary>
        public static string ToEmassStatus(string rawStatus, string mitigatedStatus)
        {
            string raw = (rawStatus ?? string.Empty).Trim().ToLowerInvariant();
            if (raw != "ongoing" && raw != "open")
            { return null; }
            switch ((mitigatedStatus ?? string.Empty).Trim().ToLowerInvariant())
            {
                case "":
                case "ongoing":
                case "open":
                case "not reviewed":
                    return Ongoing;
                case "completed":
                case "closed":
                    return Completed;
                case "risk accepted":
                    return RiskAccepted;
                default:
                    return null;   // Not Applicable, Archived
            }
        }

        /// <summary>Normalizes a level to Very Low / Low / Moderate / High / Very High, or "" when it is not one.</summary>
        public static string ToEmassLevel(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            { return string.Empty; }
            string key = value.Trim().ToLowerInvariant();
            if (key == "medium")
            { key = "moderate"; }
            foreach (string level in Levels)
            {
                if (level.ToLowerInvariant() == key)
                { return level; }
            }
            return string.Empty;
        }

        /// <summary>DISA category to eMASS raw severity: CAT I = High, II = Moderate, III = Low, IV = Very Low.</summary>
        public static string RawRiskToLevel(string rawRisk)
        {
            switch ((rawRisk ?? string.Empty).Trim().ToUpperInvariant())
            {
                case "I": return "High";
                case "II": return "Moderate";
                case "III": return "Low";
                case "IV": return "Very Low";
                default: return string.Empty;
            }
        }

        private static int RawRiskRank(string rawRisk)
        {
            switch ((rawRisk ?? string.Empty).Trim().ToUpperInvariant())
            {
                case "I": return 0;
                case "II": return 1;
                case "III": return 2;
                case "IV": return 3;
                default: return 4;
            }
        }

        /// <summary>STIG rules as "SV-1001r2_rule"; anything else (Nessus plugin IDs, IAVM IDs) unchanged.</summary>
        public static string ToSecurityCheck(string identifier, string version)
        {
            string id = (identifier ?? string.Empty).Trim();
            if (id.StartsWith("SV-", StringComparison.OrdinalIgnoreCase))
            {
                if (id.EndsWith("_rule", StringComparison.OrdinalIgnoreCase))
                { return id; }
                string release = (version ?? string.Empty).Trim();
                return string.IsNullOrEmpty(release) ? id + "_rule" : id + "r" + release + "_rule";
            }
            return id;
        }

        /// <summary>"Organization, First Last, Phone, Email" as the template asks, skipping blanks.</summary>
        public static string ComposeOfficeOrg(string organization, string name, string phone, string email)
        {
            return string.Join(", ", new[] { organization, name, phone, email }
                .Where(part => !string.IsNullOrWhiteSpace(part))
                .Select(part => part.Trim()));
        }

        public static List<EmassPoamItem> Build(IEnumerable<EmassPoamFinding> findings, EmassPoamOptions options)
        {
            Dictionary<string, List<EmassPoamFinding>> groups = new Dictionary<string, List<EmassPoamFinding>>(StringComparer.OrdinalIgnoreCase);
            List<string> order = new List<string>();
            foreach (EmassPoamFinding finding in findings)
            {
                string status = ToEmassStatus(finding.RawStatus, finding.MitigatedStatus);
                if (status == null || string.IsNullOrWhiteSpace(finding.VulnerabilityIdentifier))
                { continue; }
                // Informational results (raw risk IV, e.g. Nessus severity 0) are not weaknesses.
                if ("IV".Equals((finding.RawRisk ?? string.Empty).Trim(), StringComparison.OrdinalIgnoreCase))
                { continue; }
                string key = status + "|" + finding.SourceName + "|" + finding.VulnerabilityIdentifier;
                List<EmassPoamFinding> list;
                if (!groups.TryGetValue(key, out list))
                {
                    list = new List<EmassPoamFinding>();
                    groups.Add(key, list);
                    order.Add(key);
                }
                list.Add(finding);
            }

            List<EmassPoamItem> items = new List<EmassPoamItem>();
            foreach (string key in order)
            { items.Add(BuildItem(key.Split('|')[0], groups[key], options)); }

            // CAT I first, then by source and rule, so the POA&M reads in priority order.
            return items
                .OrderBy(item => item.RawRiskRank)
                .ThenBy(item => item.SortKey, StringComparer.OrdinalIgnoreCase)
                .ThenBy(item => item.Status, StringComparer.Ordinal)
                .ToList();
        }

        private static EmassPoamItem BuildItem(string status, List<EmassPoamFinding> findings, EmassPoamOptions options)
        {
            EmassPoamFinding first = findings[0];
            EmassPoamItem item = new EmassPoamItem
            {
                Status = status,
                Summary = FirstNonEmpty(findings.Select(f => f.Title)),
                IdentificationSource = options.IdentificationSource ?? string.Empty,
                OfficeOrg = options.OfficeOrg ?? string.Empty,
                Resources = options.Resources ?? string.Empty,
                RawRiskRank = findings.Min(f => RawRiskRank(f.RawRisk)),
                SortKey = first.SourceName + " " + first.VulnerabilityIdentifier
            };
            item.RawSeverity = RawRiskToLevel(findings.OrderBy(f => RawRiskRank(f.RawRisk)).First().RawRisk);

            string description = FirstNonEmpty(findings.Select(f => f.Description));
            item.Description = string.IsNullOrWhiteSpace(description) ? item.Summary : description;

            item.Controls = Distinct(findings.SelectMany(f => SplitList(f.Controls)));
            item.SecurityChecks = Distinct(findings.Select(f => ToSecurityCheck(f.VulnerabilityIdentifier, f.VulnerabilityVersion)));
            item.DevicesAffected = Distinct(findings.SelectMany(f =>
                SplitList(f.Hosts).Count > 0 ? SplitList(f.Hosts) : SplitList(f.Software)));
            item.IdentificationSourceDetails = SourceDetails(first);

            // Mitigations: Vulnerator mitigation text, else the first severity justification, else the placeholder (AD-917).
            item.Mitigations = JoinDistinct(findings.Select(f => f.TechnicalMitigation));
            if (string.IsNullOrWhiteSpace(item.Mitigations))
            { item.Mitigations = FirstNonEmpty(findings.Select(f => f.SeverityJustification)); }
            if (string.IsNullOrWhiteSpace(item.Mitigations))
            { item.Mitigations = options.MitigationPlaceholder ?? string.Empty; }
            // Severity honours a severity override; Impact derives from the rule's own severity (PD-06 / PD-06a).
            item.Severity = FirstNonEmpty(new[]
            {
                ToEmassLevel(FirstNonEmpty(findings.Select(f => f.Severity))),
                ToEmassLevel(FirstNonEmpty(findings.Select(f => f.SeverityOverride))),
                item.RawSeverity
            });
            item.RelevanceOfThreat = ToEmassLevel(FirstNonEmpty(findings.Select(f => f.ThreatRelevance)));
            item.Likelihood = ToEmassLevel(FirstNonEmpty(findings.Select(f => f.Likelihood)));
            item.Impact = FirstNonEmpty(new[] { ToEmassLevel(FirstNonEmpty(findings.Select(f => f.Impact))), item.RawSeverity });
            // Impact Description = Description; Recommendations = Fix Text (POAM-27/29), unless a mitigation says otherwise.
            item.ImpactDescription = JoinDistinct(findings.Select(f => f.ImpactDescription));
            if (string.IsNullOrWhiteSpace(item.ImpactDescription))
            { item.ImpactDescription = item.Description; }
            item.ResidualRiskLevel = ToEmassLevel(FirstNonEmpty(findings.Select(f => f.ResidualRisk)));
            string proposed = JoinDistinct(findings.Select(f => f.ProposedMitigation));
            item.Recommendations = string.IsNullOrWhiteSpace(proposed) ? FirstNonEmpty(findings.Select(f => f.FixText)) : proposed;
            item.Comments = BuildComments(findings);

            // Date Identified = earliest date for the finding (the checklist's own rule date when it has one),
            // else the export date; scheduled completion counts from it by severity (AD-916, POAM-06).
            item.DateIdentified = Min(findings.Select(f => f.FirstDiscovered)) ?? options.ExportDate.Date;
            DateTime? estimated = Max(findings.Select(f => f.EstimatedCompletion));
            string milestoneText = string.IsNullOrWhiteSpace(proposed) ? (options.DefaultMilestone ?? string.Empty) : proposed;
            int days;
            DateTime? dueBySeverity = options.CompletionDays != null && options.CompletionDays.TryGetValue(item.RawSeverity, out days)
                ? item.DateIdentified.Value.Date.AddDays(days)
                : (DateTime?)null;

            if (status == Ongoing)
            {
                item.ScheduledCompletion = estimated ?? dueBySeverity;
                item.Milestones.Add(new EmassMilestone
                {
                    Description = milestoneText,
                    Status = "Open",
                    ScheduledCompletion = item.ScheduledCompletion
                });
            }
            else if (status == Completed)
            {
                item.CompletionDate = Max(findings.Select(f => f.LastObserved)) ?? options.ExportDate.Date;
                item.ScheduledCompletion = estimated ?? item.CompletionDate;
                item.Milestones.Add(new EmassMilestone
                {
                    Description = milestoneText,
                    Status = "Completed",
                    ScheduledCompletion = item.ScheduledCompletion,
                    CompletionDate = item.CompletionDate
                });
            }
            // Risk Accepted: the template allows no milestones.
            return item;
        }

        /// <summary>"STIG Title :: Version N, Release: R" (POAM-16).</summary>
        private static string SourceDetails(EmassPoamFinding finding)
        {
            string source = (finding.SourceName ?? string.Empty).Trim();
            string version = (finding.SourceVersion ?? string.Empty).Trim();
            string release = (finding.SourceRelease ?? string.Empty).Trim();
            if (!string.IsNullOrEmpty(version))
            { source += " :: Version " + version; }
            if (!string.IsNullOrEmpty(release))
            { source += ", " + (release.StartsWith("Release", StringComparison.OrdinalIgnoreCase) ? release : "Release: " + release); }
            return source.Trim();
        }

        /// <summary>Per host: Finding Details, "---", Comments (POAM-19); distinct values joined by a blank line.</summary>
        private static string BuildComments(List<EmassPoamFinding> findings)
        {
            StringBuilder text = new StringBuilder();
            Append(text, null, JoinDistinct(findings.Select(f =>
            {
                string details = (f.FindingDetails ?? string.Empty).Trim();
                string comments = (f.Comments ?? string.Empty).Trim();
                if (details.Length > 0 && comments.Length > 0)
                { return details + "\n---\n" + comments; }
                return details.Length > 0 ? details : comments;
            })));
            Append(text, "Predisposing conditions", JoinDistinct(findings.Select(f => f.PredisposingConditions)));
            Append(text, "Threat description", JoinDistinct(findings.Select(f => f.ThreatDescription)));
            return text.ToString().Trim();
        }

        private static void Append(StringBuilder text, string label, string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            { return; }
            if (text.Length > 0)
            { text.Append(Environment.NewLine).Append(Environment.NewLine); }
            if (label != null)
            { text.Append(label).Append(':').Append(Environment.NewLine); }
            text.Append(value.Trim());
        }

        private static string FirstNonEmpty(IEnumerable<string> values)
        {
            foreach (string value in values)
            {
                if (!string.IsNullOrWhiteSpace(value))
                { return value.Trim(); }
            }
            return string.Empty;
        }

        private static string JoinDistinct(IEnumerable<string> values)
        {
            return string.Join(Environment.NewLine + Environment.NewLine, Distinct(values));
        }

        private static List<string> Distinct(IEnumerable<string> values)
        {
            List<string> result = new List<string>();
            HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (string value in values)
            {
                if (string.IsNullOrWhiteSpace(value))
                { continue; }
                string trimmed = value.Trim();
                if (seen.Add(trimmed))
                { result.Add(trimmed); }
            }
            return result;
        }

        private static List<string> SplitList(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            { return new List<string>(); }
            return value.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(part => part.Trim())
                .Where(part => part.Length > 0)
                .ToList();
        }

        private static DateTime? Min(IEnumerable<DateTime?> values)
        {
            List<DateTime> list = values.Where(v => v.HasValue).Select(v => v.Value).ToList();
            return list.Count == 0 ? (DateTime?)null : list.Min();
        }

        private static DateTime? Max(IEnumerable<DateTime?> values)
        {
            List<DateTime> list = values.Where(v => v.HasValue).Select(v => v.Value).ToList();
            return list.Count == 0 ? (DateTime?)null : list.Max();
        }

        /// <summary>Reads a date stored by Vulnerator as DateTime, ticks, or text; null when absent or unreadable.</summary>
        public static DateTime? ToDate(object value)
        {
            if (value == null || value == DBNull.Value)
            { return null; }
            if (value is DateTime)
            { return (DateTime)value; }
            if (value is long)
            {
                long ticks = (long)value;
                return ticks > 0 && ticks < DateTime.MaxValue.Ticks ? new DateTime(ticks) : (DateTime?)null;
            }
            string text = value.ToString().Trim();
            if (text.Length == 0)
            { return null; }
            long parsedTicks;
            if (long.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out parsedTicks) &&
                parsedTicks > 0 && parsedTicks < DateTime.MaxValue.Ticks)
            { return new DateTime(parsedTicks); }
            DateTime parsed;
            string[] formats = { "yyyy-MM-dd", "yyyy-MM-dd HH:mm:ss", "yyyy-MM-ddTHH:mm:ss", "MM/dd/yyyy", "M/d/yyyy", "yyyy/MM/dd" };
            if (DateTime.TryParseExact(text, formats, CultureInfo.InvariantCulture, DateTimeStyles.None, out parsed))
            { return parsed; }
            if (DateTime.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.None, out parsed))
            { return parsed; }
            return null;
        }
    }
}
