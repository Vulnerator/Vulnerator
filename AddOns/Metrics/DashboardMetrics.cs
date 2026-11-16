// Copyright (c) 2026 Hector L. Bones. MIT License (see LICENSE in the repository root).
// The calculations behind the dashboard views. Call EffectiveStatusResolver.Resolve on the findings first.
using System;
using System.Collections.Generic;
using System.Linq;

namespace Vulnerator.Metrics
{
    public enum HostSourceFilter
    {
        All,
        Acas,
        StigAndScap
    }

    /// <summary>Counts per level (index = (int)SeverityLevel) and per CAT (index 0 = I ... 3 = IV).</summary>
    public sealed class SeverityCounts
    {
        public SeverityCounts(string label)
        {
            Label = label;
        }

        /// <summary>"All", "ACAS", "STIG", "SCAP" or "Other".</summary>
        public string Label { get; }

        public int[] OpenByLevel { get; } = new int[6];
        public int[] OpenByCat { get; } = new int[4];
        public int[] UnverifiedByLevel { get; } = new int[6];
        public int Open => OpenByLevel.Sum();
        public int Unverified => UnverifiedByLevel.Sum();
    }

    public sealed class HostRisk
    {
        public string HostKey { get; set; }
        public long? HardwareId { get; set; }
        public string HostName { get; set; }
        public int[] OpenByLevel { get; } = new int[6];
        public int Unverified { get; set; }

        /// <summary>Open findings excluding Very Low (informational) and Unknown.</summary>
        public int OpenRated => OpenByLevel[0] + OpenByLevel[1] + OpenByLevel[2] + OpenByLevel[3];
    }

    public sealed class FamilyCompliance
    {
        public string Family { get; set; }
        public string Name { get; set; }
        public int NotAFinding { get; set; }
        public int Open { get; set; }
        public int NotApplicable { get; set; }
        public int NotReviewed { get; set; }

        /// <summary>Not a Finding / (Not a Finding + Open) x 100 (approved 2026-11-06); null when nothing assessed.</summary>
        public double? CompliantPercent => NotAFinding + Open == 0 ? (double?)null : NotAFinding * 100.0 / (NotAFinding + Open);
    }

    public sealed class PoamAgingReport
    {
        public static readonly string[] BucketNames = { "0-30 days", "31-90 days", "91-180 days", "181-365 days", "Over 365 days" };

        /// <summary>[bucket, level]: open (Ongoing) items by age since identified and severity.</summary>
        public int[,] Buckets { get; } = new int[5, 6];

        public IList<MetricPoamItem> Overdue { get; } = new List<MetricPoamItem>();
        public IList<MetricPoamItem> DueWithin30Days { get; } = new List<MetricPoamItem>();
        public int Ongoing { get; set; }
        public int RiskAccepted { get; set; }
        public int Completed { get; set; }

        public static int BucketOf(int ageDays)
        {
            if (ageDays <= 30) return 0;
            if (ageDays <= 90) return 1;
            if (ageDays <= 180) return 2;
            if (ageDays <= 365) return 3;
            return 4;
        }
    }

    /// <summary>One hardware record inside a Coverage row, and where it has data.</summary>
    public sealed class CoverageMember
    {
        public long HardwareId { get; set; }
        public string HostName { get; set; }
        public string OperatingSystem { get; set; }
        public bool HasAcas { get; set; }
        public bool HasStig { get; set; }

        /// <summary>"W01.Contoso.com (ACAS)", "W01.Contoso (STIG)", "W01 (ACAS, STIG)" or "W01 (no data)".</summary>
        public string Describe()
        {
            var sources = new List<string>();
            if (HasAcas) sources.Add("ACAS");
            if (HasStig) sources.Add("STIG");
            return HostName + " (" + (sources.Count == 0 ? "no data" : string.Join(", ", sources)) + ")";
        }
    }

    /// <summary>A device: one hardware record, or several matched by short name or linked by the user.</summary>
    public sealed class AssetCoverage
    {
        public long HardwareId { get; set; }
        public string HostName { get; set; }
        public string OperatingSystem { get; set; } = string.Empty;
        public IList<CoverageMember> Members { get; set; } = new List<CoverageMember>();
        /// <summary>Why several records are one device: "short name", "linked", or empty for a single record.</summary>
        public string MatchedBy { get; set; } = string.Empty;
        public bool IsMatched => Members.Count > 1;
        public DateTime? LastAcasScan { get; set; }
        public int StigCount { get; set; }
        public DateTime? LastChecklist { get; set; }
        public bool HasAcas { get; set; }
        public bool HasStig => StigCount > 0;
        public bool AcasStale { get; set; }
        public bool HasGap => !HasAcas || !HasStig || AcasStale;

        /// <summary>Each record and its sources, for example "W01.Contoso.com (ACAS); W01.Contoso (STIG)".</summary>
        public string Seen => string.Join("; ", Members.Select(m => m.Describe()));

        /// <summary>"No ACAS scan or STIG checklist", "No ACAS scan", "No STIG checklist", "ACAS scan older than 30 days", "Covered".</summary>
        public string Gap
        {
            get
            {
                if (!HasAcas && !HasStig) return "No ACAS scan or STIG checklist";
                var parts = new List<string>();
                if (!HasAcas) parts.Add("No ACAS scan");
                if (AcasStale) parts.Add("ACAS scan older than " + Definitions.StaleScanDays + " days");
                if (!HasStig) parts.Add("No STIG checklist");
                return parts.Count == 0 ? "Covered" : string.Join("; ", parts);
            }
        }
    }

    public enum StigCurrencyState
    {
        Current,
        Outdated,
        Unknown
    }

    public sealed class StigCurrencyRow
    {
        public MetricSubmission Submission { get; set; }
        public StigCurrencyState State { get; set; }
    }

    public sealed class StigCurrencyReport
    {
        public IList<StigCurrencyRow> Rows { get; } = new List<StigCurrencyRow>();
        public DateTime? LibraryImported { get; set; }

        /// <summary>No library import, or older than <see cref="Definitions.StaleLibraryDays"/>: "current" may not be current.</summary>
        public bool LibraryStale { get; set; }

        public string LibraryNote { get; set; }
        public int Outdated => Rows.Count(r => r.State == StigCurrencyState.Outdated);
    }

    public sealed class IavmRow
    {
        public string Type { get; set; }
        public string Iavm { get; set; }
        public SeverityLevel Level { get; set; } = SeverityLevel.Unknown;
        public ISet<string> Hosts { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        public ISet<string> Plugins { get; } = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        /// <summary>The titles of the open findings (plugin names) that reference the IAVM.</summary>
        public ISet<string> Titles { get; } = new SortedSet<string>(StringComparer.OrdinalIgnoreCase);
        public int OpenFindings { get; set; }
        public int UnverifiedFindings { get; set; }
        public DateTime? FirstSeen { get; set; }
    }

    public static class DashboardMetrics
    {
        /// <summary>View 1: open findings by severity level and CAT, overall ("All") and per source group.</summary>
        public static IList<SeverityCounts> OpenBySeverity(IEnumerable<MetricFinding> findings)
        {
            var all = new SeverityCounts("All");
            var bySource = new Dictionary<SourceGroup, SeverityCounts>();
            foreach (MetricFinding f in findings)
            {
                if (f.EffectiveStatus != EffectiveStatus.Open && f.EffectiveStatus != EffectiveStatus.Unverified) continue;
                SeverityCounts source;
                if (!bySource.TryGetValue(f.Source, out source))
                {
                    source = new SeverityCounts(Definitions.SourceGroupName(f.Source));
                    bySource[f.Source] = source;
                }
                foreach (SeverityCounts counts in new[] { all, source })
                {
                    if (f.EffectiveStatus == EffectiveStatus.Unverified)
                    {
                        counts.UnverifiedByLevel[(int)f.Level]++;
                        continue;
                    }
                    counts.OpenByLevel[(int)f.Level]++;
                    int cat = CatIndex(f.Cat);
                    if (cat >= 0) counts.OpenByCat[cat]++;
                }
            }
            var result = new List<SeverityCounts> { all };
            result.AddRange(bySource.OrderBy(p => p.Key).Select(p => p.Value));
            return result;
        }

        /// <summary>View 2: hosts ranked worst-first (Very High, then High, Moderate, Low counts; not by total).</summary>
        public static IList<HostRisk> TopHosts(IEnumerable<MetricFinding> findings, HostSourceFilter filter, int count)
        {
            var hosts = new Dictionary<string, HostRisk>();
            foreach (MetricFinding f in findings)
            {
                if (f.HostKey == null || !Matches(f.Source, filter)) continue;
                if (f.EffectiveStatus != EffectiveStatus.Open && f.EffectiveStatus != EffectiveStatus.Unverified) continue;
                HostRisk host;
                if (!hosts.TryGetValue(f.HostKey, out host))
                {
                    host = new HostRisk { HostKey = f.HostKey, HardwareId = f.HardwareId, HostName = f.HostName };
                    hosts[f.HostKey] = host;
                }
                if (f.EffectiveStatus == EffectiveStatus.Unverified) host.Unverified++;
                else host.OpenByLevel[(int)f.Level]++;
            }
            return hosts.Values
                .Where(h => h.OpenRated > 0)
                .OrderByDescending(h => h.OpenByLevel[0])
                .ThenByDescending(h => h.OpenByLevel[1])
                .ThenByDescending(h => h.OpenByLevel[2])
                .ThenByDescending(h => h.OpenByLevel[3])
                .ThenBy(h => h.HostName, StringComparer.OrdinalIgnoreCase)
                .Take(Math.Max(0, count))
                .ToList();
        }

        /// <summary>View 3: compliance per Rev 5 family from STIG and SCAP results (ACAS has no CCIs). All 20 families.</summary>
        public static IList<FamilyCompliance> ComplianceByFamily(IEnumerable<MetricFinding> findings)
        {
            var families = Definitions.Rev5Families.ToDictionary(
                p => p.Key, p => new FamilyCompliance { Family = p.Key, Name = p.Value }, StringComparer.OrdinalIgnoreCase);
            foreach (MetricFinding f in findings)
            {
                if (f.Source != SourceGroup.Stig && f.Source != SourceGroup.Scap) continue;
                foreach (string code in f.NistControls.Select(Definitions.FamilyOf).Where(c => c != null).Distinct(StringComparer.OrdinalIgnoreCase))
                {
                    FamilyCompliance family = families[code];
                    switch (f.EffectiveStatus)
                    {
                        case EffectiveStatus.Open: family.Open++; break;
                        case EffectiveStatus.NotAFinding: family.NotAFinding++; break;
                        case EffectiveStatus.NotApplicable: family.NotApplicable++; break;
                        case EffectiveStatus.NotReviewed: family.NotReviewed++; break;
                    }
                }
            }
            return Definitions.Rev5Families.Select(p => families[p.Key]).ToList();
        }

        /// <summary>View 4: POA&amp;M aging (open = Ongoing), overdue and due within 30 days.</summary>
        public static PoamAgingReport PoamAging(IEnumerable<MetricPoamItem> items, DateTime today)
        {
            DateTime day = today.Date;
            var report = new PoamAgingReport();
            foreach (MetricPoamItem item in items)
            {
                string status = (item.Status ?? string.Empty).Trim();
                if (status.Equals("Completed", StringComparison.OrdinalIgnoreCase)) { report.Completed++; continue; }
                if (status.Equals("Risk Accepted", StringComparison.OrdinalIgnoreCase)) { report.RiskAccepted++; continue; }
                if (!status.Equals("Ongoing", StringComparison.OrdinalIgnoreCase)) continue;
                report.Ongoing++;
                int age = item.DateIdentified.HasValue ? Math.Max(0, (int)(day - item.DateIdentified.Value.Date).TotalDays) : 0;
                report.Buckets[PoamAgingReport.BucketOf(age), (int)item.Level]++;
                if (item.ScheduledCompletion.HasValue)
                {
                    DateTime due = item.ScheduledCompletion.Value.Date;
                    if (due < day) report.Overdue.Add(item);
                    else if (due <= day.AddDays(30)) report.DueWithin30Days.Add(item);
                }
            }
            SortByDue(report.Overdue);
            SortByDue(report.DueWithin30Days);
            return report;
        }

        /// <summary>View 6: per hardware asset, ACAS and STIG coverage and gaps (ACAS older than 30 days = stale). No matching.</summary>
        public static IList<AssetCoverage> Coverage(IEnumerable<MetricHardware> hardware, IEnumerable<MetricFinding> findings,
            IEnumerable<MetricSubmission> submissions, DateTime today)
        {
            return Coverage(hardware, findings, submissions, today, DeviceMatchSettings.None);
        }

        /// <summary>
        /// View 6: per device, ACAS and STIG coverage and gaps. Hardware records matched by <paramref name="matching"/>
        /// (same short name, or linked by the user) are one device: an ACAS scan of W01.Contoso.com and a checklist
        /// of W01.Contoso cover the same device.
        /// </summary>
        public static IList<AssetCoverage> Coverage(IEnumerable<MetricHardware> hardware, IEnumerable<MetricFinding> findings,
            IEnumerable<MetricSubmission> submissions, DateTime today, DeviceMatchSettings matching)
        {
            var lastAcas = new Dictionary<long, DateTime>();
            var stigs = new Dictionary<long, HashSet<string>>();
            var lastStig = new Dictionary<long, DateTime>();
            foreach (MetricFinding f in findings)
            {
                if (!f.HardwareId.HasValue) continue;
                long id = f.HardwareId.Value;
                if (f.Source == SourceGroup.Acas)
                {
                    if (f.LastObserved.HasValue) Later(lastAcas, id, f.LastObserved.Value);
                    else if (!lastAcas.ContainsKey(id)) lastAcas[id] = DateTime.MinValue;
                }
                else if (f.Source == SourceGroup.Stig || f.Source == SourceGroup.Scap)
                {
                    AddStig(stigs, id, f.SourceName);
                    if (f.LastObserved.HasValue) Later(lastStig, id, f.LastObserved.Value);
                }
            }
            foreach (MetricSubmission s in submissions ?? Enumerable.Empty<MetricSubmission>())
            {
                if (!s.HardwareId.HasValue) continue;
                AddStig(stigs, s.HardwareId.Value, s.StigName);
                Later(lastStig, s.HardwareId.Value, s.ImportedOn);
            }

            DateTime staleBefore = today.Date.AddDays(-Definitions.StaleScanDays);
            var result = new List<AssetCoverage>();
            foreach (DeviceGroup group in DeviceMatching.Group(hardware.ToList(), matching))
            {
                var row = new AssetCoverage { MatchedBy = group.MatchedBy };
                var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                DateTime? newestAcas = null;
                bool undatedAcas = false;
                foreach (MetricHardware h in group.Members.OrderBy(m => m.HostName, StringComparer.OrdinalIgnoreCase))
                {
                    DateTime acas, stig;
                    HashSet<string> stigNames;
                    var member = new CoverageMember { HardwareId = h.Id, HostName = h.HostName, OperatingSystem = h.OperatingSystem ?? string.Empty };
                    if (lastAcas.TryGetValue(h.Id, out acas))
                    {
                        member.HasAcas = true;
                        // DateTime.MinValue marks ACAS results without a date: covered, but counted as stale.
                        if (acas == DateTime.MinValue) undatedAcas = true;
                        else if (!newestAcas.HasValue || acas > newestAcas.Value) newestAcas = acas;
                    }
                    if (stigs.TryGetValue(h.Id, out stigNames))
                    {
                        member.HasStig = stigNames.Count > 0;
                        names.UnionWith(stigNames);
                    }
                    if (lastStig.TryGetValue(h.Id, out stig) && (!row.LastChecklist.HasValue || stig > row.LastChecklist.Value)) row.LastChecklist = stig;
                    row.Members.Add(member);
                }
                row.HasAcas = row.Members.Any(m => m.HasAcas);
                row.LastAcasScan = newestAcas;
                row.AcasStale = row.HasAcas && (!newestAcas.HasValue || newestAcas.Value < staleBefore);
                if (undatedAcas && !newestAcas.HasValue) row.AcasStale = true;
                row.StigCount = names.Count;
                // The device's name: the longest (most complete) host name; its record id is the first member's.
                CoverageMember primary = row.Members.OrderByDescending(m => (m.HostName ?? string.Empty).Length).ThenBy(m => m.HostName, StringComparer.OrdinalIgnoreCase).First();
                row.HostName = primary.HostName;
                row.HardwareId = primary.HardwareId;
                row.OperatingSystem = string.Join("; ", row.Members.Select(m => (m.OperatingSystem ?? string.Empty).Trim()).Where(o => o.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase));
                result.Add(row);
            }
            return result.OrderByDescending(r => r.HasGap).ThenBy(r => r.HostName, StringComparer.OrdinalIgnoreCase).ToList();
        }

        /// <summary>
        /// View 7: the newest submission per host and STIG, current or outdated against the newest release Vulnerator has
        /// loaded, plus whether the DISA library import is old enough that "current" may not be current.
        /// </summary>
        public static StigCurrencyReport StigCurrency(IEnumerable<MetricSubmission> submissions, DateTime? libraryImported, DateTime today)
        {
            var report = new StigCurrencyReport { LibraryImported = libraryImported };
            if (!libraryImported.HasValue)
            {
                report.LibraryStale = true;
                report.LibraryNote = "No DISA STIG library has been imported; releases are compared with the checklists only.";
            }
            else if (libraryImported.Value.Date < today.Date.AddDays(-Definitions.StaleLibraryDays))
            {
                report.LibraryStale = true;
                report.LibraryNote = "The DISA STIG library was imported on " + libraryImported.Value.ToString("yyyy-MM-dd") +
                                     ", more than " + Definitions.StaleLibraryDays + " days ago; import the current library to check for newer releases.";
            }
            else
            {
                report.LibraryNote = "Compared with the DISA STIG library imported on " + libraryImported.Value.ToString("yyyy-MM-dd") + ".";
            }

            IEnumerable<MetricSubmission> newest = submissions
                .GroupBy(s => (s.HardwareId.HasValue ? "hw" + s.HardwareId.Value : (s.HostName ?? string.Empty).ToLowerInvariant()) + "|" + s.StigName.ToLowerInvariant())
                .Select(g => g.OrderByDescending(s => s.ImportedOn).First());
            foreach (MetricSubmission s in newest.OrderBy(s => s.HostName, StringComparer.OrdinalIgnoreCase).ThenBy(s => s.StigName, StringComparer.OrdinalIgnoreCase))
            {
                StigCurrencyState state = string.IsNullOrEmpty(s.LatestVersion) ? StigCurrencyState.Unknown
                    : s.IsOutdated ? StigCurrencyState.Outdated : StigCurrencyState.Current;
                report.Rows.Add(new StigCurrencyRow { Submission = s, State = state });
            }
            return report;
        }

        /// <summary>
        /// View 8: active IAVMs (IAVA, IAVB, IAVT) - at least one open ACAS finding references them. Severity is the worst
        /// of DISA's stig_severity (when the plugin has one) or the finding's level. Unverified findings are counted but
        /// do not make an IAVM active.
        /// </summary>
        public static IList<IavmRow> ActiveIavms(IEnumerable<MetricFinding> findings)
        {
            var rows = new Dictionary<string, IavmRow>(StringComparer.OrdinalIgnoreCase);
            foreach (MetricFinding f in findings)
            {
                if (f.EffectiveStatus != EffectiveStatus.Open && f.EffectiveStatus != EffectiveStatus.Unverified) continue;
                foreach (string reference in f.References)
                {
                    KeyValuePair<string, string>? iavm = Definitions.ParseIavm(reference);
                    if (!iavm.HasValue) continue;
                    string key = iavm.Value.Key + ":" + iavm.Value.Value;
                    IavmRow row;
                    if (!rows.TryGetValue(key, out row))
                    {
                        row = new IavmRow { Type = iavm.Value.Key, Iavm = iavm.Value.Value };
                        rows[key] = row;
                    }
                    if (f.EffectiveStatus == EffectiveStatus.Unverified)
                    {
                        row.UnverifiedFindings++;
                        continue;
                    }
                    row.OpenFindings++;
                    if (f.HostKey != null) row.Hosts.Add(f.HostName);
                    if (!string.IsNullOrEmpty(f.VulnerabilityId)) row.Plugins.Add(f.VulnerabilityId);
                    if (!string.IsNullOrWhiteSpace(f.Title)) row.Titles.Add(f.Title.Trim());
                    SeverityLevel level = Definitions.LevelOfCat(f.SecondarySeverity);
                    if (level == SeverityLevel.Unknown || f.Level < level) level = f.Level;
                    if (level < row.Level) row.Level = level;
                    DateTime? seen = f.FirstDiscovered ?? f.LastObserved;
                    if (seen.HasValue && (!row.FirstSeen.HasValue || seen.Value < row.FirstSeen.Value)) row.FirstSeen = seen;
                }
            }
            return rows.Values.Where(r => r.OpenFindings > 0)
                .OrderBy(r => r.Level).ThenBy(r => Array.IndexOf(Definitions.IavmTypes, r.Type)).ThenBy(r => r.Iavm, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }

        /// <summary>View 8 summary: active IAVM counts per type (IAVA, IAVB, IAVT) and level.</summary>
        public static IDictionary<string, int[]> IavmCounts(IEnumerable<IavmRow> rows)
        {
            var counts = Definitions.IavmTypes.ToDictionary(t => t, t => new int[6], StringComparer.OrdinalIgnoreCase);
            foreach (IavmRow row in rows) counts[row.Type][(int)row.Level]++;
            return counts;
        }

        private static bool Matches(SourceGroup source, HostSourceFilter filter)
        {
            switch (filter)
            {
                case HostSourceFilter.Acas: return source == SourceGroup.Acas;
                case HostSourceFilter.StigAndScap: return source == SourceGroup.Stig || source == SourceGroup.Scap;
                default: return true;
            }
        }

        private static int CatIndex(string cat)
        {
            switch ((cat ?? string.Empty).Trim().ToUpperInvariant())
            {
                case "I": return 0;
                case "II": return 1;
                case "III": return 2;
                case "IV": return 3;
                default: return -1;
            }
        }

        private static void Later(Dictionary<long, DateTime> dates, long id, DateTime value)
        {
            DateTime known;
            if (!dates.TryGetValue(id, out known) || value > known) dates[id] = value;
        }

        private static void AddStig(Dictionary<long, HashSet<string>> stigs, long id, string name)
        {
            if (string.IsNullOrWhiteSpace(name)) return;
            HashSet<string> set;
            if (!stigs.TryGetValue(id, out set)) stigs[id] = set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            set.Add(name.Trim());
        }

        private static void SortByDue(IList<MetricPoamItem> items)
        {
            List<MetricPoamItem> sorted = items.OrderBy(i => i.ScheduledCompletion).ThenBy(i => i.Level).ToList();
            items.Clear();
            foreach (MetricPoamItem item in sorted) items.Add(item);
        }
    }
}
