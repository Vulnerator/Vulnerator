// Copyright (c) 2026 Hector L. Bones. MIT License (see LICENSE in the repository root).
// Metrics layer tests with synthetic data. Exit code 0 = all passed; failures print as ::error:: lines.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Vulnerator.Metrics;

internal static class Program
{
    private static int passed;
    private static int failed;
    private static readonly DateTime Today = new DateTime(2026, 11, 6);

    private static int Main()
    {
        try
        {
            Definitions();
            EffectiveStatus();
            Severity();
            TopHosts();
            Compliance();
            PoamAging();
            Coverage();
            DeviceMatchingChecks();
            StigCurrency();
            Iavms();
            Trend();
        }
        catch (Exception ex)
        {
            Fail("unexpected exception", ex.ToString());
        }
        Console.WriteLine(passed + " checks passed, " + failed + " failed.");
        return failed == 0 ? 0 : 1;
    }

    private static void Definitions()
    {
        Check(Vulnerator.Metrics.Definitions.LevelOf("Very High", "I") == SeverityLevel.VeryHigh, "level: Very High from the core", null);
        Check(Vulnerator.Metrics.Definitions.LevelOf("", "I") == SeverityLevel.High, "level: CAT I = High", null);
        Check(Vulnerator.Metrics.Definitions.LevelOf("", "IV") == SeverityLevel.VeryLow, "level: CAT IV = Very Low", null);
        Check(Vulnerator.Metrics.Definitions.LevelOf("Medium", "") == SeverityLevel.Moderate, "level: Medium = Moderate", null);
        Check(Vulnerator.Metrics.Definitions.FamilyOf("AC-2(1)") == "AC" && Vulnerator.Metrics.Definitions.FamilyOf("si-2") == "SI", "family of a control", null);
        Check(Vulnerator.Metrics.Definitions.FamilyOf("XX-1") == null && Vulnerator.Metrics.Definitions.FamilyOf("") == null, "unknown family", null);
        Check(Vulnerator.Metrics.Definitions.Rev5Families.Count == 20, "20 Rev 5 families", null);
        Check(Vulnerator.Metrics.Definitions.SourceGroupOf("CKL") == SourceGroup.Stig && Vulnerator.Metrics.Definitions.SourceGroupOf("XCCDF") == SourceGroup.Scap
              && Vulnerator.Metrics.Definitions.SourceGroupOf("ACAS") == SourceGroup.Acas && Vulnerator.Metrics.Definitions.SourceGroupOf("WASSP") == SourceGroup.Other, "source groups", null);
        KeyValuePair<string, string>? iavm = Vulnerator.Metrics.Definitions.ParseIavm("IAVA:2026-A-0001");
        Check(iavm.HasValue && iavm.Value.Key == "IAVA" && iavm.Value.Value == "2026-A-0001", "IAVM reference parsed", null);
        Check(!Vulnerator.Metrics.Definitions.ParseIavm("CVE:CVE-2026-1").HasValue, "CVE is not an IAVM", null);
    }

    private static void EffectiveStatus()
    {
        var list = new List<MetricFinding>
        {
            Acas(1, "hostA", "100", "High", Today.AddDays(-20)),     // older scan only
            Acas(1, "hostA", "101", "High", Today.AddDays(-5)),      // newest scan
            Acas(1, "hostA", "102", "Low", Today.AddDays(-5).AddHours(2)), // same scan, a bit later
            Acas(2, "hostB", "100", "High", Today.AddDays(-20)),     // only one scan of host B
            Stig(1, "hostA", "V-1", "I", "Open", Today.AddDays(-60))
        };
        EffectiveStatusResolver.Resolve(list);
        Check(list[0].EffectiveStatus == Vulnerator.Metrics.EffectiveStatus.Unverified, "ACAS finding missing from the newest scan: Unverified", list[0].EffectiveStatus.ToString());
        Check(list[1].EffectiveStatus == Vulnerator.Metrics.EffectiveStatus.Open && list[2].EffectiveStatus == Vulnerator.Metrics.EffectiveStatus.Open, "ACAS findings in the newest scan: Open", null);
        Check(list[3].EffectiveStatus == Vulnerator.Metrics.EffectiveStatus.Open, "host with one scan: Open", null);
        Check(list[4].EffectiveStatus == Vulnerator.Metrics.EffectiveStatus.Open, "old STIG finding stays Open", null);
    }

    private static void Severity()
    {
        var list = new List<MetricFinding>
        {
            Acas(1, "h1", "1", "Very High", Today), Acas(1, "h1", "2", "High", Today), Acas(1, "h1", "3", "Very Low", Today),
            Stig(1, "h1", "V-1", "I", "Open", Today), Stig(1, "h1", "V-2", "II", "Not a Finding", Today),
            Acas(2, "h2", "1", "High", Today.AddDays(-30)), Acas(2, "h2", "9", "Low", Today)
        };
        list[0].Cat = "I";
        EffectiveStatusResolver.Resolve(list);
        IList<SeverityCounts> counts = DashboardMetrics.OpenBySeverity(list);
        SeverityCounts all = counts[0];
        Check(all.Label == "All" && all.OpenByLevel[0] == 1 && all.OpenByLevel[1] == 2 && all.OpenByLevel[3] == 1 && all.OpenByLevel[4] == 1, "open by level", string.Join(",", all.OpenByLevel));
        Check(all.Unverified == 1 && all.UnverifiedByLevel[1] == 1, "unverified counted separately", all.Unverified.ToString());
        SeverityCounts acas = counts.First(c => c.Label == "ACAS");
        SeverityCounts stig = counts.First(c => c.Label == "STIG");
        Check(acas.Open == 4 && stig.Open == 1 && stig.OpenByCat[0] == 1, "per source", acas.Open + "/" + stig.Open);
    }

    private static void TopHosts()
    {
        var list = new List<MetricFinding>();
        for (int i = 0; i < 10; i++) list.Add(Acas(1, "manyHigh", "h" + i, "High", Today));
        list.Add(Acas(2, "oneCritical", "c", "Very High", Today));
        list.Add(Acas(3, "infoOnly", "i", "Very Low", Today));
        list.Add(Stig(4, "stigHost", "V-1", "II", "Open", Today));
        list.Add(new MetricFinding { FindingType = "CKL", SoftwareName = "App", Asset = "App", Cat = "I", Status = "Open", RuleId = "x" });
        EffectiveStatusResolver.Resolve(list);
        IList<HostRisk> top = DashboardMetrics.TopHosts(list, HostSourceFilter.All, 10);
        Check(top.Count == 3 && top[0].HostName == "oneCritical" && top[1].HostName == "manyHigh" && top[2].HostName == "stigHost",
            "worst-first ranking; info-only and software-only left out", string.Join(",", top.Select(t => t.HostName)));
        Check(DashboardMetrics.TopHosts(list, HostSourceFilter.Acas, 10).Count == 2, "ACAS filter", null);
        Check(DashboardMetrics.TopHosts(list, HostSourceFilter.StigAndScap, 10).Single().HostName == "stigHost", "STIG filter", null);
        Check(DashboardMetrics.TopHosts(list, HostSourceFilter.All, 1).Count == 1, "top N", null);
    }

    private static void Compliance()
    {
        var list = new List<MetricFinding>
        {
            Stig(1, "h", "V-1", "II", "Not a Finding", Today, "AC-2", "AC-3"),
            Stig(1, "h", "V-2", "II", "Not a Finding", Today, "AC-2(1)"),
            Stig(1, "h", "V-3", "II", "Not a Finding", Today, "AC-6"),
            Stig(1, "h", "V-4", "I", "Open", Today, "AC-7", "SI-2"),
            Stig(1, "h", "V-5", "II", "Not Applicable", Today, "AC-8"),
            Stig(1, "h", "V-6", "II", "Not Reviewed", Today, "AC-9"),
            Acas(1, "h", "1", "High", Today)
        };
        list[6].NistControls.Add("RA-5");
        list[0].FindingType = "XCCDF";
        EffectiveStatusResolver.Resolve(list);
        IList<FamilyCompliance> families = DashboardMetrics.ComplianceByFamily(list);
        FamilyCompliance ac = families.First(f => f.Family == "AC");
        Check(families.Count == 20, "all 20 families listed", families.Count.ToString());
        Check(ac.NotAFinding == 3 && ac.Open == 1 && ac.NotApplicable == 1 && ac.NotReviewed == 1, "AC counts (a rule in AC-2 and AC-3 counts once)", ac.NotAFinding + "/" + ac.Open);
        Check(Math.Abs(ac.CompliantPercent.Value - 75.0) < 0.001, "AC compliant 75% = NaF / (NaF + Open)", ac.CompliantPercent.ToString());
        Check(families.First(f => f.Family == "SI").CompliantPercent == 0.0, "SI 0%", null);
        Check(families.First(f => f.Family == "RA").CompliantPercent == null, "ACAS not counted (RA not assessed)", null);
    }

    private static void PoamAging()
    {
        var items = new List<MetricPoamItem>
        {
            Poam("Ongoing", "High", Today.AddDays(-10), Today.AddDays(20)),
            Poam("Ongoing", "Very High", Today.AddDays(-100), Today.AddDays(-5)),
            Poam("Ongoing", "Moderate", Today.AddDays(-400), Today.AddDays(-200)),
            Poam("Ongoing", "Low", Today.AddDays(-31), Today.AddDays(60)),
            Poam("Risk Accepted", "Low", Today.AddDays(-500), null),
            Poam("Completed", "High", Today.AddDays(-50), Today.AddDays(-40))
        };
        PoamAgingReport report = DashboardMetrics.PoamAging(items, Today);
        Check(report.Ongoing == 4 && report.RiskAccepted == 1 && report.Completed == 1, "status counts", report.Ongoing + "/" + report.RiskAccepted + "/" + report.Completed);
        Check(report.Buckets[0, (int)SeverityLevel.High] == 1 && report.Buckets[2, (int)SeverityLevel.VeryHigh] == 1
              && report.Buckets[4, (int)SeverityLevel.Moderate] == 1 && report.Buckets[1, (int)SeverityLevel.Low] == 1, "age buckets", null);
        Check(report.Overdue.Count == 2 && report.Overdue[0].Level == SeverityLevel.Moderate, "overdue, oldest due first", report.Overdue.Count.ToString());
        Check(report.DueWithin30Days.Count == 1 && report.DueWithin30Days[0].Level == SeverityLevel.High, "due within 30 days", null);
    }

    private static void Coverage()
    {
        var hardware = new List<MetricHardware>
        {
            new MetricHardware { Id = 1, HostName = "covered" },
            new MetricHardware { Id = 2, HostName = "stale" },
            new MetricHardware { Id = 3, HostName = "nothing" },
            new MetricHardware { Id = 4, HostName = "stigOnly" }
        };
        var findings = new List<MetricFinding>
        {
            Acas(1, "covered", "1", "High", Today.AddDays(-3)), Stig(1, "covered", "V-1", "II", "Open", Today.AddDays(-10)),
            Acas(2, "stale", "1", "High", Today.AddDays(-45))
        };
        findings[1].SourceName = "Windows Server STIG";
        var submissions = new List<MetricSubmission> { new MetricSubmission { HardwareId = 4, StigName = "Browser STIG", ImportedOn = Today.AddDays(-2) } };
        IList<AssetCoverage> rows = DashboardMetrics.Coverage(hardware, findings, submissions, Today);
        AssetCoverage covered = rows.First(r => r.HostName == "covered"), stale = rows.First(r => r.HostName == "stale"),
            nothing = rows.First(r => r.HostName == "nothing"), stigOnly = rows.First(r => r.HostName == "stigOnly");
        Check(!covered.HasGap && covered.Gap == "Covered" && covered.StigCount == 1, "covered asset", covered.Gap);
        Check(stale.AcasStale && stale.Gap == "ACAS scan older than 30 days; No STIG checklist", "stale ACAS and no checklist", stale.Gap);
        Check(nothing.Gap == "No ACAS scan or STIG checklist", "no coverage", nothing.Gap);
        Check(stigOnly.Gap == "No ACAS scan" && stigOnly.StigCount == 1, "checklist known from submissions", stigOnly.Gap);
        Check(rows.Last().HostName == "covered", "gaps listed first", rows.Last().HostName);
    }

    private static void DeviceMatchingChecks()
    {
        Check(DeviceMatching.ShortName("W01.Contoso.com") == "w01" && DeviceMatching.ShortName("W01") == "w01" && DeviceMatching.ShortName("10.1.2.3") == "10.1.2.3",
            "short name: first label, IP addresses kept whole", DeviceMatching.ShortName("10.1.2.3"));
        var hardware = new List<MetricHardware>
        {
            new MetricHardware { Id = 1, HostName = "W01.Contoso.com", OperatingSystem = "Microsoft Windows Server 2022" },
            new MetricHardware { Id = 2, HostName = "W01.Contoso" },
            new MetricHardware { Id = 3, HostName = "DB-PRIMARY" },
            new MetricHardware { Id = 4, HostName = "sql01.contoso.com", OperatingSystem = "Red Hat Enterprise Linux 9" },
            new MetricHardware { Id = 5, HostName = "10.1.2.3" },
            new MetricHardware { Id = 6, HostName = "10.1.2.4" }
        };
        var findings = new List<MetricFinding>
        {
            Acas(1, "W01.Contoso.com", "1", "High", Today.AddDays(-3)), Stig(2, "W01.Contoso", "V-1", "II", "Open", Today.AddDays(-5)),
            Stig(3, "DB-PRIMARY", "V-2", "II", "Open", Today.AddDays(-5)), Acas(4, "sql01.contoso.com", "1", "High", Today.AddDays(-50))
        };
        findings[1].SourceName = "Windows Server STIG";
        findings[2].SourceName = "SQL Server STIG";

        IList<AssetCoverage> none = DashboardMetrics.Coverage(hardware, findings, null, Today, DeviceMatchSettings.None);
        Check(none.Count == 6 && none.All(r => !r.IsMatched), "no matching: one row per hardware record", none.Count.ToString());

        var settings = new DeviceMatchSettings();
        IList<AssetCoverage> rows = DashboardMetrics.Coverage(hardware, findings, null, Today, settings);
        AssetCoverage w01 = rows.Single(r => r.Members.Any(m => m.HostName == "W01.Contoso"));
        Check(rows.Count == 5 && w01.IsMatched && w01.HostName == "W01.Contoso.com" && w01.MatchedBy == "short name", "short name: ACAS W01.Contoso.com and STIG W01.Contoso are one device",
            string.Join(" | ", rows.Select(r => r.HostName + "=" + r.Seen)));
        Check(w01.HasAcas && w01.HasStig && !w01.HasGap && w01.Gap == "Covered", "the matched device is covered by both", w01.Gap);
        Check(w01.Seen == "W01.Contoso (STIG); W01.Contoso.com (ACAS)", "each record shows its source", w01.Seen);
        Check(w01.OperatingSystem == "Microsoft Windows Server 2022", "the device takes the operating system from its records", w01.OperatingSystem);
        Check(rows.Count(r => r.HostName.StartsWith("10.1.2.")) == 2, "IP-address host names are not matched by their first number", null);

        settings.Link(new[] { "DB-PRIMARY", "sql01.contoso.com" });
        rows = DashboardMetrics.Coverage(hardware, findings, null, Today, settings);
        AssetCoverage sql = rows.Single(r => r.Members.Any(m => m.HostName == "DB-PRIMARY"));
        Check(sql.IsMatched && sql.MatchedBy == "linked" && sql.HostName == "sql01.contoso.com" && sql.HasStig && sql.AcasStale,
            "a link joins differently named records; the newest ACAS scan decides staleness", sql.HostName + " " + sql.MatchedBy + " " + sql.Gap);
        Check(sql.OperatingSystem == "Red Hat Enterprise Linux 9", "linked device OS", sql.OperatingSystem);

        settings.Separate(new[] { "W01.Contoso.com", "W01.Contoso" });
        rows = DashboardMetrics.Coverage(hardware, findings, null, Today, settings);
        Check(rows.Count(r => r.HostName.StartsWith("W01", StringComparison.OrdinalIgnoreCase)) == 2 && settings.KeepSeparate.Count == 2, "Keep separate undoes a short-name match", null);
        settings.Link(new[] { "W01.Contoso.com", "W01.Contoso" });
        Check(settings.KeepSeparate.Count == 0 && DashboardMetrics.Coverage(hardware, findings, null, Today, settings).Count(r => r.IsMatched) == 2, "linking again clears Keep separate", null);
        settings.Link(new[] { "W01.Contoso", "10.1.2.3" });
        Check(settings.Links.Count == 2 && settings.Links.Any(l => l.Hosts.Count == 3), "a link sharing a host is merged into the existing link", string.Join(" | ", settings.Links.Select(l => string.Join(",", l.Hosts))));

        string folder = Path.Combine(Path.GetTempPath(), "vmatch-" + Guid.NewGuid().ToString("N"));
        try
        {
            var store = new DeviceMatchStore(folder);
            DeviceMatchSettings fresh = store.Load();
            Check(fresh.MatchShortNames && fresh.Links.Count == 0, "matching store: defaults when there is no file", null);
            settings.MatchShortNames = false;
            store.Save(settings);
            DeviceMatchSettings back = store.Load();
            Check(!back.MatchShortNames && back.Links.Count == 2 && back.Links.Any(l => l.Hosts.Contains("10.1.2.3")), "matching store: saved and read back", null);
            File.WriteAllText(store.Path, "{ not json");
            Check(store.Load().MatchShortNames, "matching store: a damaged file gives the defaults", null);
        }
        finally
        {
            if (Directory.Exists(folder)) Directory.Delete(folder, true);
        }
    }

    private static void StigCurrency()
    {
        var subs = new List<MetricSubmission>
        {
            Sub(1, "h1", "Server STIG", "V2R4", "V2R5", true, Today.AddDays(-30)),
            Sub(1, "h1", "Server STIG", "V2R5", "V2R5", false, Today.AddDays(-1)),
            Sub(2, "h2", "Server STIG", "V2R4", "V2R5", true, Today.AddDays(-3)),
            Sub(2, "h2", "Custom STIG", "V1R1", "", false, Today.AddDays(-3))
        };
        StigCurrencyReport report = DashboardMetrics.StigCurrency(subs, Today.AddDays(-10), Today);
        Check(report.Rows.Count == 3, "newest submission per host and STIG", report.Rows.Count.ToString());
        Check(report.Rows.Single(r => r.Submission.HostName == "h1").State == StigCurrencyState.Current, "re-submitted at the current release: Current", null);
        Check(report.Rows.Single(r => r.Submission.HostName == "h2" && r.Submission.StigName == "Server STIG").State == StigCurrencyState.Outdated, "Outdated", null);
        Check(report.Rows.Single(r => r.Submission.StigName == "Custom STIG").State == StigCurrencyState.Unknown, "STIG not loaded: Unknown", null);
        Check(report.Outdated == 1 && !report.LibraryStale, "one outdated; recent library", report.LibraryNote);
        Check(DashboardMetrics.StigCurrency(subs, null, Today).LibraryStale, "no library import: flagged", null);
        Check(DashboardMetrics.StigCurrency(subs, Today.AddDays(-120), Today).LibraryStale, "library older than 90 days: flagged", null);
    }

    private static void Iavms()
    {
        MetricFinding a = Acas(1, "h1", "500001", "Very High", Today, "IAVA:2026-A-0001", "CVE:CVE-2026-1");
        a.SecondarySeverity = "I";
        MetricFinding b = Acas(2, "h2", "500001", "High", Today, "IAVA:2026-A-0001");
        MetricFinding c = Acas(1, "h1", "500002", "Moderate", Today, "IAVB:2026-B-0002");
        c.SecondarySeverity = "I";
        MetricFinding d = Acas(1, "h1", "500003", "Low", Today, "IAVT:2026-T-0003");
        MetricFinding e = Acas(3, "h3", "500004", "High", Today.AddDays(-20), "IAVA:2026-A-0009");
        MetricFinding e2 = Acas(3, "h3", "1", "Low", Today);
        var list = new List<MetricFinding> { a, b, c, d, e, e2 };
        EffectiveStatusResolver.Resolve(list);
        IList<IavmRow> rows = DashboardMetrics.ActiveIavms(list);
        Check(rows.Count == 3, "active IAVMs (the one only on an unverified finding is not active)", string.Join(",", rows.Select(r => r.Type + ":" + r.Iavm)));
        IavmRow iava = rows.First(r => r.Iavm == "2026-A-0001");
        Check(iava.Level == SeverityLevel.VeryHigh && iava.Hosts.Count == 2 && iava.OpenFindings == 2 && iava.Plugins.Count == 1, "IAVA: worst level, hosts, plugins", iava.Level + "/" + iava.Hosts.Count);
        Check(iava.Titles.Count == 1 && iava.Titles.Single() == "Plugin 500001", "IAVA: finding titles listed", string.Join("; ", iava.Titles));
        Check(rows.First(r => r.Type == "IAVB").Level == SeverityLevel.High, "IAVB: DISA CAT I raises Moderate to High", rows.First(r => r.Type == "IAVB").Level.ToString());
        Check(rows.Any(r => r.Type == "IAVT" && r.Level == SeverityLevel.Low), "IAVT included", null);
        Check(rows[0].Iavm == "2026-A-0001", "sorted worst first", rows[0].Iavm);
        IDictionary<string, int[]> counts = DashboardMetrics.IavmCounts(rows);
        Check(counts["IAVA"][0] == 1 && counts["IAVB"][1] == 1 && counts["IAVT"][3] == 1, "counts by type and level", null);
    }

    private static void Trend()
    {
        string folder = Path.Combine(Path.GetTempPath(), "vmetrics-" + Guid.NewGuid().ToString("N"));
        try
        {
            var store = new TrendStore(folder, 3);
            Check(store.Load().Count == 0, "trend: empty at start", null);

            var day1 = new List<MetricFinding>
            {
                Acas(1, "h", "1", "High", Today.AddDays(-10)), Acas(1, "h", "2", "Low", Today.AddDays(-10)),
                Stig(1, "h", "V-1", "II", "Open", Today.AddDays(-10))
            };
            EffectiveStatusResolver.Resolve(day1);
            TrendSnapshot s1 = store.Record(day1, Today.AddDays(-10).AddHours(9));
            Check(s1.Open == 3 && s1.NewlyOpen == 3 && s1.NewlyClosed == 0, "trend: first snapshot", s1.Open + "/" + s1.NewlyOpen);

            // Day 2: plugin 2 no longer reported (Unverified, not closed), V-1 fixed, a new plugin 3.
            var day2 = new List<MetricFinding>
            {
                Acas(1, "h", "1", "High", Today), Acas(1, "h", "2", "Low", Today.AddDays(-10)), Acas(1, "h", "3", "Moderate", Today),
                Stig(1, "h", "V-1", "II", "Not a Finding", Today)
            };
            EffectiveStatusResolver.Resolve(day2);
            TrendSnapshot s2 = store.Record(day2, Today.AddHours(9));
            Check(s2.Open == 2 && s2.Unverified == 1 && s2.NotAFinding == 1, "trend: second snapshot counts", s2.Open + "/" + s2.Unverified + "/" + s2.NotAFinding);
            Check(s2.NewlyOpen == 1 && s2.NewlyClosed == 1, "trend: one new, one closed; unverified is not closed", s2.NewlyOpen + "/" + s2.NewlyClosed);

            TrendSnapshot s2b = store.Record(day2, Today.AddHours(15));
            IList<TrendSnapshot> loaded = store.Load();
            Check(loaded.Count == 2 && loaded[1].TakenOn == s2b.TakenOn && s2b.NewlyClosed == 1, "trend: one snapshot per day (newest wins)", loaded.Count.ToString());
            Check(loaded[1].ActiveKeys != null && loaded[1].ActiveKeys.Count == 3, "trend: newest keeps its keys", null);

            store.Record(day2, Today.AddDays(1));
            store.Record(day2, Today.AddDays(2));
            IList<TrendSnapshot> trimmed = store.Load();
            Check(trimmed.Count == 3 && trimmed[0].TakenOn.Date == Today, "trend: oldest dropped past the limit", trimmed.Count.ToString());
            Check(trimmed[0].ActiveKeys == null && trimmed[1].ActiveKeys != null && trimmed[2].ActiveKeys != null, "trend: keys kept on the newest two only", null);

            File.WriteAllText(store.Path, "{ not json");
            Check(store.Load().Count == 0, "trend: damaged file starts over", null);
            store.Record(day2, Today.AddDays(3));
            Check(store.Load().Count == 1, "trend: recording after a damaged file works", null);
        }
        finally
        {
            try { Directory.Delete(folder, true); } catch (IOException) { }
        }
    }

    private static MetricFinding Acas(long hw, string host, string plugin, string level, DateTime seen, params string[] refs)
    {
        return new MetricFinding
        {
            FindingType = "ACAS", SourceName = "ACAS", HardwareId = hw, HostName = host, Asset = host, VulnerabilityId = plugin, RuleId = plugin,
            Title = "Plugin " + plugin, SeverityLevelName = level, Status = "Open", LastObserved = seen, FirstDiscovered = seen.AddDays(-1),
            References = refs.ToList()
        };
    }

    private static MetricFinding Stig(long hw, string host, string rule, string cat, string status, DateTime seen, params string[] controls)
    {
        return new MetricFinding
        {
            FindingType = "CKL", SourceName = "Test STIG", HardwareId = hw, HostName = host, Asset = host, VulnerabilityId = rule, RuleId = rule,
            Title = "Rule " + rule, Cat = cat, Status = status, LastObserved = seen, NistControls = controls.ToList()
        };
    }

    private static MetricPoamItem Poam(string status, string level, DateTime identified, DateTime? due)
    {
        return new MetricPoamItem { Status = status, SeverityName = level, DateIdentified = identified, ScheduledCompletion = due, Summary = level };
    }

    private static MetricSubmission Sub(long hw, string host, string stig, string submitted, string latest, bool outdated, DateTime imported)
    {
        return new MetricSubmission
        {
            FindingType = "CKL", HardwareId = hw, HostName = host, StigName = stig, SubmittedVersion = submitted, LatestVersion = latest,
            IsOutdated = outdated, ImportedOn = imported
        };
    }

    private static void Check(bool condition, string name, string detail)
    {
        if (condition) passed++;
        else
        {
            failed++;
            Console.WriteLine("::error::" + name + ": " + (detail ?? string.Empty).Replace("\r", string.Empty).Replace("\n", " | "));
        }
    }

    private static void Fail(string name, string detail)
    {
        Check(false, name, detail);
    }
}
