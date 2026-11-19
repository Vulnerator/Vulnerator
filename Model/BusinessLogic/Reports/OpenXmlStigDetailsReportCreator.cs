using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using Vulnerator.Helper;

namespace Vulnerator.Model.BusinessLogic.Reports
{
    /// <summary>
    /// "STIG Details": every STIG rule result from checklists and SCAP / XCCDF scans, one row per host and rule, with
    /// the rule text, the reviewer's details and comments, and the NIST SP 800-53 Rev 5 controls and CCIs. A second sheet
    /// summarizes each STIG. Successor of the STIG Details tab of Vulnerator 6.
    /// </summary>
    public class OpenXmlStigDetailsReportCreator
    {
        public const string ReportName = "STIG Details";

        public static readonly string[] ColumnHeaders =
        {
            "STIG Name", "STIG Version", "Host Name", "IP Address", "Group(s)", "Vuln ID", "Rule ID", "STIG ID",
            "Rule Title", "Severity", "Severity Override", "Status", "Mitigated Status", "NIST SP 800-53 Rev 5 Controls",
            "CCIs", "Discussion", "Check Content", "Fix Text", "Finding Details", "Comments", "Finding Type",
            "Source File", "Last Observed"
        };

        private static readonly double[] ColumnWidths =
        {
            40, 11, 20, 15, 20, 12, 22, 18, 45, 9, 10, 14, 14, 24, 22, 60, 60, 60, 50, 50, 10, 35, 12
        };

        public static readonly string[] SummaryHeaders =
        {
            "STIG Name", "STIG Version", "Hosts", "Rules Evaluated", "Open CAT I", "Open CAT II", "Open CAT III",
            "Not a Finding", "Not Applicable", "Not Reviewed", "Compliance %"
        };

        public string CreateStigDetailsReport(string fileName)
        {
            try
            {
                List<ReportFinding> findings = ReportFindings.Load(ReportName, "CKL", "XCCDF");
                Write(fileName, findings, Properties.Settings.Default.EmassClassificationMarking);
                LogWriter.LogStatusUpdate($"STIG Details: {findings.Count} row(s) written to '{fileName}'.");
                return "Excel report creation successful";
            }
            catch (Exception exception)
            {
                LogWriter.LogErrorWithDebug($"Unable to create '{fileName}' (STIG Details).", exception);
                return "Excel report creation failed - see log for details";
            }
        }

        public static void Write(string fileName, List<ReportFinding> findings, string marking)
        {
            using (EmassWorkbookWriter workbook = new EmassWorkbookWriter(fileName, marking))
            {
                EmassSheet details = workbook.AddSheet("STIG Details", ColumnWidths);
                for (int c = 0; c < ColumnHeaders.Length; c++)
                { details.Text(1, c + 1, ColumnHeaders[c], EmassWorkbookWriter.StyleColumnHeader); }
                int row = 2;
                foreach (ReportFinding f in findings)
                {
                    int c = 1;
                    details.Text(row, c++, f.SourceName);
                    details.Text(row, c++, f.SourceVersionRelease);
                    details.Text(row, c++, f.Asset);
                    details.Text(row, c++, f.IpAddress);
                    details.Text(row, c++, f.Groups);
                    details.Text(row, c++, f.GroupIdentifier);
                    details.Text(row, c++, f.FullRuleIdentifier);
                    details.Text(row, c++, f.SecondaryIdentifier);
                    details.Text(row, c++, f.Title);
                    details.Text(row, c++, CatLabel(ReportFinding.NormalizeSeverity(f.RawSeverity)));
                    details.Text(row, c++, CatLabel(ReportFinding.NormalizeSeverity(f.SeverityOverride)));
                    details.Text(row, c++, ReportFinding.DisplayStatus(f.Status));
                    details.Text(row, c++, ReportFinding.DisplayStatus(f.MitigatedStatus));
                    details.Text(row, c++, f.NistControls);
                    details.Text(row, c++, f.Ccis);
                    details.Text(row, c++, f.Description);
                    details.Text(row, c++, f.CheckContent);
                    details.Text(row, c++, f.FixText);
                    details.Text(row, c++, f.FindingDetails);
                    details.Text(row, c++, f.Comments);
                    details.Text(row, c++, f.FindingType);
                    details.Text(row, c++, f.SourceFile);
                    details.Date(row, c, f.LastObserved);
                    row++;
                }
                details.FrozenRows = 1;
                details.AutoFilter = "A1:" + EmassSheet.ColumnName(ColumnHeaders.Length) + Math.Max(1, row - 1).ToString(CultureInfo.InvariantCulture);
                details.Save();

                EmassSheet summary = workbook.AddSheet("Summary by STIG", new double[] { 50, 12, 9, 12, 11, 11, 11, 12, 13, 12, 12 });
                for (int c = 0; c < SummaryHeaders.Length; c++)
                { summary.Text(1, c + 1, SummaryHeaders[c], EmassWorkbookWriter.StyleColumnHeader); }
                row = 2;
                foreach (StigSummary s in Summarize(findings))
                {
                    int c = 1;
                    summary.Text(row, c++, s.Name);
                    summary.Text(row, c++, s.Version);
                    summary.Text(row, c++, s.Hosts.ToString(CultureInfo.InvariantCulture));
                    summary.Text(row, c++, s.Evaluated.ToString(CultureInfo.InvariantCulture));
                    summary.Text(row, c++, s.OpenCat1.ToString(CultureInfo.InvariantCulture));
                    summary.Text(row, c++, s.OpenCat2.ToString(CultureInfo.InvariantCulture));
                    summary.Text(row, c++, s.OpenCat3.ToString(CultureInfo.InvariantCulture));
                    summary.Text(row, c++, s.NotAFinding.ToString(CultureInfo.InvariantCulture));
                    summary.Text(row, c++, s.NotApplicable.ToString(CultureInfo.InvariantCulture));
                    summary.Text(row, c++, s.NotReviewed.ToString(CultureInfo.InvariantCulture));
                    summary.Text(row, c, s.CompliancePercent);
                    row++;
                }
                summary.FrozenRows = 1;
                summary.Save();
            }
        }

        public static string CatLabel(string severity)
        {
            return string.IsNullOrEmpty(severity) ? string.Empty : "CAT " + severity;
        }

        public class StigSummary
        {
            public string Name { get; set; }
            public string Version { get; set; }
            public int Hosts { get; set; }
            public int Evaluated { get; set; }
            public int OpenCat1 { get; set; }
            public int OpenCat2 { get; set; }
            public int OpenCat3 { get; set; }
            public int NotAFinding { get; set; }
            public int NotApplicable { get; set; }
            public int NotReviewed { get; set; }

            /// <summary>(Not a Finding + Not Applicable) / reviewed results, as a percentage; empty when nothing was reviewed.</summary>
            public string CompliancePercent
            {
                get
                {
                    int open = OpenCat1 + OpenCat2 + OpenCat3;
                    int reviewed = open + NotAFinding + NotApplicable;
                    return reviewed == 0 ? string.Empty : (100.0 * (NotAFinding + NotApplicable) / reviewed).ToString("0.0", CultureInfo.InvariantCulture);
                }
            }
        }

        /// <summary>One line per STIG: hosts, results by status and open findings by CAT.</summary>
        public static List<StigSummary> Summarize(IEnumerable<ReportFinding> findings)
        {
            return findings
                .GroupBy(f => f.SourceName ?? string.Empty)
                .OrderBy(g => g.Key, StringComparer.OrdinalIgnoreCase)
                .Select(g => new StigSummary
                {
                    Name = g.Key,
                    Version = string.Join(", ", g.Select(f => f.SourceVersionRelease).Where(v => v.Length > 0).Distinct().OrderBy(v => v)),
                    Hosts = g.Select(f => f.Asset).Distinct(StringComparer.OrdinalIgnoreCase).Count(),
                    Evaluated = g.Count(),
                    OpenCat1 = g.Count(f => f.IsOpen && f.Severity == "I"),
                    OpenCat2 = g.Count(f => f.IsOpen && f.Severity == "II"),
                    OpenCat3 = g.Count(f => f.IsOpen && (f.Severity == "III" || f.Severity == "IV")),
                    NotAFinding = g.Count(f => f.Status == "Completed"),
                    NotApplicable = g.Count(f => f.Status == "Not Applicable"),
                    NotReviewed = g.Count(f => f.Status == "Not Reviewed")
                })
                .ToList();
        }
    }
}
