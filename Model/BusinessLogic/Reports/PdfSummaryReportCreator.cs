using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Threading;
using MigraDoc.DocumentObjectModel;
using MigraDoc.DocumentObjectModel.Tables;
using MigraDoc.Rendering;
using Vulnerator.Helper;

namespace Vulnerator.Model.BusinessLogic.Reports
{
    /// <summary>
    /// "PDF Summary": a short, printable overview of the findings the report filters select - totals, open findings by
    /// source and severity, results by status, STIG compliance, the assets with the most open findings and the most
    /// widespread open findings. Every page carries the classification / handling marking.
    /// </summary>
    public class PdfSummaryReportCreator
    {
        public const string ReportName = "PDF Summary";
        private const int TopCount = 20;
        private static readonly Color HeaderShade = new Color(217, 217, 217);
        private static readonly Color Accent = new Color(31, 56, 100);

        public string CreatePdfSummary(string fileName, string marking)
        {
            try
            {
                List<ReportFinding> findings = ReportFindings.Load(ReportName);
                Write(fileName, findings, marking);
                LogWriter.LogStatusUpdate($"PDF Summary: {findings.Count} finding(s) summarized in '{fileName}'.");
                return "PDF report creation successful";
            }
            catch (Exception exception)
            {
                LogWriter.LogErrorWithDebug($"Unable to create '{fileName}' (PDF Summary).", exception);
                return "PDF report creation failed - see log for details";
            }
        }

        /// <summary>Builds and saves the PDF. Rendering runs on its own STA thread (PDFsharp-WPF measures text with WPF).</summary>
        public static void Write(string fileName, List<ReportFinding> findings, string marking)
        {
            Exception failure = null;
            Thread thread = new Thread(() =>
            {
                try
                {
                    Document document = Build(findings, marking);
                    PdfDocumentRenderer renderer = new PdfDocumentRenderer(true) { Document = document };
                    renderer.RenderDocument();
                    renderer.PdfDocument.Info.Title = "Vulnerability Summary";
                    renderer.PdfDocument.Info.Creator = "Vulnerator 2.0";
                    if (!string.IsNullOrWhiteSpace(marking))
                    { renderer.PdfDocument.Info.Subject = marking.Trim(); }
                    renderer.PdfDocument.Save(fileName);
                }
                catch (Exception exception)
                { failure = exception; }
            });
            thread.SetApartmentState(ApartmentState.STA);
            thread.Start();
            thread.Join();
            if (failure != null)
            { throw new InvalidOperationException("PDF rendering failed: " + failure.Message, failure); }
        }

        private static Document Build(List<ReportFinding> findings, string marking)
        {
            Document document = new Document();
            document.Info.Title = "Vulnerability Summary";
            document.Info.Author = Properties.Settings.Default.Name ?? string.Empty;

            Style normal = document.Styles[StyleNames.Normal];
            normal.Font.Name = "Calibri";
            normal.Font.Size = 9.5;
            Style heading = document.Styles[StyleNames.Heading1];
            heading.Font.Size = 13;
            heading.Font.Bold = true;
            heading.Font.Color = Accent;
            heading.ParagraphFormat.SpaceBefore = Unit.FromPoint(14);
            heading.ParagraphFormat.SpaceAfter = Unit.FromPoint(6);
            heading.ParagraphFormat.KeepWithNext = true;

            Section section = document.AddSection();
            section.PageSetup = document.DefaultPageSetup.Clone();
            section.PageSetup.PageFormat = PageFormat.Letter;
            section.PageSetup.TopMargin = Unit.FromCentimeter(2.2);
            section.PageSetup.BottomMargin = Unit.FromCentimeter(2.2);
            section.PageSetup.LeftMargin = Unit.FromCentimeter(1.8);
            section.PageSetup.RightMargin = Unit.FromCentimeter(1.8);

            string banner = string.IsNullOrWhiteSpace(marking) ? string.Empty : marking.Trim();
            Paragraph header = section.Headers.Primary.AddParagraph(banner);
            header.Format.Alignment = ParagraphAlignment.Center;
            header.Format.Font.Bold = true;
            Paragraph footer = section.Footers.Primary.AddParagraph();
            footer.Format.Alignment = ParagraphAlignment.Center;
            if (banner.Length > 0)
            {
                footer.AddFormattedText(banner, TextFormat.Bold);
                footer.AddLineBreak();
            }
            footer.AddText("Vulnerator 2.0 - page ");
            footer.AddPageField();
            footer.AddText(" of ");
            footer.AddNumPagesField();

            Paragraph title = section.AddParagraph("Vulnerability Summary");
            title.Format.Font.Size = 20;
            title.Format.Font.Bold = true;
            title.Format.Font.Color = Accent;
            title.Format.SpaceAfter = Unit.FromPoint(4);
            string system = Properties.Settings.Default.EmassSystemName;
            if (!string.IsNullOrWhiteSpace(system))
            {
                Paragraph systemLine = section.AddParagraph(system.Trim());
                systemLine.Format.Font.Size = 13;
                systemLine.Format.SpaceAfter = Unit.FromPoint(8);
            }

            Table info = NewTable(section, 2, 5.0, 12.0);
            AddInfoRow(info, "Generated", DateTime.Now.ToString("d MMMM yyyy, HH:mm", CultureInfo.InvariantCulture));
            AddInfoRow(info, "Prepared by", Properties.Settings.Default.Name);
            AddInfoRow(info, "Organization", Properties.Settings.Default.Organization);
            AddInfoRow(info, "Email", Properties.Settings.Default.Email);
            AddInfoRow(info, "Phone", Properties.Settings.Default.Phone);
            AddInfoRow(info, "Scope", "Findings selected by the PDF Summary filters on the Reporting page.");
            info.Borders.Visible = false;

            // Overview
            section.AddParagraph("Overview", StyleNames.Heading1);
            List<ReportFinding> open = findings.Where(f => f.IsOpen).ToList();
            Table overview = NewTable(section, 1, 9.0, 4.0);
            AddInfoRow(overview, "Assets (hosts and software)", Count(findings.Select(f => f.Asset).Where(a => a.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase).Count()));
            AddInfoRow(overview, "Results evaluated", Count(findings.Count));
            AddInfoRow(overview, "Open findings", Count(open.Count));
            AddInfoRow(overview, "Open CAT I", Count(open.Count(f => f.Severity == "I")));
            AddInfoRow(overview, "Open CAT II", Count(open.Count(f => f.Severity == "II")));
            AddInfoRow(overview, "Open CAT III", Count(open.Count(f => f.Severity == "III")));
            AddInfoRow(overview, "Open CAT IV (informational)", Count(open.Count(f => f.Severity == "IV")));

            if (findings.Count == 0)
            {
                section.AddParagraph("No findings match the report filters.").Format.SpaceBefore = Unit.FromPoint(10);
                return document;
            }

            // Open findings by source and severity
            section.AddParagraph("Open findings by source and severity", StyleNames.Heading1);
            Table bySource = NewTable(section, 1, 5.5, 2.2, 2.2, 2.2, 2.2, 2.4);
            AddHeader(bySource, "Source", "CAT I", "CAT II", "CAT III", "CAT IV", "Total open");
            foreach (IGrouping<string, ReportFinding> type in findings.GroupBy(f => SourceLabel(f.FindingType)).OrderBy(g => g.Key))
            {
                List<ReportFinding> typeOpen = type.Where(f => f.IsOpen).ToList();
                AddRow(bySource, type.Key, Count(typeOpen.Count(f => f.Severity == "I")), Count(typeOpen.Count(f => f.Severity == "II")),
                    Count(typeOpen.Count(f => f.Severity == "III")), Count(typeOpen.Count(f => f.Severity == "IV")), Count(typeOpen.Count));
            }

            // Results by status
            section.AddParagraph("Results by status", StyleNames.Heading1);
            Table byStatus = NewTable(section, 1, 4.5, 2.1, 2.5, 2.5, 2.5, 1.8, 1.8);
            AddHeader(byStatus, "Source", "Open", "Not a Finding", "Not Applicable", "Not Reviewed", "Error", "Total");
            foreach (IGrouping<string, ReportFinding> type in findings.GroupBy(f => SourceLabel(f.FindingType)).OrderBy(g => g.Key))
            {
                AddRow(byStatus, type.Key, Count(type.Count(f => f.Status == "Ongoing")), Count(type.Count(f => f.Status == "Completed")),
                    Count(type.Count(f => f.Status == "Not Applicable")), Count(type.Count(f => f.Status == "Not Reviewed")),
                    Count(type.Count(f => f.Status == "Error")), Count(type.Count()));
            }

            // STIG compliance
            List<ReportFinding> stigResults = findings.Where(f => f.FindingType == "CKL" || f.FindingType == "XCCDF").ToList();
            if (stigResults.Count > 0)
            {
                section.AddParagraph("STIG compliance", StyleNames.Heading1);
                Table stigs = NewTable(section, 2, 7.4, 1.6, 1.4, 1.5, 1.5, 1.5, 2.5);
                AddHeader(stigs, "STIG", "Version", "Hosts", "Open I", "Open II", "Open III", "Compliance %");
                foreach (OpenXmlStigDetailsReportCreator.StigSummary s in OpenXmlStigDetailsReportCreator.Summarize(stigResults))
                {
                    AddRow(stigs, s.Name, s.Version, Count(s.Hosts), Count(s.OpenCat1), Count(s.OpenCat2), Count(s.OpenCat3), s.CompliancePercent);
                }
                Paragraph note = section.AddParagraph("Compliance % = (Not a Finding + Not Applicable) / reviewed results; Not Reviewed results are excluded.");
                note.Format.Font.Size = 8;
                note.Format.Font.Italic = true;
            }

            // Assets with the most open findings
            if (open.Count > 0)
            {
                section.AddParagraph($"Assets with the most open findings (top {TopCount})", StyleNames.Heading1);
                Table assets = NewTable(section, 1, 7.6, 2.0, 2.0, 2.0, 2.0, 2.2);
                AddHeader(assets, "Asset", "CAT I", "CAT II", "CAT III", "CAT IV", "Total open");
                foreach (var asset in open.GroupBy(f => f.Asset, StringComparer.OrdinalIgnoreCase)
                             .Select(g => new
                             {
                                 Name = g.Key,
                                 Cat1 = g.Count(f => f.Severity == "I"),
                                 Cat2 = g.Count(f => f.Severity == "II"),
                                 Cat3 = g.Count(f => f.Severity == "III"),
                                 Cat4 = g.Count(f => f.Severity == "IV"),
                                 Total = g.Count()
                             })
                             .OrderByDescending(a => a.Cat1).ThenByDescending(a => a.Cat2).ThenByDescending(a => a.Total).ThenBy(a => a.Name)
                             .Take(TopCount))
                {
                    AddRow(assets, string.IsNullOrEmpty(asset.Name) ? "(no asset)" : asset.Name, Count(asset.Cat1), Count(asset.Cat2),
                        Count(asset.Cat3), Count(asset.Cat4), Count(asset.Total));
                }

                // Most widespread open findings
                section.AddParagraph($"Most widespread open findings (top {TopCount})", StyleNames.Heading1);
                Table widespread = NewTable(section, 4, 3.2, 7.0, 4.2, 1.4, 2.0);
                AddHeader(widespread, "ID", "Title", "Source", "CAT", "Assets");
                foreach (var item in open.GroupBy(f => new { f.FindingType, f.SourceName, f.RuleIdentifier })
                             .Select(g => new
                             {
                                 Id = FindingId(g.First()),
                                 g.First().Title,
                                 Source = string.IsNullOrWhiteSpace(g.Key.SourceName) ? SourceLabel(g.Key.FindingType) : g.Key.SourceName,
                                 Severity = g.Select(f => f.Severity).OrderBy(SeverityRank).First(),
                                 Assets = g.Select(f => f.Asset).Distinct(StringComparer.OrdinalIgnoreCase).Count()
                             })
                             .OrderBy(i => SeverityRank(i.Severity)).ThenByDescending(i => i.Assets).ThenBy(i => i.Id)
                             .Take(TopCount))
                {
                    AddRow(widespread, item.Id, Shorten(item.Title, 140), Shorten(item.Source, 60), item.Severity, Count(item.Assets));
                }
            }

            return document;
        }

        private static string FindingId(ReportFinding finding)
        {
            if (finding.FindingType == "CKL" || finding.FindingType == "XCCDF")
            { return string.IsNullOrWhiteSpace(finding.GroupIdentifier) ? finding.FullRuleIdentifier : finding.GroupIdentifier; }
            return finding.RuleIdentifier;
        }

        private static string SourceLabel(string findingType)
        {
            switch (findingType)
            {
                case "CKL": return "STIG checklists";
                case "XCCDF": return "SCAP / XCCDF";
                case "ACAS": return "ACAS";
                case null:
                case "": return "Other";
                default: return findingType;
            }
        }

        private static int SeverityRank(string severity)
        {
            switch (severity)
            {
                case "I": return 1;
                case "II": return 2;
                case "III": return 3;
                case "IV": return 4;
                default: return 5;
            }
        }

        private static string Count(int value) { return value.ToString("N0", CultureInfo.InvariantCulture); }

        private static string Shorten(string text, int length)
        {
            text = (text ?? string.Empty).Replace("\r", " ").Replace("\n", " ").Trim();
            return text.Length <= length ? text : text.Substring(0, length - 3) + "...";
        }

        /// <summary>A table; the first <paramref name="textColumns"/> columns are left-aligned text, the rest right-aligned numbers.</summary>
        private static Table NewTable(Section section, int textColumns, params double[] widthsCm)
        {
            Table table = section.AddTable();
            table.Borders.Width = 0.5;
            table.Borders.Color = new Color(166, 166, 166);
            table.LeftPadding = Unit.FromPoint(4);
            table.RightPadding = Unit.FromPoint(4);
            table.TopPadding = Unit.FromPoint(2);
            table.BottomPadding = Unit.FromPoint(2);
            for (int i = 0; i < widthsCm.Length; i++)
            {
                Column column = table.AddColumn(Unit.FromCentimeter(widthsCm[i]));
                column.Format.Alignment = i < textColumns ? ParagraphAlignment.Left : ParagraphAlignment.Right;
            }
            return table;
        }

        private static void AddHeader(Table table, params string[] cells)
        {
            Row row = table.AddRow();
            row.HeadingFormat = true;
            row.Shading.Color = HeaderShade;
            row.Format.Font.Bold = true;
            for (int i = 0; i < cells.Length; i++)
            { row.Cells[i].AddParagraph(cells[i] ?? string.Empty); }
        }

        private static void AddRow(Table table, params string[] cells)
        {
            Row row = table.AddRow();
            for (int i = 0; i < cells.Length; i++)
            { row.Cells[i].AddParagraph(cells[i] ?? string.Empty); }
        }

        private static void AddInfoRow(Table table, string label, string value)
        {
            Row row = table.AddRow();
            row.Cells[0].AddParagraph(label).Format.Font.Bold = true;
            row.Cells[1].AddParagraph(value ?? string.Empty);
            row.Cells[1].Format.Alignment = ParagraphAlignment.Left;
        }
    }
}
