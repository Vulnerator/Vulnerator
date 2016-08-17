using log4net;
using MigraDoc.DocumentObjectModel;
using MigraDoc.DocumentObjectModel.Tables;
using MigraDoc.Rendering;
using PdfSharp.Pdf;
using System;

namespace Vulnerator.Model
{
    public class PdfReportCreator
    {
        private string ContactOrganization = ConfigAlter.ReadSettingsFromDictionary("tbEmassOrg");
        private string ContactName = ConfigAlter.ReadSettingsFromDictionary("tbEmassName");
        private string ContactNumber = ConfigAlter.ReadSettingsFromDictionary("tbEmassNumber");
        private string ContactEmail = ConfigAlter.ReadSettingsFromDictionary("tbEmassEmail");
        private static readonly ILog log = LogManager.GetLogger(typeof(Logger));

        public string PdfWriter(string filename, string systemName)
        {
            try
            {
                Document pdfSummaryDoc = new Document();                                                            // Create initial (blank) report

                Style docStyle = pdfSummaryDoc.Styles.AddStyle("docStyle", "Normal");                               // Set up Style for text in document  
                docStyle.Font.Name = "Calibri";
                docStyle.Font.Size = 11;
                docStyle.ParagraphFormat.PageBreakBefore = false;

                docStyle = pdfSummaryDoc.Styles.AddStyle("mainHeaderStyle", "Normal");                              // Set up Style for main level headers
                docStyle.Font.Name = "Calibri";
                docStyle.Font.Size = 16;
                docStyle.Font.Color = Colors.Navy;
                docStyle.Font.Bold = true;
                docStyle.ParagraphFormat.PageBreakBefore = false;

                Column workingColumn;
                Row workingRow;
                Cell workingCell;

                Section reportOverviewSection = pdfSummaryDoc.AddSection();                                         // Section for Report information
                Paragraph reportOverviewParagraph = reportOverviewSection.AddParagraph(
                    "Report Overview", "mainHeaderStyle");                                                          // Paragraph for Report Overview
                reportOverviewParagraph.AddText(Environment.NewLine);

                Table reportOverviewTable = new Table();                                                            // Create table to house data; format it
                reportOverviewTable.Format.Font.Name = "Calibri";
                reportOverviewTable.Format.Font.Size = 11;
                workingColumn = reportOverviewTable.AddColumn(Unit.FromCentimeter(5.5));                            // Create left column and format it
                workingColumn.Format.Alignment = ParagraphAlignment.Left;
                workingColumn = reportOverviewTable.AddColumn(Unit.FromCentimeter(8));                              // Create right column and format it
                workingColumn.Format.Alignment = ParagraphAlignment.Left;

                workingRow = reportOverviewTable.AddRow();                                                          // "System name" row
                workingCell = workingRow.Cells[0];
                workingCell.AddParagraph("System Name:");
                workingCell = workingRow.Cells[1];
                workingCell.AddParagraph(systemName);

                workingRow = reportOverviewTable.AddRow();                                                          // "Report creator name" row
                workingCell = workingRow.Cells[0];
                workingCell.AddParagraph("Report Creator Name:");
                workingCell = workingRow.Cells[1];
                if (!string.IsNullOrWhiteSpace(ContactName))
                {
                    workingCell.AddParagraph(ContactName);
                }
                else
                {
                    workingCell.AddParagraph(string.Empty);
                }

                workingRow = reportOverviewTable.AddRow();                                                          // "Report creator organization" row
                workingCell = workingRow.Cells[0];
                workingCell.AddParagraph("Report Creator Organization:");
                workingCell = workingRow.Cells[1];
                if (!string.IsNullOrWhiteSpace(ContactOrganization))
                {
                    workingCell.AddParagraph(ContactOrganization);
                }
                else
                {
                    workingCell.AddParagraph(string.Empty);
                }

                workingRow = reportOverviewTable.AddRow();                                                          // "Report creator email" row
                workingCell = workingRow.Cells[0];
                workingCell.AddParagraph("Report Creator Email:");
                workingCell = workingRow.Cells[1];
                if (!string.IsNullOrWhiteSpace(ContactEmail))
                {
                    workingCell.AddParagraph(ContactEmail);
                }
                else
                {
                    workingCell.AddParagraph(string.Empty);
                }

                workingRow = reportOverviewTable.AddRow();                                                          // "Report creator number" row
                workingCell = workingRow.Cells[0];
                workingCell.AddParagraph("Report Creator Number:");
                workingCell = workingRow.Cells[1];
                if (!string.IsNullOrWhiteSpace(ContactNumber))
                {
                    workingCell.AddParagraph(ContactNumber);
                }
                else
                {
                    workingCell.AddParagraph(string.Empty);
                }

                reportOverviewSection.Add(reportOverviewTable);                                                     // Add created table to the report section

                Section overviewTablesSection = pdfSummaryDoc.AddSection();                                         // Section for various overview tables
                Paragraph vulnOverviewCountParagraph = overviewTablesSection.AddParagraph(
                    "Vulnerability Count Overview", "mainHeaderStyle");                                             // Paragraph for Vulnerability Count Overview
                vulnOverviewCountParagraph.AddText(Environment.NewLine);

                PdfDocumentRenderer pdfRenderer = new PdfDocumentRenderer(false);
                pdfRenderer.Document = pdfSummaryDoc;
                pdfRenderer.RenderDocument();                                                                       // Render the document

                pdfRenderer.PdfDocument.Save(filename);                                                             // Save the document
                return "Success";
            }
            catch (Exception exception)
            {
                log.Error("Unable to create PDF report.");
                log.Debug("Exception details: " + exception);
                return "Failed; See Log";
            }
        }                                                                                                           // End method "PdfCreator"
    }
}
