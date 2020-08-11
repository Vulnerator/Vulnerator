using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using DocumentFormat.OpenXml;
using DocumentFormat.OpenXml.Packaging;
using DocumentFormat.OpenXml.Spreadsheet;
using Vulnerator.Helper;
using Vulnerator.Model.DataAccess;

namespace Vulnerator.Model.BusinessLogic.Reports
{
    public class OpenXmlNavyRarReportCreator
    {
        private Dictionary<string, int> sharedStringDictionary = new Dictionary<string, int>();
        private int sharedStringMaxIndex;
        private UInt32Value sheetIndex = 1;
        string doubleCarriageReturn = Environment.NewLine + Environment.NewLine;
        private DdlReader _ddlReader = new DdlReader();
        private Assembly assembly = Assembly.GetExecutingAssembly();
        private string _storedProcedureBase = "Vulnerator.Resources.DdlFiles.StoredProcedures.";
        private OpenXmlWriter _openXmlWriter;
        private readonly OpenXmlStylesheetCreator _openXmlStylesheetCreator = new OpenXmlStylesheetCreator();
        private readonly OpenXmlCellDataHandler _openXmlCellDataHandler = new OpenXmlCellDataHandler();
        private readonly string[] mitigatedStatuses = { "Ongoing", "Completed", "Not Applicable", "Not Reviewed" };
        private readonly string[] levels = {"Very High", "High", "Moderate", "Low", "Very Low"};

        public string CreateNavyRar(string fileName)
        {
            try
            {
                if (!DatabaseBuilder.sqliteConnection.State.ToString().Equals("Open"))
                {
                    DatabaseBuilder.sqliteConnection.Open();
                }

                using (SpreadsheetDocument spreadsheetDocument =
                    SpreadsheetDocument.Create(fileName, SpreadsheetDocumentType.Workbook))
                {
                    LogWriter.LogStatusUpdate("Creating Navy RAR workbook framework.");
                    WorkbookPart workbookPart = spreadsheetDocument.AddWorkbookPart();
                    WorkbookStylesPart workbookStylesPart = workbookPart.AddNewPart<WorkbookStylesPart>();
                    workbookStylesPart.Stylesheet = _openXmlStylesheetCreator.CreateStylesheet();
                    Workbook workbook = workbookPart.Workbook = new Workbook();
                    Sheets sheets = workbook.AppendChild(new Sheets());
                    StartReport(workbookPart, sheets);
                    LogWriter.LogStatusUpdate("Writing Navy RAR findings.");
                    WriteFindingsToReport();
                    LogWriter.LogStatusUpdate("Finalizing Navy RAR workbook.");
                    EndReport();
                    _openXmlCellDataHandler.CreateSharedStringPart(workbookPart, sharedStringMaxIndex,
                        sharedStringDictionary);
                }

                return "Excel report creation successful";
            }
            catch (Exception exception)
            {
                string error = $"Unable to create '{fileName}' (Excel Report).";
                LogWriter.LogErrorWithDebug(error, exception);
                return "Excel report creation failed - see log for details";
            }
            finally
            {
                DatabaseBuilder.sqliteConnection.Close();
            }
        }

        private void StartReport(WorkbookPart workbookPart, Sheets sheets)
        {
            try
            {
                WorksheetPart worksheetPart = workbookPart.AddNewPart<WorksheetPart>();
                Sheet sheet = new Sheet()
                    {Id = workbookPart.GetIdOfPart(worksheetPart), SheetId = sheetIndex, Name = "Navy RAR"};
                sheetIndex++;
                sheets.Append(sheet);
                _openXmlWriter = OpenXmlWriter.Create(worksheetPart);
                _openXmlWriter.WriteStartElement(new Worksheet());
                WriteReportColumns();
                _openXmlWriter.WriteStartElement(new SheetData());
                _openXmlWriter.WriteElement(new Row() {Hidden = true});
                WriteReportEmptyHeaders();
                WriteReportHeaderRow();
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to initialize 'Navy RAR' tab.");
                throw exception;
            }
        }

        private void WriteReportColumns()
        {
            try
            {
                _openXmlWriter.WriteStartElement(new Columns());
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 4.43, Max = 1, Min = 1});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 10.57, Max = 2, Min = 2});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 10.57, Max = 3, Min = 3});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 32.29, Max = 4, Min = 4});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 10.57, Max = 5, Min = 5});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 32.29, Max = 6, Min = 6});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 24.43, Max = 7, Min = 7});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 24.43, Max = 8, Min = 8});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 24.43, Max = 9, Min = 9});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 32.29, Max = 10, Min = 10});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 32.29, Max = 11, Min = 11});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 24.43, Max = 12, Min = 12});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 24.43, Max = 13, Min = 13});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 24.43, Max = 14, Min = 14});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 24.43, Max = 15, Min = 15});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 24.43, Max = 16, Min = 16});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 32.29, Max = 17, Min = 17});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 24.43, Max = 18, Min = 18});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 32.29, Max = 19, Min = 19});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 24.43, Max = 20, Min = 20});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 32.29, Max = 21, Min = 21});
                _openXmlWriter.WriteEndElement();
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to generate 'Navy RAR' columns.");
                throw exception;
            }
        }

        private void WriteReportEmptyHeaders()
        {
            try
            {
                for (int i = 0; i < 2; i++)
                {
                    _openXmlWriter.WriteStartElement(new Row());
                    _openXmlWriter.WriteEndElement();
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to generate first 'Navy RAR' header row.");
                throw exception;
            }
        }

        private void WriteReportHeaderRow()
        {
            try
            {
                _openXmlWriter.WriteStartElement(new Row());
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 25, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, $"Non-Compliant Security Control{Environment.NewLine}(16a)", 26, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, $"Affected CCI{Environment.NewLine}(16a.1)", 26, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, $"Source of Discovery{Environment.NewLine}(16a.2)", 26, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, $"Vulnerability ID{Environment.NewLine}(16a.3)", 26, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, $"Vulnerability Description{Environment.NewLine}(16b)", 26, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, $"Devices Affected{Environment.NewLine}(16b.1)", 26, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, $"Security Objectives{Environment.NewLine}(C-I-A){Environment.NewLine}(16c)", 26, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, $"Raw Test Result{Environment.NewLine}(16d)", 26, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, $"Predisposing Condition(s){Environment.NewLine}(16d.1)", 26, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, $"Technical Mitigation(s){Environment.NewLine}(16d.2)", 26, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, $"Severity or Pervasiveness{Environment.NewLine}(VH-VL){Environment.NewLine}(16d.3)", 26, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, $"Relevance of Threat{Environment.NewLine}(VH-VL){Environment.NewLine}(16e)", 26, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, $"Threat Description{Environment.NewLine}(16e.1)", 26, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, $"Likelihood{Environment.NewLine}(Cells 16d.3 & 16e){Environment.NewLine}(VH-VL){Environment.NewLine}(16f)", 26, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, $"Impact{Environment.NewLine}(VH-VL){Environment.NewLine}(16g)", 26, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, $"Impact Description{Environment.NewLine}(16h)", 26, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, $"Risk{Environment.NewLine}(Cells 16f & 16g){Environment.NewLine}(VH-VL){Environment.NewLine}(16i)", 26, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, $"Proposed Mitigation(s){Environment.NewLine}(From POA&M){Environment.NewLine}(16j)", 26, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, $"Residual Risk{Environment.NewLine}(After Proposed Mitigation(s)){Environment.NewLine}(16k)", 26, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, $"Recommendations{Environment.NewLine}(16l)", 26, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlWriter.WriteEndElement();
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to generate second 'Navy RAR' header row.");
                throw exception;
            }
        }

        private void WriteFindingsToReport()
        {
            try
            {
                using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                {
                    sqliteCommand.Parameters.Add(new SQLiteParameter("UserName",
                        Properties.Settings.Default.ActiveUser));
                    FilterTextCreator filterTextCreator = new FilterTextCreator();
                    string findingTypeFilter = filterTextCreator.FindingType(sqliteCommand, "Navy RAR");
                    string groupFilter = filterTextCreator.Group(sqliteCommand, "Navy RAR");
                    string severityFilter = filterTextCreator.Severity(sqliteCommand, "Navy RAR");
                    string statusFilter = filterTextCreator.Status(sqliteCommand, "Navy RAR");
                    string rmfOverrideFilter = filterTextCreator.RmfOverride(sqliteCommand, "Navy RAR");
                    sqliteCommand.CommandText =
                        _ddlReader.ReadDdl(_storedProcedureBase + "Select.NavyRarVulnerabilities.dml", assembly);

                    if (!string.IsNullOrWhiteSpace(findingTypeFilter) ||
                        !string.IsNullOrWhiteSpace(groupFilter) ||
                        !string.IsNullOrWhiteSpace(severityFilter) ||
                        !string.IsNullOrWhiteSpace(statusFilter))
                    {
                        
                        Regex regex = new Regex(Properties.Resources.RegexSqlGroupBy);
                        sqliteCommand.CommandText =
                            sqliteCommand.CommandText.Insert(regex.Match(sqliteCommand.CommandText).Index, "WHERE ");
                        if (!string.IsNullOrWhiteSpace(findingTypeFilter))
                        {
                            sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(regex.Match(sqliteCommand.CommandText).Index, findingTypeFilter);
                        }
                        if (!string.IsNullOrWhiteSpace(groupFilter))
                        {
                            if (!string.IsNullOrWhiteSpace(findingTypeFilter))
                            {
                                sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(regex.Match(sqliteCommand.CommandText).Index, $"AND {Environment.NewLine}");
                            }
                            sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(regex.Match(sqliteCommand.CommandText).Index, groupFilter);
                        }
                        if (!string.IsNullOrWhiteSpace(severityFilter))
                        {
                            if (!string.IsNullOrWhiteSpace(findingTypeFilter) || !string.IsNullOrWhiteSpace(groupFilter))
                            {
                                sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(regex.Match(sqliteCommand.CommandText).Index, $"AND {Environment.NewLine}");
                            }
                            sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(regex.Match(sqliteCommand.CommandText).Index, $"(PrimaryRawRiskIndicator {severityFilter}) ");
                        }
                        if (!string.IsNullOrWhiteSpace(statusFilter))
                        {
                            if (!string.IsNullOrWhiteSpace(findingTypeFilter) || !string.IsNullOrWhiteSpace(groupFilter) || !string.IsNullOrWhiteSpace(severityFilter))
                            {
                                sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(regex.Match(sqliteCommand.CommandText).Index, $"AND {Environment.NewLine}");
                            }
                            sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(regex.Match(sqliteCommand.CommandText).Index, $"(UniqueMitigatedStatus {statusFilter}) ");
                            sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(regex.Match(sqliteCommand.CommandText).Index, Environment.NewLine);
                            regex = new Regex(Properties.Resources.RegexGroupsMitigationsOrConditionsVulnerabilities);
                            sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(regex.Match(sqliteCommand.CommandText).Index, $"{Environment.NewLine}WHERE (MitigatedStatus {statusFilter}) ");
                        }
                        else
                        {
                            sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(regex.Match(sqliteCommand.CommandText).Index, Environment.NewLine);
                        }
                        
                    }

                    if (!string.IsNullOrWhiteSpace(rmfOverrideFilter))
                    {
                        Regex regex = new Regex(Properties.Resources.RegexSqlSoftwareId);
                        sqliteCommand.CommandText =
                            sqliteCommand.CommandText.Insert(regex.Match(sqliteCommand.CommandText).Index,
                                rmfOverrideFilter);
                        regex = new Regex(Properties.Resources.RegexGroupProposedMitigation);
                        sqliteCommand.CommandText =
                            sqliteCommand.CommandText.Insert(regex.Match(sqliteCommand.CommandText).Index,
                                Properties.Resources.StringGroupRmfFields);
                    }

                    using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
                    {
                        while (sqliteDataReader.Read())
                        {
                            if (sqliteDataReader["UniqueVulnerabilityIdentifier"].ToString().Equals("Plugin"))
                            {
                                continue;
                            }
                            WriteFindingToReport(sqliteDataReader);
                        }
                    }
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to write findings to the 'Navy RAR' workbook.");
                throw exception;
            }
        }

        private void WriteFindingToReport(SQLiteDataReader sqliteDataReader)
        {
            try
            {
                _openXmlWriter.WriteStartElement(new Row());
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 25, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, sqliteDataReader["NIST_Controls"].ToString(), 24, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, sqliteDataReader["CCI"].ToString(), 24, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, $"{sqliteDataReader["VulnSourceName"]} :: v{sqliteDataReader["VulnSourceVersion"]}r{sqliteDataReader["VulnSourceRelease"]}", 20, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, sqliteDataReader["UniqueVulnerabilityIdentifier"].ToString(), 24, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                string descriptionCellValue =
                    $"Title: {Environment.NewLine}{sqliteDataReader["VulnerabilityTitle"]}{doubleCarriageReturn}" +
                    $"Description:{Environment.NewLine}{sqliteDataReader["VulnerabilityDescription"]}";
                _openXmlCellDataHandler.WriteCellValue(
                    _openXmlWriter,
                    descriptionCellValue,
                    20, ref sharedStringMaxIndex, sharedStringDictionary);
                if (!string.IsNullOrWhiteSpace(sqliteDataReader["DisplayedSoftwareName"].ToString()))
                {
                    _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, sqliteDataReader["DisplayedSoftwareName"].ToString().Replace(",", Environment.NewLine), 24, ref sharedStringMaxIndex,
                        sharedStringDictionary);
                }
                else
                {
                    _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, sqliteDataReader["HostName"].ToString().Replace(",", Environment.NewLine), 24, ref sharedStringMaxIndex,
                        sharedStringDictionary);
                }

                string ciaTriad = string.Empty;
                if (!string.IsNullOrWhiteSpace(sqliteDataReader["ConfidentialityLevel"].ToString()))
                {
                    ciaTriad = "C";
                }
                if (!string.IsNullOrWhiteSpace(sqliteDataReader["IntegrityLevel"].ToString()))
                {
                    ciaTriad += string.IsNullOrWhiteSpace(ciaTriad) ? "I" : "-I";
                }
                if (!string.IsNullOrWhiteSpace(sqliteDataReader["AvailabilityLevel"].ToString()))
                {
                    ciaTriad += string.IsNullOrWhiteSpace(ciaTriad) ? "A" : "-A";
                }
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, ciaTriad, 24, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, sqliteDataReader["PrimaryRawRiskIndicator"].ToString(), 24,
                    ref sharedStringMaxIndex, sharedStringDictionary);
                string technicalMitigation = sqliteDataReader["GroupTechnicalMitigation"].ToString().Replace(",", doubleCarriageReturn) + doubleCarriageReturn +
                                             sqliteDataReader["UniqueTechnicalMitigation"];
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, technicalMitigation, 20,
                    ref sharedStringMaxIndex, sharedStringDictionary);
                string predisposingConditions = sqliteDataReader["GroupPredisposingConditions"].ToString().Replace(",", doubleCarriageReturn) + doubleCarriageReturn +
                                                sqliteDataReader["UniquePredisposingConditions"];
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, predisposingConditions, 20,
                    ref sharedStringMaxIndex, sharedStringDictionary);
                if (!string.IsNullOrWhiteSpace(sqliteDataReader["UniqueSeverityPervasiveness"].ToString()))
                {
                    _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, sqliteDataReader["UniqueSeverityPervasiveness"].ToString(), 24, ref sharedStringMaxIndex,
                        sharedStringDictionary);
                }
                else if (!string.IsNullOrWhiteSpace(sqliteDataReader["GroupSeverityPervasiveness"].ToString()))
                {
                    foreach (string level in levels)
                    {
                        if (sqliteDataReader["GroupSeverityPervasiveness"].ToString().Contains(level))
                        {
                            _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, level, 24, ref sharedStringMaxIndex,
                                sharedStringDictionary);
                            break;
                        }
                    }
                    
                }
                else
                {
                    _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 24, ref sharedStringMaxIndex,
                        sharedStringDictionary);
                }
                if (!string.IsNullOrWhiteSpace(sqliteDataReader["UniqueThreatRelevance"].ToString()))
                {
                    _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, sqliteDataReader["UniqueThreatRelevance"].ToString(), 24, ref sharedStringMaxIndex,
                        sharedStringDictionary);
                }
                else if (!string.IsNullOrWhiteSpace(sqliteDataReader["GroupThreatRelevance"].ToString()))
                {
                    foreach (string level in levels)
                    {
                        if (sqliteDataReader["GroupThreatRelevance"].ToString().Contains(level))
                        {
                            _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, level, 24, ref sharedStringMaxIndex,
                                sharedStringDictionary);
                            break;
                        }
                    }
                    
                }
                else
                {
                    _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 24, ref sharedStringMaxIndex,
                        sharedStringDictionary);
                }
                string threatDescription = sqliteDataReader["GroupThreatDescription"].ToString().Replace(",", doubleCarriageReturn) + doubleCarriageReturn +
                                  sqliteDataReader["UniqueThreatDescription"];
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, threatDescription, 20,
                    ref sharedStringMaxIndex, sharedStringDictionary);
                if (!string.IsNullOrWhiteSpace(sqliteDataReader["UniqueLikelihood"].ToString()))
                {
                    _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, sqliteDataReader["UniqueLikelihood"].ToString(), 24, ref sharedStringMaxIndex,
                        sharedStringDictionary);
                }
                else if (!string.IsNullOrWhiteSpace(sqliteDataReader["GroupLikelihood"].ToString()))
                {
                    foreach (string level in levels)
                    {
                        if (sqliteDataReader["GroupLikelihood"].ToString().Contains(level))
                        {
                            _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, level, 24, ref sharedStringMaxIndex,
                                sharedStringDictionary);
                            break;
                        }
                    }
                    
                }
                else
                {
                    _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 24, ref sharedStringMaxIndex,
                        sharedStringDictionary);
                }
                if (!string.IsNullOrWhiteSpace(sqliteDataReader["UniqueImpact"].ToString()))
                {
                    _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, sqliteDataReader["UniqueImpact"].ToString(), 24, ref sharedStringMaxIndex,
                        sharedStringDictionary);
                }
                else if (!string.IsNullOrWhiteSpace(sqliteDataReader["GroupImpact"].ToString()))
                {
                    foreach (string level in levels)
                    {
                        if (sqliteDataReader["GroupImpact"].ToString().Contains(level))
                        {
                            _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, level, 24, ref sharedStringMaxIndex,
                                sharedStringDictionary);
                            break;
                        }
                    }
                    
                }
                else
                {
                    _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 24, ref sharedStringMaxIndex,
                        sharedStringDictionary);
                }
                string impactDescription = sqliteDataReader["GroupImpactDescription"].ToString().Replace(",", doubleCarriageReturn) + doubleCarriageReturn +
                                          sqliteDataReader["UniqueImpactDescription"];
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, impactDescription, 20,
                    ref sharedStringMaxIndex, sharedStringDictionary);
                if (!string.IsNullOrWhiteSpace(sqliteDataReader["UniqueResidualRisk"].ToString()))
                {
                    _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, sqliteDataReader["UniqueResidualRisk"].ToString(), 24, ref sharedStringMaxIndex,
                        sharedStringDictionary);
                }
                else if (!string.IsNullOrWhiteSpace(sqliteDataReader["GroupResidualRisk"].ToString()))
                {
                    foreach (string level in levels)
                    {
                        if (sqliteDataReader["GroupResidualRisk"].ToString().Contains(level))
                        {
                            _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, level, 24, ref sharedStringMaxIndex,
                                sharedStringDictionary);
                            break;
                        }
                    }
                    
                }
                else
                {
                    _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 24, ref sharedStringMaxIndex,
                        sharedStringDictionary);
                }
                string proposedMitigations = sqliteDataReader["GroupProposedMitigation"].ToString().Replace(",", doubleCarriageReturn) + doubleCarriageReturn +
                                             sqliteDataReader["UniqueProposedMitigation"];
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, proposedMitigations, 20,
                    ref sharedStringMaxIndex, sharedStringDictionary);
                if (!string.IsNullOrWhiteSpace(sqliteDataReader["UniqueResidualRiskAfterProposed"].ToString()))
                {
                    _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, sqliteDataReader["UniqueResidualRiskAfterProposed"].ToString(), 24, ref sharedStringMaxIndex,
                        sharedStringDictionary);
                }
                else if (!string.IsNullOrWhiteSpace(sqliteDataReader["GroupResidualRiskAfterProposed"].ToString()))
                {
                    foreach (string level in levels)
                    {
                        if (sqliteDataReader["GroupResidualRiskAfterProposed"].ToString().Contains(level))
                        {
                            _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, level, 24, ref sharedStringMaxIndex,
                                sharedStringDictionary);
                            break;
                        }
                    }
                    
                }
                else
                {
                    _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 24, ref sharedStringMaxIndex,
                        sharedStringDictionary);
                }
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 20,
                    ref sharedStringMaxIndex, sharedStringDictionary);
                _openXmlWriter.WriteEndElement();
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to write finding to 'Navy RAR'.");
                throw exception;
            }
        }

        private void EndReport()
        {
            try
            {
                _openXmlWriter.WriteEndElement();
                _openXmlWriter.WriteEndElement();
                _openXmlWriter.Dispose();
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to finalize 'Navy RAR' tab.");
                throw exception;
            }
        }
    }
}
