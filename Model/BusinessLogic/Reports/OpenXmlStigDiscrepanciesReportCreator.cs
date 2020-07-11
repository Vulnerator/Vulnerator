using DocumentFormat.OpenXml;
using DocumentFormat.OpenXml.Packaging;
using DocumentFormat.OpenXml.Spreadsheet;
using log4net;
using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SQLite;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.RegularExpressions;
using Vulnerator.Helper;
using Vulnerator.Model.DataAccess;
using Vulnerator.Model.Object;
using Vulnerator.ViewModel;
using File = Vulnerator.Model.Object.File;

namespace Vulnerator.Model.BusinessLogic.Reports
{
    public class OpenXmlStigDiscrepanciesReportCreator
    {
        private Dictionary<string, int> sharedStringDictionary = new Dictionary<string, int>();
        private int sharedStringMaxIndex = 0;
        private int poamRowCounterIndex = 1;
        private UInt32Value sheetIndex = 1;
        private DdlReader _ddlReader = new DdlReader();
        private Assembly assembly = Assembly.GetExecutingAssembly();
        private string _storedProcedureBase = "Vulnerator.Resources.DdlFiles.StoredProcedures.";
        private OpenXmlWriter _openXmlWriter;
        private readonly OpenXmlStylesheetCreator _openXmlStylesheetCreator = new OpenXmlStylesheetCreator();
        private readonly OpenXmlCellDataHandler _openXmlCellDataHandler = new OpenXmlCellDataHandler();

        public string CreateDiscrepanciesReport(string fileName)
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
                    LogWriter.LogStatusUpdate("Creating POA&M workbook framework.");
                    WorkbookPart workbookPart = spreadsheetDocument.AddWorkbookPart();
                    WorkbookStylesPart workbookStylesPart = workbookPart.AddNewPart<WorkbookStylesPart>();
                    workbookStylesPart.Stylesheet = _openXmlStylesheetCreator.CreateStylesheet();
                    Workbook workbook = workbookPart.Workbook = new Workbook();
                    Sheets sheets = workbook.AppendChild(new Sheets());
                    StartPoam(workbookPart, sheets);
                    LogWriter.LogStatusUpdate("Writing POA&M findings.");
                    WriteFindingsToPoam();
                    LogWriter.LogStatusUpdate("Finalizing POA&M workbook.");
                    EndPoam();
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

        private void StartPoam(WorkbookPart workbookPart, Sheets sheets)
        {
            try
            {
                WorksheetPart worksheetPart = workbookPart.AddNewPart<WorksheetPart>();
                Sheet sheet = new Sheet()
                    {Id = workbookPart.GetIdOfPart(worksheetPart), SheetId = sheetIndex, Name = "POA&M"};
                sheetIndex++;
                sheets.Append(sheet);
                _openXmlWriter = OpenXmlWriter.Create(worksheetPart);
                _openXmlWriter.WriteStartElement(new Worksheet());
                WritePoamColumns();
                _openXmlWriter.WriteStartElement(new SheetData());
                _openXmlWriter.WriteElement(new Row() {Hidden = true});
                WritePoamHeaderRowOne();
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to initialize 'POA&M' tab.");
                throw exception;
            }
        }

        private void WritePoamColumns()
        {
            try
            {
                _openXmlWriter.WriteStartElement(new Columns());
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 24.43, Max = 1, Min = 1});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 24.43, Max = 2, Min = 2});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 24.43, Max = 3, Min = 3});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 32.29, Max = 4, Min = 4});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 32.29, Max = 5, Min = 5});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 32.29, Max = 6, Min = 6});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 24.43, Max = 7, Min = 7});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 24.43, Max = 8, Min = 8});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 24.43, Max = 9, Min = 9});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 24.43, Max = 10, Min = 10});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 24.43, Max = 11, Min = 11});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 24.43, Max = 12, Min = 12});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 32.29, Max = 13, Min = 13});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 32.29, Max = 14, Min = 14});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 32.29, Max = 15, Min = 15});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 32.29, Max = 16, Min = 16});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 32.29, Max = 17, Min = 17});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 32.29, Max = 18, Min = 18});
                _openXmlWriter.WriteEndElement();
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to generate 'POA&M' columns.");
                throw exception;
            }
        }

        private void WritePoamHeaderRowOne()
        {
            try
            {
                _openXmlWriter.WriteStartElement(new Row());
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, "Rule ID", 4, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, "STIG ID", 4, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, "Vul (\"V\") ID", 4, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, "Group Title", 4, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, "Vulnerability Title", 4, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, "STIG Name", 4, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, "XCCDF Host", 4, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, "CKL Host", 4, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, "Raw XCCDF Status", 4, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, "Raw CKL Status", 4, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, "Mitigated XCCDF Status", 4, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, "Mitigated CKL Status", 4, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, "CKL Comments", 4, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, "CKL Finding Details", 4, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, "XCCDF Output", 4, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, "XCCDF File Name", 4, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, "CKL File Name", 4, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, "Review Notes", 4, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlWriter.WriteEndElement();
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to generate first 'POA&M' header row.");
                throw exception;
            }
        }

        private void WriteFindingsToPoam()
        {
            try
            {
                using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                {
                    sqliteCommand.CommandText =
                        _ddlReader.ReadDdl(_storedProcedureBase + "Select.StigDiscrepancies.dml", assembly);
                    using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
                    {
                        while (sqliteDataReader.Read())
                        {
                            if (string.IsNullOrWhiteSpace(sqliteDataReader["XccdfStatus"].ToString()) || 
                                string.IsNullOrWhiteSpace(sqliteDataReader["CklStatus"].ToString()) || 
                                sqliteDataReader["XccdfStatus"].Equals(sqliteDataReader["CklStatus"]))
                            {
                                continue;
                            }

                            WriteFindingToPoam(sqliteDataReader);
                        }
                    }
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to write findings to the 'POA&M' workbook.");
                throw exception;
            }
        }

        private void WriteFindingToPoam(SQLiteDataReader sqliteDataReader)
        {
            try
            {
                _openXmlWriter.WriteStartElement(new Row());
                string ruleId =
                    $"{sqliteDataReader["UniqueVulnerabilityIdentifier"]}r{sqliteDataReader["VulnVersion"]}";

                if (!string.IsNullOrWhiteSpace(sqliteDataReader["VulnRelease"].ToString()))
                {
                    ruleId += $".{sqliteDataReader["VulnRelease"]}";
                }

                _openXmlCellDataHandler.WriteCellValue(
                    _openXmlWriter,
                    ruleId,
                    24, ref sharedStringMaxIndex, sharedStringDictionary);

                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter,
                    sqliteDataReader["SecondaryVulnerabilityIdentifier"].ToString(), 24,
                    ref sharedStringMaxIndex, sharedStringDictionary);
                
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter,
                    sqliteDataReader["VulnerabilityGroupIdentifier"].ToString(), 24,
                    ref sharedStringMaxIndex, sharedStringDictionary);
                
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter,
                    sqliteDataReader["VulnerabilityGroupTitle"].ToString(), 24,
                    ref sharedStringMaxIndex, sharedStringDictionary);
                
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter,
                    sqliteDataReader["VulnerabilityTitle"].ToString(), 20,
                    ref sharedStringMaxIndex, sharedStringDictionary);
                
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter,
                    sqliteDataReader["SourceName"].ToString(), 20,
                    ref sharedStringMaxIndex, sharedStringDictionary);
                
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter,
                    sqliteDataReader["XccdfHost"].ToString(), 24,
                    ref sharedStringMaxIndex, sharedStringDictionary);
                
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter,
                    sqliteDataReader["CklHost"].ToString(), 24,
                    ref sharedStringMaxIndex, sharedStringDictionary);
                
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter,
                    sqliteDataReader["XccdfStatus"].ToString(), 24,
                    ref sharedStringMaxIndex, sharedStringDictionary);
                
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter,
                    sqliteDataReader["CklStatus"].ToString(), 24,
                    ref sharedStringMaxIndex, sharedStringDictionary);
                
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter,
                    sqliteDataReader["MitigatedXccdfStatus"].ToString(), 24,
                    ref sharedStringMaxIndex, sharedStringDictionary);
                
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter,
                    sqliteDataReader["MitigatedCklStatus"].ToString(), 24,
                    ref sharedStringMaxIndex, sharedStringDictionary);
                
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter,
                    sqliteDataReader["CklComments"].ToString(), 20,
                    ref sharedStringMaxIndex, sharedStringDictionary);
                
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter,
                    sqliteDataReader["cklFindingDetails"].ToString(), 20,
                    ref sharedStringMaxIndex, sharedStringDictionary);
                
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter,
                    sqliteDataReader["XccdfOutput"].ToString(), 20,
                    ref sharedStringMaxIndex, sharedStringDictionary);
                
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter,
                    sqliteDataReader["XccdfFileName"].ToString(), 20,
                    ref sharedStringMaxIndex, sharedStringDictionary);
                
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter,
                    sqliteDataReader["CklFileName"].ToString(), 20,
                    ref sharedStringMaxIndex, sharedStringDictionary);
                
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter,
                    string.Empty, 20,
                    ref sharedStringMaxIndex, sharedStringDictionary);

                _openXmlWriter.WriteEndElement();
                poamRowCounterIndex++;
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to write finding to 'POA&M'.");
                throw exception;
            }
        }

        private void EndPoam()
        {
            try
            {
                _openXmlWriter.WriteEndElement();
                _openXmlWriter.WriteEndElement();
                _openXmlWriter.Dispose();
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to finalize 'POA&M' tab.");
                throw exception;
            }
        }
    }
}