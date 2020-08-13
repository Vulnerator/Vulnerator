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
    public class OpenXmlEmassPoamReportCreator
    {
        private Dictionary<string, int> sharedStringDictionary = new Dictionary<string, int>();
        private int sharedStringMaxIndex;
        private string ContactOrganization = Properties.Settings.Default.Organization;
        private string ContactName = Properties.Settings.Default.Name;
        private string ContactNumber = Properties.Settings.Default.Phone;
        private string ContactEmail = Properties.Settings.Default.Email;
        private int poamRowCounterIndex = 1;
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

        public string CreateEmassPoam(string fileName)
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
                WritePoamHeaderRowTwo();
                WritePoamHeaderRowThree();
                WritePoamHeaderRowFour();
                WritePoamHeaderRowFive();
                WritePoamHeaderRowSix();
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
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 4.43, Max = 1, Min = 1});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 32.29, Max = 2, Min = 2});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 24.43, Max = 3, Min = 3});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 24.43, Max = 4, Min = 4});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 10.57, Max = 5, Min = 5});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 10.57, Max = 6, Min = 6});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 24.43, Max = 7, Min = 7});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 10.57, Max = 8, Min = 8});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 24.43, Max = 9, Min = 9});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 24.43, Max = 10, Min = 10});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 24.43, Max = 11, Min = 11});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 24.43, Max = 12, Min = 12});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 24.43, Max = 13, Min = 13});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 10.57, Max = 14, Min = 14});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 32.29, Max = 15, Min = 15});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 32.29, Max = 16, Min = 16});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 32.29, Max = 17, Min = 17});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 32.29, Max = 18, Min = 18});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 32.29, Max = 19, Min = 19});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 32.29, Max = 20, Min = 20});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 32.29, Max = 21, Min = 21});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 32.29, Max = 22, Min = 22});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 32.29, Max = 23, Min = 23});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 32.29, Max = 24, Min = 24});
                _openXmlWriter.WriteElement(new Column() {CustomWidth = true, Width = 32.29, Max = 25, Min = 25});
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
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, "Date Exported:", 19, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 19, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, DateTime.Now.ToLongDateString(), 20,
                    ref sharedStringMaxIndex, sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 20, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 20, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 20, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 20, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 20, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, "System Type:", 19, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 20, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 20, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, "OMB Project ID:", 19, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 20, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 20, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 20, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                WritePoamEmptyHeaderCells();
                _openXmlWriter.WriteEndElement();
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to generate first 'POA&M' header row.");
                throw exception;
            }
        }

        private void WritePoamHeaderRowTwo()
        {
            try
            {
                _openXmlWriter.WriteStartElement(new Row());
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, "Exported By:", 19, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 19, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, ContactName, 20, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 20, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 20, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 20, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 20, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 20, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 19, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 20, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 20, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 19, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 20, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 20, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 20, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                WritePoamEmptyHeaderCells();
                _openXmlWriter.WriteEndElement();
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to generate second 'POA&M' header row.");
                throw exception;
            }
        }

        private void WritePoamHeaderRowThree()
        {
            try
            {
                _openXmlWriter.WriteStartElement(new Row());
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, "DoD Component:", 19, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 19, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 20, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 20, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 20, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 20, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 20, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 20, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, "POC Name:", 19, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, ContactName, 20, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 20, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 19, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 19, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 19, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 19, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                WritePoamEmptyHeaderCells();
                _openXmlWriter.WriteEndElement();
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to generate third 'POA&M' header row.");
                throw exception;
            }
        }

        private void WritePoamHeaderRowFour()
        {
            try
            {
                _openXmlWriter.WriteStartElement(new Row());
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, @"System / Project Name:", 19,
                    ref sharedStringMaxIndex, sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 19, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, ContactName, 20, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 20, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 20, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 20, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 20, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 20, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, "POC Phone:", 19, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, ContactNumber, 20, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 20, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, "Security Costs:", 19, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 20, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 20, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 20, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                WritePoamEmptyHeaderCells();
                _openXmlWriter.WriteEndElement();
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to generate fourth 'POA&M' header row.");
                throw exception;
            }
        }

        private void WritePoamHeaderRowFive()
        {
            try
            {
                _openXmlWriter.WriteStartElement(new Row());
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, "DoD IT Registration No:", 19,
                    ref sharedStringMaxIndex, sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 19, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 20, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 20, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 20, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 20, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 20, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 20, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, "POC Email:", 19, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, ContactEmail, 20, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 20, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 19, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 19, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 19, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 19, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                WritePoamEmptyHeaderCells();
                _openXmlWriter.WriteEndElement();
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to generate fifth POA&M header row.");
                throw exception;
            }
        }

        private void WritePoamEmptyHeaderCells()
        {
            try
            {
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 19, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 19, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 19, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 19, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 19, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 19, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 19, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 19, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 19, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 19, ref sharedStringMaxIndex,
                    sharedStringDictionary);
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to generate POA&M header row empty cell placeholders.");
                throw exception;
            }
        }

        private void WritePoamHeaderRowSix()
        {
            try
            {
                _openXmlWriter.WriteStartElement(new Row());
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, "Control Vulnerability Description", 16,
                    ref sharedStringMaxIndex, sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 16, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter,
                    "Security Control Number (NC/NA controls only)", 16, ref sharedStringMaxIndex, sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, "Office/Org", 16, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, "Security Checks", 16, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, "Resources Required", 16, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, "Scheduled Completion Date", 16,
                    ref sharedStringMaxIndex, sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, "Milestone with Completion Dates", 16,
                    ref sharedStringMaxIndex, sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, "Milestone Changes", 16, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, "Source Identifying Control Vulnerability",
                    16, ref sharedStringMaxIndex, sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, "Status", 16, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, "Comments", 16, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, "Raw Severity", 16,
                    ref sharedStringMaxIndex, sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, "Devices Affected", 16, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter,
                    "Mitigations (in-house and in conjunction with the Navy CSSP)", 16, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, "Predisposing Conditions", 16,
                    ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, "Severity", 16, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, "Relevance of Threat", 16, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, "Threat Description", 16, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, "Likelihood", 16, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, "Impact", 16, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, "Impact Description", 16, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, "Residual Risk Level", 16, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, "Recommendations", 16, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter,
                    "Resulting Residual Risk after Proposed Mitigations", 16, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlWriter.WriteEndElement();

                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, "", 16, ref sharedStringMaxIndex,
                    sharedStringDictionary);
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to generate sixth 'POA&M' header row.");
                throw exception;
            }
        }

        private void WriteFindingsToPoam()
        {
            try
            {
                using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                {
                    sqliteCommand.Parameters.Add(new SQLiteParameter("UserName",
                        Properties.Settings.Default.ActiveUser));
                    FilterTextCreator filterTextCreator = new FilterTextCreator();
                    string findingTypeFilter = filterTextCreator.FindingType(sqliteCommand, "eMASS-Importable POA&M");
                    string groupFilter = filterTextCreator.Group(sqliteCommand, "eMASS-Importable POA&M");
                    string severityFilter = filterTextCreator.Severity(sqliteCommand, "eMASS-Importable POA&M");
                    string statusFilter = filterTextCreator.Status(sqliteCommand, "eMASS-Importable POA&M");
                    string rmfOverrideFilter = filterTextCreator.RmfOverride(sqliteCommand, "eMASS-Importable POA&M");
                    sqliteCommand.CommandText =
                        _ddlReader.ReadDdl(_storedProcedureBase + "Select.EmassPoamVulnerabilities.dml", assembly);

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

                            sqliteCommand.CommandText = string.IsNullOrWhiteSpace(rmfOverrideFilter) ? 
                                sqliteCommand.CommandText.Insert(regex.Match(sqliteCommand.CommandText).Index, $"(RawStatus {statusFilter} OR UniqueMitigatedStatus {statusFilter}) ") : 
                                sqliteCommand.CommandText.Insert(regex.Match(sqliteCommand.CommandText).Index, $"(RawStatus {statusFilter} OR UniqueMitigatedStatus {statusFilter} OR GroupMitigatedStatus {statusFilter}) ");
                            regex = new Regex(Properties.Resources.RegexGroupsMitigationsOrConditionsVulnerabilities);
                            sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(regex.Match(sqliteCommand.CommandText).Index, $"{Environment.NewLine}WHERE (MitigatedStatus {statusFilter}) ");
                        }
                        sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(regex.Match(sqliteCommand.CommandText).Index, Environment.NewLine);
                    }

                    if (!string.IsNullOrWhiteSpace(rmfOverrideFilter))
                    {
                        Regex regex = new Regex(Properties.Resources.RegexSqlFindingTypes);
                        sqliteCommand.CommandText =
                            sqliteCommand.CommandText.Insert(regex.Match(sqliteCommand.CommandText).Index,
                                rmfOverrideFilter);
                        regex = new Regex(Properties.Resources.RegexSqlFromUniqueFindings);
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
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, poamRowCounterIndex.ToString(), 16,
                    ref sharedStringMaxIndex, sharedStringDictionary);
                string descriptionCellValue =
                    $"Title: {Environment.NewLine}{sqliteDataReader["VulnerabilityTitle"]}{doubleCarriageReturn}" +
                    $"Description:{Environment.NewLine}{sqliteDataReader["VulnerabilityDescription"]}";

                _openXmlCellDataHandler.WriteCellValue(
                    _openXmlWriter,
                    descriptionCellValue,
                    20, ref sharedStringMaxIndex, sharedStringDictionary);

                if (!string.IsNullOrWhiteSpace(sqliteDataReader["NIST_Controls"].ToString()))
                {
                    _openXmlCellDataHandler.WriteCellValue(_openXmlWriter,
                        sqliteDataReader["NIST_Controls"].ToString().Replace(",", Environment.NewLine), 24, ref sharedStringMaxIndex, sharedStringDictionary);
                }
                else
                {
                    _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 24, ref sharedStringMaxIndex,
                        sharedStringDictionary);
                }

                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter,
                    ContactOrganization + ", " + ContactName + ", " + ContactNumber + ", " + ContactEmail, 20,
                    ref sharedStringMaxIndex, sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter,
                    sqliteDataReader["UniqueVulnerabilityIdentifier"].ToString(), 24, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 20, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                if (sqliteDataReader.HasColumn("GroupEstimatedCompletionDate") && !string.IsNullOrWhiteSpace(sqliteDataReader["GroupEstimatedCompletionDate"].ToString()))
                {
                    _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, DateTime.Parse(sqliteDataReader["GroupEstimatedCompletionDate"].ToString()).ToShortDateString(), 20, ref sharedStringMaxIndex,
                        sharedStringDictionary);
                }
                else if (!string.IsNullOrWhiteSpace(sqliteDataReader["UniqueEstimatedCompletionDate"].ToString()))
                {
                    _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, sqliteDataReader["UniqueEstimatedCompletionDate"].ToString(), 20, ref sharedStringMaxIndex,
                        sharedStringDictionary);
                }
                else
                {
                    _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 20, ref sharedStringMaxIndex,
                        sharedStringDictionary);
                }
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 20, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 20, ref sharedStringMaxIndex,
                    sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, sqliteDataReader["VulnSourceName"] + " :: " +
                                                                       sqliteDataReader["VulnSourceVersion"] + "." +
                                                                       sqliteDataReader["VulnSourceRelease"], 24,
                    ref sharedStringMaxIndex, sharedStringDictionary);
                if (sqliteDataReader.HasColumn("GroupMitigatedStatus") && !string.IsNullOrWhiteSpace(sqliteDataReader["GroupMitigatedStatus"].ToString()))
                {
                    _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, sqliteDataReader["GroupMitigatedStatus"].ToString(), 24,
                        ref sharedStringMaxIndex, sharedStringDictionary);
                }
                else if (!string.IsNullOrWhiteSpace(sqliteDataReader["UniqueMitigatedStatus"].ToString()))
                {
                    _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, sqliteDataReader["UniqueMitigatedStatus"].ToString(), 24,
                        ref sharedStringMaxIndex, sharedStringDictionary);
                }
                else
                {
                    {
                        _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, sqliteDataReader["RawStatus"].ToString(), 24,
                            ref sharedStringMaxIndex, sharedStringDictionary);
                    }
                }
                // TODO: Parameterize this to make using comments and/or finding details optional
                string comments = sqliteDataReader["Comments"] + doubleCarriageReturn + sqliteDataReader["FindingDetails"];
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, comments, 20,
                    ref sharedStringMaxIndex, sharedStringDictionary);
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, sqliteDataReader["PrimaryRawRiskIndicator"].ToString(), 24,
                    ref sharedStringMaxIndex, sharedStringDictionary);
                if (!string.IsNullOrWhiteSpace(sqliteDataReader["DisplayedSoftwareName"].ToString()))
                {
                    _openXmlCellDataHandler.WriteCellValue(_openXmlWriter,
                        sqliteDataReader["DisplayedSoftwareName"].ToString().Replace(",", Environment.NewLine), 20, ref sharedStringMaxIndex,
                        sharedStringDictionary);
                }
                else
                {
                    _openXmlCellDataHandler.WriteCellValue(_openXmlWriter,
                        sqliteDataReader["HostName"].ToString().Replace(",", Environment.NewLine), 20, ref sharedStringMaxIndex,
                        sharedStringDictionary);
                }
                string technicalMitigation = sqliteDataReader["UniqueTechnicalMitigation"].ToString();
                if (!string.IsNullOrWhiteSpace(sqliteDataReader["GroupTechnicalMitigations"].ToString()))
                {
                    technicalMitigation = technicalMitigation.Insert(0, sqliteDataReader["GroupTechnicalMitigations"].ToString().Replace(",", doubleCarriageReturn) + doubleCarriageReturn);
                }
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, technicalMitigation, 20,
                    ref sharedStringMaxIndex, sharedStringDictionary);
                string predisposingConditions = sqliteDataReader["UniquePredisposingConditions"].ToString();
                if (!string.IsNullOrWhiteSpace(sqliteDataReader["GroupPredisposingConditions"].ToString()))
                {
                    predisposingConditions = predisposingConditions.Insert(0, sqliteDataReader["GroupPredisposingConditions"].ToString().Replace(",", doubleCarriageReturn) + doubleCarriageReturn);
                }
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, predisposingConditions, 20,
                    ref sharedStringMaxIndex, sharedStringDictionary);
                if (sqliteDataReader.HasColumn("GroupSeverityPervasiveness") && !string.IsNullOrWhiteSpace(sqliteDataReader["GroupSeverityPervasiveness"].ToString()))
                {
                    _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, sqliteDataReader["GroupSeverityPervasiveness"].ToString(), 24, ref sharedStringMaxIndex,
                        sharedStringDictionary);
                }
                else if (!string.IsNullOrWhiteSpace(sqliteDataReader["UniqueSeverityPervasiveness"].ToString()))
                {
                    _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, sqliteDataReader["UniqueSeverityPervasiveness"].ToString(), 24, ref sharedStringMaxIndex,
                        sharedStringDictionary);
                }
                else
                {
                    _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 24, ref sharedStringMaxIndex,
                        sharedStringDictionary);
                }
                if (sqliteDataReader.HasColumn("GroupThreatRelevance") && !string.IsNullOrWhiteSpace(sqliteDataReader["GroupThreatRelevance"].ToString()))
                {
                    _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, sqliteDataReader["GroupThreatRelevance"].ToString(), 24, ref sharedStringMaxIndex,
                        sharedStringDictionary);
                    
                }
                else if (!string.IsNullOrWhiteSpace(sqliteDataReader["UniqueThreatRelevance"].ToString()))
                {
                    _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, sqliteDataReader["UniqueThreatRelevance"].ToString(), 24, ref sharedStringMaxIndex,
                        sharedStringDictionary);
                }
                else
                {
                    _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 24, ref sharedStringMaxIndex,
                        sharedStringDictionary);
                }
                string threatDescription = sqliteDataReader["UniqueThreatDescription"].ToString();
                if (!string.IsNullOrWhiteSpace(sqliteDataReader["GroupThreatDescription"].ToString()))
                {
                    threatDescription = threatDescription.Insert(0,
                        sqliteDataReader["GroupThreatDescription"].ToString().Replace(",", doubleCarriageReturn) +
                        doubleCarriageReturn);
                }
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, threatDescription, 20,
                    ref sharedStringMaxIndex, sharedStringDictionary);
                if (sqliteDataReader.HasColumn("GroupLikelihood") && !string.IsNullOrWhiteSpace(sqliteDataReader["GroupLikelihood"].ToString()))
                {
                    _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, sqliteDataReader["GroupLikelihood"].ToString(), 24, ref sharedStringMaxIndex,
                        sharedStringDictionary);
                }
                else if (!string.IsNullOrWhiteSpace(sqliteDataReader["UniqueLikelihood"].ToString()))
                {
                    _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, sqliteDataReader["UniqueLikelihood"].ToString(), 24, ref sharedStringMaxIndex,
                        sharedStringDictionary);
                }
                else
                {
                    _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 24, ref sharedStringMaxIndex,
                        sharedStringDictionary);
                }
                if (sqliteDataReader.HasColumn("GroupImpact") && !string.IsNullOrWhiteSpace(sqliteDataReader["GroupImpact"].ToString()))
                {
                    _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, sqliteDataReader["GroupImpact"].ToString(), 24, ref sharedStringMaxIndex,
                        sharedStringDictionary);
                }
                else if (!string.IsNullOrWhiteSpace(sqliteDataReader["UniqueImpact"].ToString()))
                {
                    _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, sqliteDataReader["UniqueImpact"].ToString(), 24, ref sharedStringMaxIndex,
                        sharedStringDictionary);
                }
                else
                {
                    _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 24, ref sharedStringMaxIndex,
                        sharedStringDictionary);
                }
                string impactDescription = sqliteDataReader["UniqueImpactDescription"].ToString();
                if (!string.IsNullOrWhiteSpace(sqliteDataReader["GroupImpactDescription"].ToString()))
                {
                    impactDescription = impactDescription.Insert(0,
                        sqliteDataReader["GroupImpactDescription"].ToString().Replace(",", doubleCarriageReturn) +
                        doubleCarriageReturn);
                }
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, impactDescription, 20,
                    ref sharedStringMaxIndex, sharedStringDictionary);
                if (sqliteDataReader.HasColumn("GroupResidualRisk") && !string.IsNullOrWhiteSpace(sqliteDataReader["GroupResidualRisk"].ToString()))
                {
                    _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, sqliteDataReader["GroupResidualRisk"].ToString(), 24, ref sharedStringMaxIndex,
                        sharedStringDictionary);
                }
                else if (!string.IsNullOrWhiteSpace(sqliteDataReader["UniqueResidualRisk"].ToString()))
                {
                    _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, sqliteDataReader["UniqueResidualRisk"].ToString(), 24, ref sharedStringMaxIndex,
                        sharedStringDictionary);
                }
                else
                {
                    _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 24, ref sharedStringMaxIndex,
                        sharedStringDictionary);
                }
                string proposedMitigations = sqliteDataReader["UniqueProposedMitigation"].ToString();
                if (!string.IsNullOrWhiteSpace(sqliteDataReader["GroupProposedMitigations"].ToString()))
                {
                    proposedMitigations = proposedMitigations.Insert(0,
                        sqliteDataReader["GroupProposedMitigations"].ToString().Replace(",", doubleCarriageReturn) +
                        doubleCarriageReturn);
                }
                _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, proposedMitigations, 20,
                    ref sharedStringMaxIndex, sharedStringDictionary);
                if (sqliteDataReader.HasColumn("GroupResidualRiskAfterProposed") && !string.IsNullOrWhiteSpace(sqliteDataReader["GroupResidualRiskAfterProposed"].ToString()))
                {
                    _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, sqliteDataReader["GroupResidualRiskAfterProposed"].ToString(), 24, ref sharedStringMaxIndex,
                        sharedStringDictionary);
                }
                else if (!string.IsNullOrWhiteSpace(sqliteDataReader["UniqueResidualRiskAfterProposed"].ToString()))
                {
                    _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, sqliteDataReader["UniqueResidualRiskAfterProposed"].ToString(), 24, ref sharedStringMaxIndex,
                        sharedStringDictionary);
                }
                else
                {
                    _openXmlCellDataHandler.WriteCellValue(_openXmlWriter, string.Empty, 24, ref sharedStringMaxIndex,
                        sharedStringDictionary);
                }
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
                WritePoamMergeCells();
                _openXmlWriter.WriteEndElement();
                _openXmlWriter.Dispose();
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to finalize 'POA&M' tab.");
                throw exception;
            }
        }

        private void WritePoamMergeCells()
        {
            try
            {
                string[] mergeCellArray = new string[]
                {
                    "A1:O1", "A2:B2", "A3:B3", "A4:B4", "A5:B5", "A6:B6", "A7:B7", "C2:H2", "C3:H3",
                    "C4:H4", "C5:H5", "C6:H6", "I2:I3", "J2:K3", "J4:K4", "J5:K5", "J6:K6", "L2:L3",
                    "M2:O3", "M5:O5", "L4:O4", "L6:O6"
                };
                _openXmlWriter.WriteStartElement(new MergeCells());
                foreach (string mergeCell in mergeCellArray)
                {
                    _openXmlWriter.WriteElement(new MergeCell() {Reference = mergeCell});
                }

                _openXmlWriter.WriteEndElement();
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to generate 'POA&M' 'MergeCells' element.");
                throw exception;
            }
        }
    }
}