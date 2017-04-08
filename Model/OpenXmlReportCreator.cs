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
using System.Security;
using System.Text.RegularExpressions;

namespace Vulnerator.Model
{
    /// <summary>
    /// Class housing all methods and items required to create the Excel reports using the OpenXml SDK.
    /// </summary>
    class OpenXmlReportCreator
    {
        #region Member Variables

        private int IavmFilterOne { get { return int.Parse(ConfigAlter.ReadSettingsFromDictionary("iavmFilterOne")); } }
        private int IavmFilterTwo { get { return int.Parse(ConfigAlter.ReadSettingsFromDictionary("iavmFilterTwo")); } }
        private int IavmFilterThree { get { return int.Parse(ConfigAlter.ReadSettingsFromDictionary("iavmFilterThree")); } }
        private int IavmFilterFour { get { return int.Parse(ConfigAlter.ReadSettingsFromDictionary("iavmFilterFour")); } }
        private bool IncludeOngoingFindings { get { return bool.Parse(ConfigAlter.ReadSettingsFromDictionary("cbOpen")); } }
        private bool IncludeCompletedFindings { get { return bool.Parse(ConfigAlter.ReadSettingsFromDictionary("cbCompleted")); } }
        private bool IncludeNotApplicableFindings { get { return bool.Parse(ConfigAlter.ReadSettingsFromDictionary("cbNotApplicable")); } }
        private bool IncludeNotReviewedFindings { get { return bool.Parse(ConfigAlter.ReadSettingsFromDictionary("cbNotReviewed")); } }
        private bool IncludeCriticalFindings { get { return bool.Parse(ConfigAlter.ReadSettingsFromDictionary("cbCritical")); } }
        private bool IncludeHighFindings { get { return bool.Parse(ConfigAlter.ReadSettingsFromDictionary("cbHigh")); } }
        private bool IncludeMediumFindings { get { return bool.Parse(ConfigAlter.ReadSettingsFromDictionary("cbMedium")); } }
        private bool IncludeLowFindings { get { return bool.Parse(ConfigAlter.ReadSettingsFromDictionary("cbLow")); } }
        private bool IncludeInformationalFindings { get { return bool.Parse(ConfigAlter.ReadSettingsFromDictionary("cbInfo")); } }
        private bool IncludCatIFindings { get { return bool.Parse(ConfigAlter.ReadSettingsFromDictionary("cbCatI")); } }
        private bool IncludCatIIFindings { get { return bool.Parse(ConfigAlter.ReadSettingsFromDictionary("cbCatII")); } }
        private bool IncludCatIIIFindings { get { return bool.Parse(ConfigAlter.ReadSettingsFromDictionary("cbCatIII")); } }
        private bool IncludCatIVFindings { get { return bool.Parse(ConfigAlter.ReadSettingsFromDictionary("cbCatIV")); } }
        private bool IsDiacapPackage { get { return bool.Parse(ConfigAlter.ReadSettingsFromDictionary("rbDiacap")); } }
        private bool RevisionThreeSelected { get { return bool.Parse(ConfigAlter.ReadSettingsFromDictionary("revisionThreeRadioButton")); } }
        private bool AssetOverviewTabIsNeeded { get { return bool.Parse(ConfigAlter.ReadSettingsFromDictionary("cbAssetOverview")); } }
        private bool PoamAndRarTabsAreNeeded { get { return bool.Parse(ConfigAlter.ReadSettingsFromDictionary("cbPoamRar")); } }
        private bool DiscrepanciesTabIsNeeded { get { return bool.Parse(ConfigAlter.ReadSettingsFromDictionary("cbDiscrepancies")); } }
        private bool AcasOutputTabIsNeeded { get { return bool.Parse(ConfigAlter.ReadSettingsFromDictionary("cbAcasOutput")); } }
        private bool StigDetailsTabIsNeeded { get { return bool.Parse(ConfigAlter.ReadSettingsFromDictionary("cbStigDetails")); } }
        private bool FprDetailsTabIsNeeded { get { return bool.Parse(ConfigAlter.ReadSettingsFromDictionary("cbFprDetails")); } }
        private bool AcasFindingsShouldBeMerged { get { return bool.Parse(ConfigAlter.ReadSettingsFromDictionary("cbMergeAcas")); } }
        private bool CklFindingsShouldBeMerged { get { return bool.Parse(ConfigAlter.ReadSettingsFromDictionary("cbMergeCkl")); } }
        private bool XccdfFindingsShouldBeMerged { get { return bool.Parse(ConfigAlter.ReadSettingsFromDictionary("cbMergeXccdf")); } }
        private bool WasspFindingsShouldBeMerged { get { return bool.Parse(ConfigAlter.ReadSettingsFromDictionary("cbMergeWassp")); } }
        private bool FprFindingsShouldBeMerged { get { return bool.Parse(ConfigAlter.ReadSettingsFromDictionary("cbMergeFpr")); } }
        private bool UserRequiresComments { get { return bool.Parse(ConfigAlter.ReadSettingsFromDictionary("cbComments")); } }
        private bool UserRequiresFindingDetails { get { return bool.Parse(ConfigAlter.ReadSettingsFromDictionary("cbFindingDetails")); } }
        private bool TestPlanIsRequired { get { return bool.Parse(ConfigAlter.ReadSettingsFromDictionary("cbTestPlan")); } }
        private Dictionary<string, int> sharedStringDictionary = new Dictionary<string, int>();
        private int sharedStringMaxIndex = 0;
        private string ContactOrganization = ConfigAlter.ReadSettingsFromDictionary("tbEmassOrg");
        private string ContactName = ConfigAlter.ReadSettingsFromDictionary("tbEmassName");
        private string ContactNumber = ConfigAlter.ReadSettingsFromDictionary("tbEmassNumber");
        private string ContactEmail = ConfigAlter.ReadSettingsFromDictionary("tbEmassEmail");
        private int poamRowCounterIndex = 1;
        private int assetOverviewRowCounterIndex = 1;
        private int testPlanRowCounterIndex = 1;
        private List<string> assetOverviewMergeCellReferences = new List<string>();
        private List<string> testPlanMergeCellReferences = new List<string>();
        private UInt32Value sheetIndex = 1;
        private string[] delimiter = new string[] { ",\r\n" };
        string doubleCarriageReturn = Environment.NewLine + Environment.NewLine;
        private static readonly ILog log = LogManager.GetLogger(typeof(Logger));

        private OpenXmlWriter assetOverviewOpenXmlWriter;
        private OpenXmlWriter poamOpenXmlWriter;
        private OpenXmlWriter rarOpenXmlWriter;
        private OpenXmlWriter acasOutputOpenXmlWriter;
        private OpenXmlWriter discrepanciesOpenXmlWriter;
        private OpenXmlWriter stigDetailsOpenXmlWriter;
        private OpenXmlWriter fprDetailsOpenXmlWriter;
        private OpenXmlWriter testPlanOpenXmlWriter;

        #endregion Member Variables

        public string CreateExcelReport(string fileName, AsyncObservableCollection<MitigationItem> mitigationList)
        {
            try
            {
                using (SpreadsheetDocument spreadsheetDocument = SpreadsheetDocument.Create(fileName, SpreadsheetDocumentType.Workbook))
                {
                    log.Info("Creating workbook framework.");
                    WorkbookPart workbookPart = spreadsheetDocument.AddWorkbookPart();
                    WorkbookStylesPart workbookStylesPart = workbookPart.AddNewPart<WorkbookStylesPart>();
                    workbookStylesPart.Stylesheet = CreateStylesheet();
                    Workbook workbook = workbookPart.Workbook = new Workbook();
                    Sheets sheets = workbook.AppendChild(new Sheets());
                    StartSpreadsheets(workbookPart, sheets);

                    if (AssetOverviewTabIsNeeded)
                    {
                        log.Info("Creating Asset Overview tab.");
                        if (CountVulnerabilitiesByFindingType("ACAS") > 0)
                        {
                            WriteFindingTypeHeaderRowOne("ACAS");
                            WriteFindingTypeHeaderRowTwo("ACAS");
                            WriteAssetOverviewItems("ACAS");
                        }
                        if (CountVulnerabilitiesByFindingType("CKL") > 0)
                        {
                            WriteFindingTypeHeaderRowOne("CKL");
                            WriteFindingTypeHeaderRowTwo("CKL");
                            WriteAssetOverviewItems("CKL");
                        }
                        if (CountVulnerabilitiesByFindingType("XCCDF") > 0)
                        {
                            WriteFindingTypeHeaderRowOne("XCCDF");
                            WriteFindingTypeHeaderRowTwo("XCCDF");
                            WriteAssetOverviewItems("XCCDF");
                        }
                        if (CountVulnerabilitiesByFindingType("WASSP") > 0)
                        {
                            WriteFindingTypeHeaderRowOne("WASSP");
                            WriteFindingTypeHeaderRowTwo("WASSP");
                            WriteAssetOverviewItems("WASSP");
                        }
                        if (CountVulnerabilitiesByFindingType("FPR") > 0)
                        {
                            WriteFindingTypeHeaderRowOne("FPR");
                            WriteFindingTypeHeaderRowTwo("FPR");
                            WriteAssetOverviewItems("FPR");
                        }
                    }

                    if (TestPlanIsRequired)
                    {
                        log.Info("Creating Test Plan tab.");
                        WriteTestPlanHeaderRowOne();
                        WriteTestPlanHeaderRowTwo();
                        WriteTestPlanHeaderRowThree();
                        ObtainTestPlanItems("ACAS");
                        ObtainTestPlanItems("XCCDF");
                        ObtainTestPlanItems("CKL");
                        ObtainTestPlanItems("FPR");
                    }

                    if (PoamAndRarTabsAreNeeded)
                    {
                        log.Info("Creating POA&M and RAR tabs.");
                        WriteFindingsToPoamAndRar("ACAS", AcasFindingsShouldBeMerged, mitigationList);
                        WriteFindingsToPoamAndRar("CKL", CklFindingsShouldBeMerged, mitigationList);
                        WriteFindingsToPoamAndRar("XCCDF", XccdfFindingsShouldBeMerged, mitigationList);
                        WriteFindingsToPoamAndRar("WASSP", WasspFindingsShouldBeMerged, mitigationList);
                        WriteFindingsToPoamAndRar("FPR", FprFindingsShouldBeMerged, mitigationList);
                    }

                    if (AcasOutputTabIsNeeded)
                    {
                        log.Info("Creating ACAS Output tab.");
                        WriteIndividualAcasOutput();
                    }

                    if (DiscrepanciesTabIsNeeded)
                    {
                        log.Info("Creating Discrepancies tab.");
                        WriteIndividualDiscrepancies(mitigationList);
                    }

                    if (StigDetailsTabIsNeeded)
                    {
                        log.Info("Creating STIG Details tab.");
                        WriteStigDetailItems("CKL");
                        WriteStigDetailItems("XCCDF");
                    }

                    if (FprDetailsTabIsNeeded)
                    {
                        log.Info("Creating Fortify Details tab.");
                        WriteFprDetailsItems("FPR");
                    }

                    log.Info("Finalizing workbook.");
                    EndSpreadsheets();
                    CreateSharedStringPart(workbookPart);
                }

                return "Excel report creation successful";
            }
            catch (Exception exception)
            {
                log.Error("Unable to create " + fileName + " (Excel Report).");
                log.Debug("Exception details: " + exception);
                return "Excel report creation failed - see log for details";
            }
        }

        private void StartSpreadsheets(WorkbookPart workbookPart, Sheets sheets)
        {
            try
            {
                if (AssetOverviewTabIsNeeded)
                { StartAssetOverview(workbookPart, sheets); }
                if (TestPlanIsRequired)
                { StartTestPlan(workbookPart, sheets); }
                if (PoamAndRarTabsAreNeeded)
                {
                    StartPoam(workbookPart, sheets);
                    StartRar(workbookPart, sheets);
                }
                if (AcasOutputTabIsNeeded)
                { StartAcasOutput(workbookPart, sheets); }
                if (DiscrepanciesTabIsNeeded)
                { StartDiscrepancies(workbookPart, sheets); }
                if (StigDetailsTabIsNeeded)
                { StartStigDetails(workbookPart, sheets); }
                if (FprDetailsTabIsNeeded)
                { StartFprDetails(workbookPart, sheets); }
            }
            catch (Exception exception)
            {
                log.Error("Spreadsheet creation failed to initialize properly.");
                throw exception;
            }
        }

        private void WriteFindingsToPoamAndRar(string findingType, bool findingsAreMerged, AsyncObservableCollection<MitigationItem> mitigationList)
        {
            try
            {
                using (SQLiteCommand sqliteCommand = FindingsDatabaseActions.sqliteConnection.CreateCommand())
                {
                    sqliteCommand.Parameters.Add(new SQLiteParameter("FindingType", findingType));
                    sqliteCommand.CommandText = SetSqliteCommandText(findingsAreMerged, findingType);
                    using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
                    {
                        while (sqliteDataReader.Read())
                        {
                            if (sqliteDataReader["VulnId"].ToString().Equals("Plugin"))
                            { continue; }
                            if (!FilterBySeverity(sqliteDataReader["Impact"].ToString(), sqliteDataReader["RawRisk"].ToString()))
                            { continue; }
                            if (!FilterByStatus(sqliteDataReader["Status"].ToString()))
                            { continue; }

                            WriteFindingToPoam(sqliteDataReader, mitigationList);
                            WriteFindingToRar(sqliteDataReader, mitigationList);
                        }
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to write findings to the POA&M and/or RAR tab(s).");
                throw exception;
            }
        }

        private void EndSpreadsheets()
        {
            try
            {
                if (AssetOverviewTabIsNeeded)
                { EndAssetOverview(); }
                if (TestPlanIsRequired)
                { EndTestPlan(); }
                if (PoamAndRarTabsAreNeeded)
                {
                    EndPoam();
                    EndRar();
                }
                if (AcasOutputTabIsNeeded)
                { EndAcasOutput(); }
                if (DiscrepanciesTabIsNeeded)
                { EndDiscrepancies(); }
                if (StigDetailsTabIsNeeded)
                { EndStigDetails(); }
                if (FprDetailsTabIsNeeded)
                { EndFprDetails(); }
            }
            catch (Exception exception)
            {
                log.Error("Unable to finalize spreadsheets.");
                throw exception;
            }
        }

        #region Create Asset Overview

        private void StartAssetOverview(WorkbookPart workbookPart, Sheets sheets)
        {
            try
            {
                WorksheetPart worksheetPart = workbookPart.AddNewPart<WorksheetPart>();
                Sheet sheet = new Sheet() { Id = workbookPart.GetIdOfPart(worksheetPart), SheetId = sheetIndex, Name = "Asset Overview" };
                sheetIndex++;
                sheets.Append(sheet);
                assetOverviewOpenXmlWriter = OpenXmlWriter.Create(worksheetPart);
                assetOverviewOpenXmlWriter.WriteStartElement(new Worksheet());
                WriteAssetOverviewColumns();
                assetOverviewOpenXmlWriter.WriteStartElement(new SheetData());
                WriteAssetOverviewHeaderRowOne();
            }
            catch (Exception exception)
            {
                log.Error("Unable to initialize Asset Overview tab.");
                throw exception;
            }
        }

        private void WriteAssetOverviewColumns()
        {
            try
            {
                assetOverviewOpenXmlWriter.WriteStartElement(new Columns());
                assetOverviewOpenXmlWriter.WriteElement(new Column() { Min = 1U, Max = 1U, Width = 30d, CustomWidth = true });
                assetOverviewOpenXmlWriter.WriteElement(new Column() { Min = 2U, Max = 2U, Width = 30d, CustomWidth = true });
                assetOverviewOpenXmlWriter.WriteElement(new Column() { Min = 3U, Max = 3U, Width = 30d, CustomWidth = true });
                assetOverviewOpenXmlWriter.WriteElement(new Column() { Min = 4U, Max = 4U, Width = 60d, CustomWidth = true });
                assetOverviewOpenXmlWriter.WriteElement(new Column() { Min = 5U, Max = 5U, Width = 30d, CustomWidth = true });
                assetOverviewOpenXmlWriter.WriteElement(new Column() { Min = 7U, Max = 7U, Width = 15d, CustomWidth = true });
                assetOverviewOpenXmlWriter.WriteElement(new Column() { Min = 8U, Max = 8U, Width = 15d, CustomWidth = true });
                assetOverviewOpenXmlWriter.WriteElement(new Column() { Min = 9U, Max = 9U, Width = 15d, CustomWidth = true });
                assetOverviewOpenXmlWriter.WriteElement(new Column() { Min = 10U, Max = 10U, Width = 15d, CustomWidth = true });
                assetOverviewOpenXmlWriter.WriteElement(new Column() { Min = 11U, Max = 11U, Width = 15d, CustomWidth = true });
                assetOverviewOpenXmlWriter.WriteElement(new Column() { Min = 12U, Max = 12U, Width = 15d, CustomWidth = true });
                assetOverviewOpenXmlWriter.WriteEndElement();
            }
            catch (Exception exception)
            {
                log.Error("Unable to generate Asset Overview tab columns.");
                throw exception;
            }
        }

        private void WriteAssetOverviewHeaderRowOne()
        {
            try
            {
                assetOverviewOpenXmlWriter.WriteStartElement(new Row());
                WriteCellValue(assetOverviewOpenXmlWriter, "Asset Overview", 3);
                WriteCellValue(assetOverviewOpenXmlWriter, string.Empty, 3);
                WriteCellValue(assetOverviewOpenXmlWriter, string.Empty, 3);
                WriteCellValue(assetOverviewOpenXmlWriter, string.Empty, 3);
                WriteCellValue(assetOverviewOpenXmlWriter, string.Empty, 3);
                WriteCellValue(assetOverviewOpenXmlWriter, string.Empty, 3);
                WriteCellValue(assetOverviewOpenXmlWriter, string.Empty, 3);
                WriteCellValue(assetOverviewOpenXmlWriter, string.Empty, 3);
                WriteCellValue(assetOverviewOpenXmlWriter, string.Empty, 3);
                WriteCellValue(assetOverviewOpenXmlWriter, string.Empty, 3);
                WriteCellValue(assetOverviewOpenXmlWriter, string.Empty, 3);
                assetOverviewOpenXmlWriter.WriteEndElement();
                assetOverviewRowCounterIndex++;
            }
            catch (Exception exception)
            {
                log.Error("Unable to generate first Asset Overview header row.");
                throw exception;
            }
        }

        private void WriteFindingTypeHeaderRowOne(string findingType)
        {
            try
            {
                assetOverviewOpenXmlWriter.WriteElement(new Row());
                assetOverviewRowCounterIndex++;
                assetOverviewOpenXmlWriter.WriteStartElement(new Row());
                WriteCellValue(assetOverviewOpenXmlWriter, findingType + " Asset Insight", 3);
                WriteCellValue(assetOverviewOpenXmlWriter, string.Empty, 3);
                WriteCellValue(assetOverviewOpenXmlWriter, string.Empty, 3);
                WriteCellValue(assetOverviewOpenXmlWriter, string.Empty, 3);
                WriteCellValue(assetOverviewOpenXmlWriter, string.Empty, 3);
                WriteCellValue(assetOverviewOpenXmlWriter, string.Empty, 3);
                WriteCellValue(assetOverviewOpenXmlWriter, string.Empty, 3);
                WriteCellValue(assetOverviewOpenXmlWriter, string.Empty, 3);
                WriteCellValue(assetOverviewOpenXmlWriter, string.Empty, 3);
                WriteCellValue(assetOverviewOpenXmlWriter, string.Empty, 3);
                WriteCellValue(assetOverviewOpenXmlWriter, string.Empty, 3);
                assetOverviewOpenXmlWriter.WriteEndElement();
                assetOverviewMergeCellReferences.Add("A" + assetOverviewRowCounterIndex.ToString() + ":K" + assetOverviewRowCounterIndex.ToString());
                assetOverviewRowCounterIndex++;
            }
            catch (Exception exception)
            {
                log.Error("Unable to generate first Finding Type header row.");
                throw exception;
            }
        }

        private void WriteFindingTypeHeaderRowTwo(string findingType)
        {
            try
            {
                assetOverviewOpenXmlWriter.WriteStartElement(new Row());
                if (!findingType.Equals("FPR"))
                { WriteCellValue(assetOverviewOpenXmlWriter, "Host Name", 17); }
                else
                { WriteCellValue(assetOverviewOpenXmlWriter, "Software Name", 17); }
                WriteCellValue(assetOverviewOpenXmlWriter, "IP Address", 17);
                WriteCellValue(assetOverviewOpenXmlWriter, "Group Name", 17);
                WriteCellValue(assetOverviewOpenXmlWriter, "Operating System", 17);
                WriteCellValue(assetOverviewOpenXmlWriter, "File Name", 17);
                WriteCellValue(assetOverviewOpenXmlWriter, "CAT I", 6);
                WriteCellValue(assetOverviewOpenXmlWriter, "CAT II", 7);
                WriteCellValue(assetOverviewOpenXmlWriter, "CAT III", 8);
                if (findingType.Equals("FPR"))
                { WriteCellValue(assetOverviewOpenXmlWriter, "Unknown", 9); }
                else
                { WriteCellValue(assetOverviewOpenXmlWriter, "CAT IV", 9); }
                WriteCellValue(assetOverviewOpenXmlWriter, "Total", 17);
                switch (findingType)
                {
                    case "ACAS":
                        {
                            WriteCellValue(assetOverviewOpenXmlWriter, "Credentialed", 17);
                            break;
                        }
                    case "XCCDF":
                        {
                            WriteCellValue(assetOverviewOpenXmlWriter, "SCAP Score", 17);
                            break;
                        }
                    default:
                        {
                            WriteCellValue(assetOverviewOpenXmlWriter, string.Empty, 17);
                            break;
                        }
                }
                assetOverviewOpenXmlWriter.WriteEndElement();
                assetOverviewRowCounterIndex++;
            }
            catch (Exception exception)
            {
                log.Error("Unable to generate second Finding Type header row.");
                throw exception;
            }
        }

        private int CountVulnerabilitiesByFindingType(string findingType)
        {
            try
            {
                int count = 0;
                using (SQLiteCommand sqliteCommand = FindingsDatabaseActions.sqliteConnection.CreateCommand())
                {
                    sqliteCommand.Parameters.Add(new SQLiteParameter("FindingType", findingType));
                    sqliteCommand.CommandText = "SELECT COUNT(VulnId) AS Count FROM UniqueFinding NATURAL JOIN FindingTypes NATURAL JOIN Vulnerability WHERE FindingType = @FindingType;";
                    using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
                    {
                        while (sqliteDataReader.Read())
                        { count = int.Parse(sqliteDataReader["Count"].ToString()); }
                    }
                }
                return count;
            }
            catch (Exception exception)
            {
                log.Error("Unable to count vulnerabilities of finding type " + findingType);
                throw exception;
            }
        }

        private void WriteAssetOverviewItems(string findingType)
        {
            try
            {
                List<AssetOverviewLineItem> assetList = new List<AssetOverviewLineItem>();
                using (SQLiteCommand sqliteCommand = FindingsDatabaseActions.sqliteConnection.CreateCommand())
                {
                    sqliteCommand.Parameters.Add(new SQLiteParameter("FindingType", findingType));
                    sqliteCommand.CommandText = "SELECT AssetIdToReport, HostName, IpAddress, GroupName, " + 
                        "SUM(CASE WHEN (RawRisk = 'I' OR (Impact = 'Critical' AND RawRisk IS NULL) OR (Impact = 'High' AND RawRisk IS NULL)) AND Status = 'Ongoing' THEN 1 ELSE 0 END) AS CatI, " + 
                        "SUM(CASE WHEN (RawRisk = 'II' OR (Impact = 'Medium' AND RawRisk IS NULL)) AND Status = 'Ongoing' THEN 1 ELSE 0 END) AS CatII, " + 
                        "SUM(CASE WHEN (RawRisk = 'III' OR (Impact = 'Low' AND RawRisk IS NULL)) AND Status = 'Ongoing' THEN 1 ELSE 0 END) AS CatIII, " +
                        "SUM(CASE WHEN (RawRisk = 'IV' OR (Impact = 'Informational' AND RawRisk IS NULL)) AND Status = 'Ongoing' THEN 1 ELSE 0 END) AS CatIV, " +
                        "COUNT(CASE WHEN Status = 'Ongoing' THEN 1 END) AS Total, " +
                        "OperatingSystem, IsCredentialed, Found21745, Found26917, FileName " +
                        "FROM Assets NATURAL JOIN UniqueFinding NATURAL JOIN Vulnerability NATURAL JOIN Groups NATURAL JOIN FileNames " +
                        "NATURAL JOIN FindingTypes NATURAL JOIN FindingStatuses WHERE FindingType = @FindingType " +
                        "GROUP BY AssetIdToReport, FileName;";
                    if (findingType.Equals("XCCDF"))
                    {
                        sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(893, " NATURAL JOIN ScapScores");
                        sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(729, ", ScapScore");
                    }
                    if (findingType.Equals("FPR"))
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(729, ", SUM(CASE WHEN RawRisk IS NULL AND Status = 'Ongoing' THEN 1 ELSE 0 END) AS Unknown"); }
                    using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
                    {
                        int i = 1;
                        while (sqliteDataReader.Read())
                        {
                            WriteAssetOverviewRow(sqliteDataReader, findingType);
                            i++;
                        }
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to write Asset Overview items.");
                throw exception;
            }
        }

        private void WriteAssetOverviewRow(SQLiteDataReader sqliteDataReader, string findingType)
        {
            try
            {
                assetOverviewOpenXmlWriter.WriteStartElement(new Row());
                WriteCellValue(assetOverviewOpenXmlWriter, sqliteDataReader["HostName"].ToString(), 18);
                WriteCellValue(assetOverviewOpenXmlWriter, sqliteDataReader["IpAddress"].ToString(), 18);
                WriteCellValue(assetOverviewOpenXmlWriter, sqliteDataReader["GroupName"].ToString(), 18);
                WriteCellValue(assetOverviewOpenXmlWriter, sqliteDataReader["OperatingSystem"].ToString(), 18);
                WriteCellValue(assetOverviewOpenXmlWriter, sqliteDataReader["FileName"].ToString(), 18);
                WriteCellValue(assetOverviewOpenXmlWriter, sqliteDataReader["CatI"].ToString(), 11);
                WriteCellValue(assetOverviewOpenXmlWriter, sqliteDataReader["CatII"].ToString(), 12);
                WriteCellValue(assetOverviewOpenXmlWriter, sqliteDataReader["CatIII"].ToString(), 13);
                if (findingType.Equals("FPR"))
                { WriteCellValue(assetOverviewOpenXmlWriter, sqliteDataReader["Unknown"].ToString(), 14); }
                else
                { WriteCellValue(assetOverviewOpenXmlWriter, sqliteDataReader["CatIV"].ToString(), 14); }
                WriteCellValue(assetOverviewOpenXmlWriter, sqliteDataReader["Total"].ToString(), 18);
                switch (findingType)
                {
                    case "ACAS":
                        {
                            switch (sqliteDataReader["IsCredentialed"].ToString())
                            {
                                case "true":
                                    {
                                        WriteCellValue(assetOverviewOpenXmlWriter, "Yes", 18);
                                        break;
                                    }
                                case "false":
                                    {
                                        string credentialedString = SetCredentialedString(sqliteDataReader["IpAddress"].ToString());
                                        WriteCellValue(assetOverviewOpenXmlWriter, credentialedString, 18);
                                        break;
                                    }
                                case "":
                                    {
                                        WriteCellValue(assetOverviewOpenXmlWriter, "Unknown", 18);
                                        break;
                                    }
                                case "No":
                                    {
                                        string credentialedString = SetCredentialedString(sqliteDataReader["IpAddress"].ToString());
                                        WriteCellValue(assetOverviewOpenXmlWriter, credentialedString, 18);
                                        break;
                                    }
                                case "Yes":
                                    {
                                        WriteCellValue(assetOverviewOpenXmlWriter, "Yes", 18);
                                        break;
                                    }
                                default:
                                    { break; }
                            }
                            break;
                        }
                    case "XCCDF":
                        {
                            WriteCellValue(assetOverviewOpenXmlWriter, sqliteDataReader["ScapScore"].ToString(), 18);
                            break;
                        }
                    default:
                        {
                            WriteCellValue(assetOverviewOpenXmlWriter, string.Empty, 18);
                            break;
                        }
                }
                assetOverviewOpenXmlWriter.WriteEndElement();
                assetOverviewRowCounterIndex++;
            }
            catch (Exception exception)
            {
                log.Error("Unable to generate Asset Overview header row.");
                throw exception;
            }
        }

        private void EndAssetOverview()
        {
            try
            {
                assetOverviewOpenXmlWriter.WriteEndElement();
                WriteAssetOverviewMergeCells();
                assetOverviewOpenXmlWriter.WriteEndElement();
                assetOverviewOpenXmlWriter.Dispose();
            }
            catch (Exception exception)
            {
                log.Error("Unable to finalize Asset Overview tab.");
                throw exception;
            }
        }

        private void WriteAssetOverviewMergeCells()
        {
            try
            {
                assetOverviewMergeCellReferences.Add("A1:K1");
                assetOverviewOpenXmlWriter.WriteStartElement(new MergeCells());
                foreach (string reference in assetOverviewMergeCellReferences)
                { assetOverviewOpenXmlWriter.WriteElement(new MergeCell() { Reference = reference }); }
                assetOverviewOpenXmlWriter.WriteEndElement();
            }
            catch (Exception exception)
            {
                log.Error("Unable to generate Asset Overview MergeCells element.");
                throw exception;
            }
        }

        #endregion Create Asset Overview

        #region Create POA&M

        private void StartPoam(WorkbookPart workbookPart, Sheets sheets)
        {
            try
            {
                WorksheetPart worksheetPart = workbookPart.AddNewPart<WorksheetPart>();
                Sheet sheet = new Sheet() { Id = workbookPart.GetIdOfPart(worksheetPart), SheetId = sheetIndex, Name = "POA&M" };
                sheetIndex++;
                sheets.Append(sheet);
                poamOpenXmlWriter = OpenXmlWriter.Create(worksheetPart);
                poamOpenXmlWriter.WriteStartElement(new Worksheet());
                WritePoamColumns();
                poamOpenXmlWriter.WriteStartElement(new SheetData());
                poamOpenXmlWriter.WriteElement(new Row() { Hidden = true });
                WritePoamHeaderRowOne();
                WritePoamHeaderRowTwo();
                WritePoamHeaderRowThree();
                WritePoamHeaderRowFour();
                WritePoamHeaderRowFive();
                WritePoamHeaderRowSix();
            }
            catch (Exception exception)
            {
                log.Error("Unable to initialize POA&M tab.");
                throw exception;
            }
        }

        private void WritePoamColumns()
        {
            try
            {
                poamOpenXmlWriter.WriteStartElement(new Columns());
                poamOpenXmlWriter.WriteElement(new Column() { CustomWidth = true, Width = 4.43, Max = 1, Min = 1 });
                poamOpenXmlWriter.WriteElement(new Column() { CustomWidth = true, Width = 32.29, Max = 2, Min = 2 });
                poamOpenXmlWriter.WriteElement(new Column() { CustomWidth = true, Width = 24.43, Max = 3, Min = 3 });
                poamOpenXmlWriter.WriteElement(new Column() { CustomWidth = true, Width = 24.43, Max = 4, Min = 4 });
                poamOpenXmlWriter.WriteElement(new Column() { CustomWidth = true, Width = 10.57, Max = 5, Min = 5 });
                poamOpenXmlWriter.WriteElement(new Column() { CustomWidth = true, Width = 10.57, Max = 6, Min = 6 });
                poamOpenXmlWriter.WriteElement(new Column() { CustomWidth = true, Width = 24.43, Max = 7, Min = 7 });
                poamOpenXmlWriter.WriteElement(new Column() { CustomWidth = true, Width = 10.57, Max = 8, Min = 8 });
                poamOpenXmlWriter.WriteElement(new Column() { CustomWidth = true, Width = 24.43, Max = 9, Min = 9 });
                poamOpenXmlWriter.WriteElement(new Column() { CustomWidth = true, Width = 24.43, Max = 10, Min = 10 });
                poamOpenXmlWriter.WriteElement(new Column() { CustomWidth = true, Width = 24.43, Max = 11, Min = 11 });
                poamOpenXmlWriter.WriteElement(new Column() { CustomWidth = true, Width = 24.43, Max = 12, Min = 12 });
                poamOpenXmlWriter.WriteElement(new Column() { CustomWidth = true, Width = 24.43, Max = 13, Min = 13 });
                poamOpenXmlWriter.WriteElement(new Column() { CustomWidth = true, Width = 10.57, Max = 14, Min = 14 });
                poamOpenXmlWriter.WriteElement(new Column() { CustomWidth = true, Width = 32.29, Max = 15, Min = 15 });
                poamOpenXmlWriter.WriteEndElement();
            }
            catch (Exception exception)
            {
                log.Error("Unable to generate POA&M columns.");
                throw exception;
            }
        }

        private void WritePoamHeaderRowOne()
        {
            try
            {
                poamOpenXmlWriter.WriteStartElement(new Row());
                WriteCellValue(poamOpenXmlWriter, "Date Exported:", 19);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 19);
                WriteCellValue(poamOpenXmlWriter, DateTime.Now.ToLongDateString(), 20);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 20);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 20);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 20);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 20);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 20);
                WriteCellValue(poamOpenXmlWriter, "System Type:", 19);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 20);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 20);
                WriteCellValue(poamOpenXmlWriter, "OMB Project ID:", 19);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 20);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 20);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 20);
                poamOpenXmlWriter.WriteEndElement();
            }
            catch (Exception exception)
            {
                log.Error("Unable to generate first POA&M header row.");
                throw exception;
            }
        }

        private void WritePoamHeaderRowTwo()
        {
            try
            {
                poamOpenXmlWriter.WriteStartElement(new Row());
                WriteCellValue(poamOpenXmlWriter, "Exported By:", 19);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 19);
                WriteCellValue(poamOpenXmlWriter, ContactName, 20);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 20);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 20);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 20);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 20);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 20);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 19);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 20);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 20);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 19);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 20);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 20);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 20);
                poamOpenXmlWriter.WriteEndElement();
            }
            catch (Exception exception)
            {
                log.Error("Unable to generate second POA&M header row.");
                throw exception;
            }
        }

        private void WritePoamHeaderRowThree()
        {
            try
            {
                poamOpenXmlWriter.WriteStartElement(new Row());
                WriteCellValue(poamOpenXmlWriter, "DoD Component:", 19);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 19);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 20);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 20);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 20);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 20);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 20);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 20);
                WriteCellValue(poamOpenXmlWriter, "POC Name:", 19);
                WriteCellValue(poamOpenXmlWriter, ContactName, 20);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 20);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 19);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 19);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 19);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 19);
                poamOpenXmlWriter.WriteEndElement();
            }
            catch (Exception exception)
            {
                log.Error("Unable to generate third POA&M header row.");
                throw exception;
            }
        }

        private void WritePoamHeaderRowFour()
        {
            try
            {
                poamOpenXmlWriter.WriteStartElement(new Row());
                WriteCellValue(poamOpenXmlWriter, @"System / Project Name:", 19);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 19);
                WriteCellValue(poamOpenXmlWriter, ContactName, 20);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 20);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 20);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 20);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 20);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 20);
                WriteCellValue(poamOpenXmlWriter, "POC Phone:", 19);
                WriteCellValue(poamOpenXmlWriter, ContactNumber, 20);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 20);
                WriteCellValue(poamOpenXmlWriter, "Security Costs:", 19);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 20);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 20);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 20);
                poamOpenXmlWriter.WriteEndElement();
            }
            catch (Exception exception)
            {
                log.Error("Unable to generate fourth POA&M header row.");
                throw exception;
            }
        }

        private void WritePoamHeaderRowFive()
        {
            try
            {
                poamOpenXmlWriter.WriteStartElement(new Row());
                WriteCellValue(poamOpenXmlWriter, "DoD IT Registration No:", 19);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 19);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 20);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 20);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 20);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 20);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 20);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 20);
                WriteCellValue(poamOpenXmlWriter, "POC Email:", 19);
                WriteCellValue(poamOpenXmlWriter, ContactEmail, 20);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 20);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 19);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 19);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 19);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 19);
                poamOpenXmlWriter.WriteEndElement();
            }
            catch (Exception exception)
            {
                log.Error("Unable to generate fifth POA&M header row.");
                throw exception;
            }
        }

        private void WritePoamHeaderRowSix()
        {
            try
            {
                poamOpenXmlWriter.WriteStartElement(new Row());
                WriteCellValue(poamOpenXmlWriter, "Control Vulnerability Description", 16);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 16);
                WriteCellValue(poamOpenXmlWriter, @"Security Control Number (NC/NA controls only)", 16);
                WriteCellValue(poamOpenXmlWriter, @"Office/Org", 16);
                WriteCellValue(poamOpenXmlWriter, "Security Checks", 16);
                WriteCellValue(poamOpenXmlWriter, "Raw Severity Value", 16);
                WriteCellValue(poamOpenXmlWriter, "Mitigations", 16);
                WriteCellValue(poamOpenXmlWriter, "Severity Value", 16);
                WriteCellValue(poamOpenXmlWriter, "Resources Required", 16);
                WriteCellValue(poamOpenXmlWriter, "Scheduled Completion Date", 16);
                WriteCellValue(poamOpenXmlWriter, "Milestone with Completion Dates", 16);
                WriteCellValue(poamOpenXmlWriter, "Milestone Changes", 16);
                WriteCellValue(poamOpenXmlWriter, "Source Identifying Control Vulnerability", 16);
                WriteCellValue(poamOpenXmlWriter, "Status", 16);
                WriteCellValue(poamOpenXmlWriter, "Comments", 16);
                poamOpenXmlWriter.WriteEndElement();
            }
            catch (Exception exception)
            {
                log.Error("Unable to generate sixth POA&M header row.");
                throw exception;
            }
        }

        private void WriteFindingToPoam(SQLiteDataReader sqliteDataReader, AsyncObservableCollection<MitigationItem> mitigationList)
        {
            try
            {
                MitigationItem mitigation = mitigationList.FirstOrDefault(
                    x => x.MitigationGroupName.Equals(sqliteDataReader["GroupName"].ToString()) &&
                        x.MitigationVulnerabilityId.Equals(sqliteDataReader["VulnId"].ToString()));

                if (mitigation != null)
                {
                    if (!FilterByStatus(mitigation.MitigationStatus))
                    { return; }
                }
                else if (!FilterByStatus(sqliteDataReader["Status"].ToString()))
                { return; }

                poamOpenXmlWriter.WriteStartElement(new Row());
                WriteCellValue(poamOpenXmlWriter, poamRowCounterIndex.ToString(), 16);

                string descriptionCellValue = "Title: " + Environment.NewLine + sqliteDataReader["VulnTitle"].ToString() + doubleCarriageReturn +
                    "Description: " + Environment.NewLine + sqliteDataReader["Description"].ToString() + doubleCarriageReturn +
                    "Devices Affected:" + Environment.NewLine + sqliteDataReader["AssetIdToReport"].ToString().Replace(",", Environment.NewLine);

                WriteCellValue(
                    poamOpenXmlWriter,
                    LargeCellValueHandler(
                        descriptionCellValue,
                        sqliteDataReader["VulnId"].ToString(),
                        sqliteDataReader["AssetIdToReport"].ToString().Replace(",", Environment.NewLine),
                        "Description"
                    ), 
                    20);
                if (IsDiacapPackage)
                { WriteCellValue(poamOpenXmlWriter, sqliteDataReader["IaControl"].ToString(), 24); }
                else
                {
                    if (!string.IsNullOrWhiteSpace(sqliteDataReader["NistControl"].ToString()))
                    { WriteCellValue(poamOpenXmlWriter, sqliteDataReader["NistControl"].ToString(), 24); }
                    else if (!string.IsNullOrWhiteSpace(sqliteDataReader["IaControl"].ToString()))
                    { WriteCellValue(poamOpenXmlWriter, ConvertDiacapToRmf(sqliteDataReader["IaControl"].ToString()), 24); }
                    else
                    { WriteCellValue(poamOpenXmlWriter, string.Empty, 24); }
                }
                WriteCellValue(poamOpenXmlWriter, ContactOrganization + ", " + ContactName + ", " + ContactNumber + ", " + ContactEmail, 20);
                WriteCellValue(poamOpenXmlWriter, sqliteDataReader["VulnId"].ToString(), 24);
                if (!string.IsNullOrWhiteSpace(sqliteDataReader["RawRisk"].ToString()))
                { WriteCellValue(poamOpenXmlWriter, sqliteDataReader["RawRisk"].ToString(), 24); }
                else
                { WriteCellValue(poamOpenXmlWriter, ConvertAcasSeverityToDisaCategory(sqliteDataReader["Impact"].ToString()), 24); }
                if (mitigation != null)
                { WriteCellValue(poamOpenXmlWriter, mitigation.MitigationText, 20); }
                else
                {
                    string mitigationText = string.Empty;
                    if (UserRequiresComments)
                    { mitigationText = sqliteDataReader["Comments"].ToString(); }
                    if (UserRequiresFindingDetails)
                    {
                        if (string.IsNullOrWhiteSpace(mitigationText))
                        { mitigationText = sqliteDataReader["FindingDetails"].ToString(); }
                        else
                        { mitigationText += doubleCarriageReturn + sqliteDataReader["FindingDetails"].ToString(); }
                    }
                    WriteCellValue(
                        poamOpenXmlWriter,
                        LargeCellValueHandler(
                            mitigationText,
                            sqliteDataReader["VulnId"].ToString(),
                            sqliteDataReader["AssetIdToReport"].ToString().Replace(",", Environment.NewLine),
                            "Mitigation"
                        ), 
                        20);
                }
                WriteCellValue(poamOpenXmlWriter, string.Empty, 24);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 20);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 20);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 20);
                WriteCellValue(poamOpenXmlWriter, string.Empty, 20);
                if (sqliteDataReader["FindingType"].ToString().Equals("WASSP"))
                { WriteCellValue(poamOpenXmlWriter, sqliteDataReader["Source"].ToString(), 24); }
                else if (!sqliteDataReader["FindingType"].ToString().Equals("ACAS"))
                {
                    WriteCellValue(poamOpenXmlWriter, sqliteDataReader["Source"].ToString() + " :: " +
                        sqliteDataReader["Version"].ToString() + sqliteDataReader["Release"].ToString(), 24);
                }
                else
                {
                    WriteCellValue(poamOpenXmlWriter, sqliteDataReader["Source"].ToString() + " :: " +
                        sqliteDataReader["Version"].ToString() + "." + sqliteDataReader["Release"].ToString(), 24);
                }
                if (mitigation != null)
                { WriteCellValue(poamOpenXmlWriter, mitigation.MitigationStatus, 24); }
                else
                { WriteCellValue(poamOpenXmlWriter, sqliteDataReader["Status"].ToString(), 24); }
                WriteCellValue(poamOpenXmlWriter, sqliteDataReader["AssetIdToReport"].ToString().Replace(",", Environment.NewLine), 20);
                poamOpenXmlWriter.WriteEndElement();
                poamRowCounterIndex++;
            }
            catch (Exception exception)
            {
                log.Error("Unable to write finding to POA&M.");
                throw exception;
            }
        }

        private void EndPoam()
        {
            try
            {
                poamOpenXmlWriter.WriteEndElement();
                WritePoamMergeCells();
                poamOpenXmlWriter.WriteEndElement();
                poamOpenXmlWriter.Dispose();
            }
            catch (Exception exception)
            {
                log.Error("Unable to finalize POA&M tab.");
                throw exception;
            }
        }

        private void WritePoamMergeCells()
        {
            try
            {
                string[] mergeCellArray = new string[] {
                "A1:O1", "A2:B2", "A3:B3", "A4:B4", "A5:B5", "A6:B6", "A7:B7", "C2:H2", "C3:H3",
                "C4:H4", "C5:H5", "C6:H6", "I2:I3", "J2:K3", "J4:K4", "J5:K5", "J6:K6", "L2:L3",
                "M2:O3", "M5:O5", "L4:O4", "L6:O6" };
                poamOpenXmlWriter.WriteStartElement(new MergeCells());
                foreach (string mergeCell in mergeCellArray)
                { poamOpenXmlWriter.WriteElement(new MergeCell() { Reference = mergeCell }); }
                poamOpenXmlWriter.WriteEndElement();
            }
            catch (Exception exception)
            {
                log.Error("Unable to generate POA&M MergeCells element.");
                throw exception;
            }
        }

        #endregion Create POA&M

        #region Create RAR

        private void StartRar(WorkbookPart workbookPart, Sheets sheets)
        {
            try
            {
                WorksheetPart worksheetPart = workbookPart.AddNewPart<WorksheetPart>();
                Sheet sheet = new Sheet() { Id = workbookPart.GetIdOfPart(worksheetPart), SheetId = sheetIndex, Name = "RAR" };
                sheetIndex++;
                sheets.Append(sheet);
                rarOpenXmlWriter = OpenXmlWriter.Create(worksheetPart);
                rarOpenXmlWriter.WriteStartElement(new Worksheet());
                WriteRarColumns();
                rarOpenXmlWriter.WriteStartElement(new SheetData());
                WriteRarHeaderRows();
            }
            catch (Exception exception)
            {
                log.Error("Unable to initialize RAR tab.");
                throw exception;
            }
        }

        private void WriteRarColumns()
        {
            try
            {
                rarOpenXmlWriter.WriteStartElement(new Columns());
                rarOpenXmlWriter.WriteElement(new Column() { Min = 1U, Max = 1U, Width = 5d, CustomWidth = true });
                rarOpenXmlWriter.WriteElement(new Column() { Min = 2U, Max = 2U, Width = 15d, CustomWidth = true });
                rarOpenXmlWriter.WriteElement(new Column() { Min = 3U, Max = 3U, Width = 15d, CustomWidth = true });
                rarOpenXmlWriter.WriteElement(new Column() { Min = 4U, Max = 4U, Width = 44d, CustomWidth = true });
                rarOpenXmlWriter.WriteElement(new Column() { Min = 5U, Max = 5U, Width = 17.71d, CustomWidth = true });
                rarOpenXmlWriter.WriteElement(new Column() { Min = 6U, Max = 6U, Width = 38.71d, CustomWidth = true });
                rarOpenXmlWriter.WriteElement(new Column() { Min = 7U, Max = 7U, Width = 28.00d, CustomWidth = true });
                rarOpenXmlWriter.WriteElement(new Column() { Min = 8U, Max = 8U, Width = 24.43d, CustomWidth = true });
                rarOpenXmlWriter.WriteElement(new Column() { Min = 9U, Max = 9U, Width = 15.00d, CustomWidth = true });
                rarOpenXmlWriter.WriteElement(new Column() { Min = 10U, Max = 10U, Width = 38.71d, CustomWidth = true });
                rarOpenXmlWriter.WriteElement(new Column() { Min = 11U, Max = 11U, Width = 38.71d, CustomWidth = true });
                rarOpenXmlWriter.WriteElement(new Column() { Min = 12U, Max = 12U, Width = 16.57d, CustomWidth = true });
                rarOpenXmlWriter.WriteElement(new Column() { Min = 13U, Max = 13U, Width = 16.57d, CustomWidth = true });
                rarOpenXmlWriter.WriteElement(new Column() { Min = 14U, Max = 14U, Width = 31.86d, CustomWidth = true });
                rarOpenXmlWriter.WriteElement(new Column() { Min = 15U, Max = 15U, Width = 38.71d, CustomWidth = true });
                rarOpenXmlWriter.WriteElement(new Column() { Min = 16U, Max = 16U, Width = 16.57d, CustomWidth = true });
                rarOpenXmlWriter.WriteElement(new Column() { Min = 17U, Max = 17U, Width = 16.57d, CustomWidth = true });
                rarOpenXmlWriter.WriteElement(new Column() { Min = 18U, Max = 18U, Width = 38.71d, CustomWidth = true });
                rarOpenXmlWriter.WriteElement(new Column() { Min = 19U, Max = 19U, Width = 16.57d, CustomWidth = true });
                rarOpenXmlWriter.WriteElement(new Column() { Min = 20U, Max = 20U, Width = 38.71d, CustomWidth = true });
                rarOpenXmlWriter.WriteElement(new Column() { Min = 21U, Max = 21U, Width = 38.71d, CustomWidth = true });
                rarOpenXmlWriter.WriteEndElement();
            }
            catch (Exception exception)
            {
                log.Error("Unable to generate RAR columns.");
                throw exception;
            }
        }

        private void WriteRarHeaderRows()
        {
            try
            {
                rarOpenXmlWriter.WriteStartElement(new Row());
                rarOpenXmlWriter.WriteEndElement();
                rarOpenXmlWriter.WriteStartElement(new Row());
                WriteCellValue(rarOpenXmlWriter, string.Empty, 0);
                WriteCellValue(rarOpenXmlWriter, "(16) Specific Vulnerabilities", 25);
                rarOpenXmlWriter.WriteEndElement();
                rarOpenXmlWriter.WriteStartElement(new Row() { Height = 75.00d, CustomHeight = true });
                WriteCellValue(rarOpenXmlWriter, string.Empty, 0);
                WriteCellValue(rarOpenXmlWriter, "Non-Compliant Security Controls" + Environment.NewLine + "(16a)", 26);
                WriteCellValue(rarOpenXmlWriter, "Affected CCI" + Environment.NewLine + "(16a.1)", 26);
                WriteCellValue(rarOpenXmlWriter, "Source of Discovery" + Environment.NewLine + "(16a.2)", 26);
                WriteCellValue(rarOpenXmlWriter, "Vulnerability ID" + Environment.NewLine + "(16a.3)", 26);
                WriteCellValue(rarOpenXmlWriter, "Vulnerability Description" + Environment.NewLine + "(16b)", 26);
                WriteCellValue(rarOpenXmlWriter, "Devices Affected" + Environment.NewLine + "(16b.1)", 26);
                WriteCellValue(rarOpenXmlWriter, "Security Objectives" + Environment.NewLine + "(C-I-A)" + Environment.NewLine + "(16c)", 26);
                WriteCellValue(rarOpenXmlWriter, "Raw Test Result" + Environment.NewLine + "(16d)", 26);
                WriteCellValue(rarOpenXmlWriter, "Predisposing Condition(s)" + Environment.NewLine + "(16d.1)", 26);
                WriteCellValue(rarOpenXmlWriter, "Technical Mitigation(s)" + Environment.NewLine + "(16d.2)", 26);
                WriteCellValue(rarOpenXmlWriter, "Severity or Pervasiveness" + Environment.NewLine + "(VL-VH)" + Environment.NewLine + "(16d.3)", 26);
                WriteCellValue(rarOpenXmlWriter, "Relevance of Threat" + Environment.NewLine + "(VL-VH)" + Environment.NewLine + "(16e)", 26);
                WriteCellValue(rarOpenXmlWriter, "Threat Description" + Environment.NewLine + "(16e.1)", 26);
                WriteCellValue(rarOpenXmlWriter, "Likelihood" + Environment.NewLine + "(Cells 16d.3 & 16e)" + Environment.NewLine + "(VL-VH)" + Environment.NewLine + "(16f)", 26);
                WriteCellValue(rarOpenXmlWriter, "Impact" + Environment.NewLine + "(VL-VH)" + Environment.NewLine + "(16g)", 26);
                WriteCellValue(rarOpenXmlWriter, "Impact Description"+ Environment.NewLine + "(16h)", 26);
                WriteCellValue(rarOpenXmlWriter, "Risk" + Environment.NewLine + "(Cells 16f & 16g)" + Environment.NewLine + "(VL-VH)" + Environment.NewLine + "(16i)", 26);
                WriteCellValue(rarOpenXmlWriter, "Proposed Mitigations" + Environment.NewLine + "(From POA&M)" + Environment.NewLine + "(16j)", 26);
                WriteCellValue(rarOpenXmlWriter, "Residual Risk" + Environment.NewLine + "(After Proposed Mitigations)" + Environment.NewLine + "(16k)", 26);
                WriteCellValue(rarOpenXmlWriter, "Recommendations" + Environment.NewLine + "(16l)", 26);
                rarOpenXmlWriter.WriteEndElement();
            }
            catch (Exception exception)
            {
                log.Error("Unable to generate RAR header rows.");
                throw exception;
            }
        }

        private void WriteFindingToRar(SQLiteDataReader sqliteDataReader, AsyncObservableCollection<MitigationItem> mitigationList)
        {
            try
            {
                MitigationItem mitigation = mitigationList.FirstOrDefault(
                    x => x.MitigationGroupName.Equals(sqliteDataReader["GroupName"].ToString()) &&
                        x.MitigationVulnerabilityId.Equals(sqliteDataReader["VulnId"].ToString()));

                if (mitigation != null)
                {
                    if (!mitigation.MitigationStatus.Equals("Ongoing"))
                    { return; }
                }
                else if (!sqliteDataReader["Status"].ToString().Equals("Ongoing"))
                { return; }

                rarOpenXmlWriter.WriteStartElement(new Row());
                WriteCellValue(rarOpenXmlWriter, string.Empty, 0);
                if (IsDiacapPackage)
                { WriteCellValue(rarOpenXmlWriter, sqliteDataReader["IaControl"].ToString(), 24); }
                else
                {
                    if (!string.IsNullOrWhiteSpace(sqliteDataReader["NistControl"].ToString()))
                    { WriteCellValue(rarOpenXmlWriter, sqliteDataReader["NistControl"].ToString(), 24); }
                    else if (!string.IsNullOrWhiteSpace(sqliteDataReader["IaControl"].ToString()))
                    { WriteCellValue(rarOpenXmlWriter, ConvertDiacapToRmf(sqliteDataReader["IaControl"].ToString()), 24); }
                    else
                    { WriteCellValue(rarOpenXmlWriter, string.Empty, 24); }
                }
                WriteCellValue(rarOpenXmlWriter, sqliteDataReader["CciNumber"].ToString(), 24);
                if (sqliteDataReader["FindingType"].ToString().Equals("WASSP"))
                { WriteCellValue(rarOpenXmlWriter, sqliteDataReader["Source"].ToString(), 24); }
                else if (!sqliteDataReader["FindingType"].ToString().Equals("ACAS"))
                {
                    WriteCellValue(rarOpenXmlWriter, sqliteDataReader["Source"].ToString() + " :: " +
                        sqliteDataReader["Version"].ToString() + sqliteDataReader["Release"].ToString(), 24);
                }
                else
                {
                    WriteCellValue(rarOpenXmlWriter, sqliteDataReader["Source"].ToString() + " :: " +
                        sqliteDataReader["Version"].ToString() + "." + sqliteDataReader["Release"].ToString(), 24);
                }
                WriteCellValue(rarOpenXmlWriter, sqliteDataReader["VulnId"].ToString(), 24);
                WriteCellValue(rarOpenXmlWriter, sqliteDataReader["VulnTitle"].ToString(), 20);
                WriteCellValue(rarOpenXmlWriter, sqliteDataReader["AssetIdToReport"].ToString().Replace(",", Environment.NewLine), 20);
                WriteCellValue(rarOpenXmlWriter, string.Empty, 24);
                if (!string.IsNullOrWhiteSpace(sqliteDataReader["RawRisk"].ToString()))
                { WriteCellValue(rarOpenXmlWriter, sqliteDataReader["RawRisk"].ToString(), 24); }
                else
                { WriteCellValue(rarOpenXmlWriter, ConvertAcasSeverityToDisaCategory(sqliteDataReader["Impact"].ToString()), 24); }
                WriteCellValue(rarOpenXmlWriter, string.Empty, 20);
                if (mitigation != null)
                { WriteCellValue(rarOpenXmlWriter, mitigation.MitigationText, 20); }
                else
                {
                    string mitigationText = string.Empty;
                    if (UserRequiresComments)
                    { mitigationText = sqliteDataReader["Comments"].ToString(); }
                    if (UserRequiresFindingDetails)
                    {
                        if (!string.IsNullOrWhiteSpace(mitigationText))
                        { mitigationText = mitigationText + doubleCarriageReturn + sqliteDataReader["FindingDetails"].ToString(); }
                        else
                        { mitigationText = sqliteDataReader["FindingDetails"].ToString(); }
                    }
                    WriteCellValue(
                        rarOpenXmlWriter, LargeCellValueHandler(
                            mitigationText,
                            sqliteDataReader["VulnId"].ToString(),
                            sqliteDataReader["AssetIdToReport"].ToString().Replace(",", Environment.NewLine),
                            "Mitigation"
                        ), 
                        20);
                }
                WriteCellValue(rarOpenXmlWriter, string.Empty, 24);
                WriteCellValue(rarOpenXmlWriter, string.Empty, 24);
                WriteCellValue(
                    rarOpenXmlWriter, 
                    LargeCellValueHandler(
                        sqliteDataReader["Description"].ToString(),
                        sqliteDataReader["VulnId"].ToString(),
                        sqliteDataReader["AssetIdToReport"].ToString().Replace(",", Environment.NewLine),
                        "Description"
                    ), 
                    20);
                WriteCellValue(rarOpenXmlWriter, string.Empty, 24);
                WriteCellValue(rarOpenXmlWriter, ConvertAcasSeverityToRmfImpact(sqliteDataReader["Impact"].ToString()), 24);
                WriteCellValue(
                    rarOpenXmlWriter,
                    LargeCellValueHandler(
                        sqliteDataReader["Description"].ToString(),
                        sqliteDataReader["VulnId"].ToString(),
                        sqliteDataReader["AssetIdToReport"].ToString().Replace(",", Environment.NewLine),
                        "Description"
                    ), 
                    20);
                WriteCellValue(rarOpenXmlWriter, string.Empty, 24);
                WriteCellValue(rarOpenXmlWriter, string.Empty, 20);
                WriteCellValue(rarOpenXmlWriter, string.Empty, 24);
                WriteCellValue(rarOpenXmlWriter, string.Empty, 20);
                rarOpenXmlWriter.WriteEndElement();
            }
            catch (Exception exception)
            {
                log.Error("Unable to write finding to RAR.");
                throw exception;
            }
        }

        private void EndRar()
        {
            try
            {
                rarOpenXmlWriter.WriteEndElement();
                rarOpenXmlWriter.WriteEndElement();
                rarOpenXmlWriter.Dispose();
            }
            catch (Exception exception)
            {
                log.Error("Unable to finalize RAR tab.");
                throw exception;
            }
        }

        #endregion Create RAR

        #region Create ACAS Output

        private void StartAcasOutput(WorkbookPart workbookPart, Sheets sheets)
        {
            try
            {
                WorksheetPart worksheetPart = workbookPart.AddNewPart<WorksheetPart>();
                Sheet sheet = new Sheet() { Id = workbookPart.GetIdOfPart(worksheetPart), SheetId = sheetIndex, Name = "ACAS Output & Review" };
                sheetIndex++;
                sheets.Append(sheet);
                acasOutputOpenXmlWriter = OpenXmlWriter.Create(worksheetPart);
                acasOutputOpenXmlWriter.WriteStartElement(new Worksheet());
                WriteAcasOutputColumns();
                acasOutputOpenXmlWriter.WriteStartElement(new SheetData());
                WriteAcasOutputHeaderRow();
            }
            catch (Exception exception)
            {
                log.Error("Unable to initialize ACAS Output tab.");
                throw exception;
            }
        }

        private void WriteAcasOutputColumns()
        {
            try
            {
                acasOutputOpenXmlWriter.WriteStartElement(new Columns());
                acasOutputOpenXmlWriter.WriteElement(new Column() { Min = 1U, Max = 1U, Width = 10.00d, CustomWidth = true });
                acasOutputOpenXmlWriter.WriteElement(new Column() { Min = 2U, Max = 2U, Width = 20.00d, CustomWidth = true });
                acasOutputOpenXmlWriter.WriteElement(new Column() { Min = 3U, Max = 3U, Width = 15.00d, CustomWidth = true });
                acasOutputOpenXmlWriter.WriteElement(new Column() { Min = 4U, Max = 4U, Width = 15.00d, CustomWidth = true });
                acasOutputOpenXmlWriter.WriteElement(new Column() { Min = 5U, Max = 5U, Width = 20.00d, CustomWidth = true });
                acasOutputOpenXmlWriter.WriteElement(new Column() { Min = 6U, Max = 6U, Width = 20.00d, CustomWidth = true });
                acasOutputOpenXmlWriter.WriteElement(new Column() { Min = 7U, Max = 7U, Width = 35.00d, CustomWidth = true });
                acasOutputOpenXmlWriter.WriteElement(new Column() { Min = 8U, Max = 8U, Width = 35.00d, CustomWidth = true });
                acasOutputOpenXmlWriter.WriteElement(new Column() { Min = 9U, Max = 9U, Width = 35.00d, CustomWidth = true });
                acasOutputOpenXmlWriter.WriteElement(new Column() { Min = 10U, Max = 10U, Width = 35.00d, CustomWidth = true });
                acasOutputOpenXmlWriter.WriteElement(new Column() { Min = 11U, Max = 11U, Width = 20.00d, CustomWidth = true });
                acasOutputOpenXmlWriter.WriteElement(new Column() { Min = 12U, Max = 12U, Width = 35.00d, CustomWidth = true });
                acasOutputOpenXmlWriter.WriteElement(new Column() { Min = 13U, Max = 13U, Width = 25.00d, CustomWidth = true });
                acasOutputOpenXmlWriter.WriteElement(new Column() { Min = 14U, Max = 14U, Width = 25.00d, CustomWidth = true });
                acasOutputOpenXmlWriter.WriteElement(new Column() { Min = 15U, Max = 15U, Width = 25.00d, CustomWidth = true });
                acasOutputOpenXmlWriter.WriteElement(new Column() { Min = 16U, Max = 16U, Width = 25.00d, CustomWidth = true });
                acasOutputOpenXmlWriter.WriteElement(new Column() { Min = 17U, Max = 17U, Width = 25.00d, CustomWidth = true });
                acasOutputOpenXmlWriter.WriteElement(new Column() { Min = 18U, Max = 18U, Width = 25.00d, CustomWidth = true });
                acasOutputOpenXmlWriter.WriteElement(new Column() { Min = 19U, Max = 19U, Width = 15.00d, CustomWidth = true });
                acasOutputOpenXmlWriter.WriteElement(new Column() { Min = 20U, Max = 20U, Width = 35.00d, CustomWidth = true });
                acasOutputOpenXmlWriter.WriteEndElement();
            }
            catch (Exception exception)
            {
                log.Error("Unable to generate ACAS Output columns.");
                throw exception;
            }
        }

        private void WriteAcasOutputHeaderRow()
        {
            try
            {
                acasOutputOpenXmlWriter.WriteStartElement(new Row());
                WriteCellValue(acasOutputOpenXmlWriter, "Plugin ID", 4);
                WriteCellValue(acasOutputOpenXmlWriter, "Plugin Title", 4);
                WriteCellValue(acasOutputOpenXmlWriter, "Risk Factor", 4);
                WriteCellValue(acasOutputOpenXmlWriter, "STIG Severity", 4);
                WriteCellValue(acasOutputOpenXmlWriter, "Asset Name", 4);
                WriteCellValue(acasOutputOpenXmlWriter, "IP Address", 4);
                WriteCellValue(acasOutputOpenXmlWriter, "Synopsis", 4);
                WriteCellValue(acasOutputOpenXmlWriter, "Description", 4);
                WriteCellValue(acasOutputOpenXmlWriter, "Scan Output", 4);
                WriteCellValue(acasOutputOpenXmlWriter, "Solution", 4);
                WriteCellValue(acasOutputOpenXmlWriter, "Cross Reference", 4);
                WriteCellValue(acasOutputOpenXmlWriter, "CPE", 4);
                WriteCellValue(acasOutputOpenXmlWriter, "Plugin Publication Date", 4);
                WriteCellValue(acasOutputOpenXmlWriter, "Plugin Modification Date", 4);
                WriteCellValue(acasOutputOpenXmlWriter, "Last Observed Date", 4);
                WriteCellValue(acasOutputOpenXmlWriter, "Patch Publication Date", 4);
                WriteCellValue(acasOutputOpenXmlWriter, "Scan Filename", 4);
                WriteCellValue(acasOutputOpenXmlWriter, "Group Name", 4);
                WriteCellValue(acasOutputOpenXmlWriter, "Review Status", 4);
                WriteCellValue(acasOutputOpenXmlWriter, "Notes", 4);
                acasOutputOpenXmlWriter.WriteEndElement();
            }
            catch (Exception exception)
            {
                log.Error("Unable to generate ACAS Output header row.");
                throw exception;
            }
        }

        private void WriteIndividualAcasOutput()
        {
            try
            {
                using (SQLiteCommand sqliteCommand = FindingsDatabaseActions.sqliteConnection.CreateCommand())
                {
                    sqliteCommand.Parameters.Add(new SQLiteParameter("FindingType", "ACAS"));
                    sqliteCommand.CommandText = SetSqliteCommandText(false, "ACAS");
                    using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
                    {
                        while (sqliteDataReader.Read())
                        {
                            acasOutputOpenXmlWriter.WriteStartElement(new Row());
                            WriteCellValue(acasOutputOpenXmlWriter, sqliteDataReader["VulnId"].ToString(), 24);
                            WriteCellValue(acasOutputOpenXmlWriter, sqliteDataReader["VulnTitle"].ToString(), 20);
                            WriteCellValue(acasOutputOpenXmlWriter, sqliteDataReader["Impact"].ToString(), 24);
                            WriteCellValue(acasOutputOpenXmlWriter, sqliteDataReader["RawRisk"].ToString(), 24);
                            WriteCellValue(acasOutputOpenXmlWriter, sqliteDataReader["HostName"].ToString(), 24);
                            WriteCellValue(acasOutputOpenXmlWriter, sqliteDataReader["IpAddress"].ToString(), 24);
                            WriteCellValue(
                                acasOutputOpenXmlWriter, 
                                LargeCellValueHandler(
                                    sqliteDataReader["RiskStatement"].ToString(),
                                    sqliteDataReader["VulnId"].ToString(),
                                    sqliteDataReader["AssetIdToReport"].ToString().Replace(",", Environment.NewLine),
                                    "Synopsis"
                                ), 
                                20);
                            WriteCellValue(
                                acasOutputOpenXmlWriter,
                                LargeCellValueHandler(
                                    sqliteDataReader["Description"].ToString(),
                                    sqliteDataReader["VulnId"].ToString(),
                                    sqliteDataReader["AssetIdToReport"].ToString().Replace(",", Environment.NewLine),
                                    "Description"
                                ), 
                                20);
                            WriteCellValue(
                                acasOutputOpenXmlWriter,
                                LargeCellValueHandler(
                                    sqliteDataReader["PluginOutput"].ToString(),
                                    sqliteDataReader["VulnId"].ToString(),
                                    sqliteDataReader["AssetIdToReport"].ToString().Replace(",", Environment.NewLine),
                                    "PluginOutput"
                                ), 
                                20);
                            WriteCellValue(
                                acasOutputOpenXmlWriter,
                                LargeCellValueHandler(
                                    sqliteDataReader["FixText"].ToString(),
                                    sqliteDataReader["VulnId"].ToString(),
                                    sqliteDataReader["AssetIdToReport"].ToString().Replace(",", Environment.NewLine),
                                    "FixText"
                                ), 
                                20);
                            WriteCellValue(acasOutputOpenXmlWriter, sqliteDataReader["CrossReferences"].ToString(), 24);
                            WriteCellValue(acasOutputOpenXmlWriter, sqliteDataReader["CPEs"].ToString(), 24);
                            WriteCellValue(acasOutputOpenXmlWriter, sqliteDataReader["PluginPublishedDate"].ToString(), 24);
                            WriteCellValue(acasOutputOpenXmlWriter, sqliteDataReader["PluginModifiedDate"].ToString(), 24);
                            WriteCellValue(acasOutputOpenXmlWriter, sqliteDataReader["LastObserved"].ToString(), 24);
                            WriteCellValue(acasOutputOpenXmlWriter, sqliteDataReader["PatchPublishedDate"].ToString(), 24);
                            WriteCellValue(acasOutputOpenXmlWriter, sqliteDataReader["FileName"].ToString(), 24);
                            WriteCellValue(acasOutputOpenXmlWriter, string.Empty, 24);
                            WriteCellValue(acasOutputOpenXmlWriter, string.Empty, 24);
                            WriteCellValue(acasOutputOpenXmlWriter, string.Empty, 20);
                            acasOutputOpenXmlWriter.WriteEndElement();
                        }
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to insert ACAS output value.");
                throw exception;
            }
        }

        private void EndAcasOutput()
        {
            try
            {
                acasOutputOpenXmlWriter.WriteEndElement();
                acasOutputOpenXmlWriter.WriteEndElement();
                acasOutputOpenXmlWriter.Dispose();
            }
            catch (Exception exception)
            {
                log.Error("Unable to finalize ACAS Output tab.");
                throw exception;
            }
        }

        #endregion Create Acas Output

        #region Create STIG Details

        private void StartStigDetails(WorkbookPart workbookPart, Sheets sheets)
        {
            try
            {
                WorksheetPart worksheetPart = workbookPart.AddNewPart<WorksheetPart>();
                Sheet sheet = new Sheet() { Id = workbookPart.GetIdOfPart(worksheetPart), SheetId = sheetIndex, Name = "STIG Details" };
                sheetIndex++;
                sheets.Append(sheet);
                stigDetailsOpenXmlWriter = OpenXmlWriter.Create(worksheetPart);
                stigDetailsOpenXmlWriter.WriteStartElement(new Worksheet());
                WriteStigDetailsColumns();
                stigDetailsOpenXmlWriter.WriteStartElement(new SheetData());
                WriteStigDetailsHeaderRow();
            }
            catch (Exception exception)
            {
                log.Error("Unable to initialize STIG Details tab.");
                throw exception;
            }
        }

        private void WriteStigDetailsColumns()
        {
            try
            {
                stigDetailsOpenXmlWriter.WriteStartElement(new Columns());
                stigDetailsOpenXmlWriter.WriteElement(new Column() { Min = 1U, Max = 1U, Width = 10.00d, CustomWidth = true });
                stigDetailsOpenXmlWriter.WriteElement(new Column() { Min = 2U, Max = 2U, Width = 10.00d, CustomWidth = true });
                stigDetailsOpenXmlWriter.WriteElement(new Column() { Min = 3U, Max = 3U, Width = 20.00d, CustomWidth = true });
                stigDetailsOpenXmlWriter.WriteElement(new Column() { Min = 4U, Max = 4U, Width = 20.00d, CustomWidth = true });
                stigDetailsOpenXmlWriter.WriteElement(new Column() { Min = 5U, Max = 5U, Width = 10.00d, CustomWidth = true });
                stigDetailsOpenXmlWriter.WriteElement(new Column() { Min = 6U, Max = 6U, Width = 25.00d, CustomWidth = true });
                stigDetailsOpenXmlWriter.WriteElement(new Column() { Min = 7U, Max = 7U, Width = 25.00d, CustomWidth = true });
                stigDetailsOpenXmlWriter.WriteElement(new Column() { Min = 8U, Max = 8U, Width = 25.00d, CustomWidth = true });
                stigDetailsOpenXmlWriter.WriteElement(new Column() { Min = 9U, Max = 9U, Width = 10.00d, CustomWidth = true });
                stigDetailsOpenXmlWriter.WriteElement(new Column() { Min = 10U, Max = 10U, Width = 15.00d, CustomWidth = true });
                stigDetailsOpenXmlWriter.WriteElement(new Column() { Min = 11U, Max = 11U, Width = 35.00d, CustomWidth = true });
                stigDetailsOpenXmlWriter.WriteElement(new Column() { Min = 12U, Max = 12U, Width = 35.00d, CustomWidth = true });
                stigDetailsOpenXmlWriter.WriteElement(new Column() { Min = 13U, Max = 13U, Width = 35.00d, CustomWidth = true });
                stigDetailsOpenXmlWriter.WriteElement(new Column() { Min = 14U, Max = 14U, Width = 20.00d, CustomWidth = true });
                stigDetailsOpenXmlWriter.WriteElement(new Column() { Min = 15U, Max = 15U, Width = 20.00d, CustomWidth = true });
                stigDetailsOpenXmlWriter.WriteElement(new Column() { Min = 16U, Max = 16U, Width = 15.00d, CustomWidth = true });
                stigDetailsOpenXmlWriter.WriteElement(new Column() { Min = 17U, Max = 17U, Width = 35.00d, CustomWidth = true });
                stigDetailsOpenXmlWriter.WriteElement(new Column() { Min = 18U, Max = 18U, Width = 35.00d, CustomWidth = true });
                stigDetailsOpenXmlWriter.WriteElement(new Column() { Min = 19U, Max = 19U, Width = 35.00d, CustomWidth = true });
                stigDetailsOpenXmlWriter.WriteElement(new Column() { Min = 20U, Max = 20U, Width = 25.00d, CustomWidth = true });
                stigDetailsOpenXmlWriter.WriteElement(new Column() { Min = 21U, Max = 21U, Width = 15.00d, CustomWidth = true });
                stigDetailsOpenXmlWriter.WriteElement(new Column() { Min = 22U, Max = 22U, Width = 35.00d, CustomWidth = true });
                stigDetailsOpenXmlWriter.WriteEndElement();
            }
            catch (Exception exception)
            {
                log.Error("Unable to generate STIG Details columns.");
                throw exception;
            }
        }

        private void WriteStigDetailsHeaderRow()
        {
            try
            {
                stigDetailsOpenXmlWriter.WriteStartElement(new Row());
                WriteCellValue(stigDetailsOpenXmlWriter, "IA Control", 4);
                WriteCellValue(stigDetailsOpenXmlWriter, "NIST Control", 4);
                WriteCellValue(stigDetailsOpenXmlWriter, "CCI Number", 4);
                WriteCellValue(stigDetailsOpenXmlWriter, "STIG Title", 4);
                WriteCellValue(stigDetailsOpenXmlWriter, "V-ID", 4);
                WriteCellValue(stigDetailsOpenXmlWriter, "Rule ID", 4);
                WriteCellValue(stigDetailsOpenXmlWriter, "STIG ID", 4);
                WriteCellValue(stigDetailsOpenXmlWriter, "STIG Name", 4);
                WriteCellValue(stigDetailsOpenXmlWriter, "Risk Factor", 4);
                WriteCellValue(stigDetailsOpenXmlWriter, "STIG Severity", 4);
                WriteCellValue(stigDetailsOpenXmlWriter, "Description", 4);
                WriteCellValue(stigDetailsOpenXmlWriter, "Check Content", 4);
                WriteCellValue(stigDetailsOpenXmlWriter, "Solution", 4);
                WriteCellValue(stigDetailsOpenXmlWriter, "Host Name", 4);
                WriteCellValue(stigDetailsOpenXmlWriter, "IP Address", 4);
                WriteCellValue(stigDetailsOpenXmlWriter, "Status", 4);
                WriteCellValue(stigDetailsOpenXmlWriter, "Comments", 4);
                WriteCellValue(stigDetailsOpenXmlWriter, "Finding Details", 4);
                WriteCellValue(stigDetailsOpenXmlWriter, "File Name", 4);
                WriteCellValue(stigDetailsOpenXmlWriter, "Group Name", 4);
                WriteCellValue(stigDetailsOpenXmlWriter, "Review Status", 4);
                WriteCellValue(stigDetailsOpenXmlWriter, "Notes", 4);
                stigDetailsOpenXmlWriter.WriteEndElement();
            }
            catch (Exception exception)
            {
                log.Error("Unable to generate STIG Details header row.");
                throw exception;
            }
        }

        private void WriteStigDetailItems(string findingType)
        {
            try
            {
                using (SQLiteCommand sqliteCommand = FindingsDatabaseActions.sqliteConnection.CreateCommand())
                {
                    sqliteCommand.Parameters.Add(new SQLiteParameter("FindingType", findingType));
                    sqliteCommand.CommandText = SetSqliteCommandText(false, findingType);
                    using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
                    {
                        while (sqliteDataReader.Read())
                        {
                            stigDetailsOpenXmlWriter.WriteStartElement(new Row());
                            WriteCellValue(stigDetailsOpenXmlWriter, sqliteDataReader["IaControl"].ToString(), 24);
                            WriteCellValue(stigDetailsOpenXmlWriter, sqliteDataReader["NistControl"].ToString(), 24);
                            WriteCellValue(stigDetailsOpenXmlWriter, sqliteDataReader["CciNumber"].ToString(), 24);
                            WriteCellValue(stigDetailsOpenXmlWriter, sqliteDataReader["VulnTitle"].ToString(), 20);
                            WriteCellValue(stigDetailsOpenXmlWriter, sqliteDataReader["VulnId"].ToString(), 24);
                            WriteCellValue(stigDetailsOpenXmlWriter, sqliteDataReader["RuleId"].ToString(), 24);
                            WriteCellValue(stigDetailsOpenXmlWriter, sqliteDataReader["StigId"].ToString(), 24);
                            WriteCellValue(stigDetailsOpenXmlWriter, sqliteDataReader["Source"].ToString(), 24);
                            WriteCellValue(stigDetailsOpenXmlWriter, sqliteDataReader["Impact"].ToString(), 24);
                            WriteCellValue(stigDetailsOpenXmlWriter, sqliteDataReader["RawRisk"].ToString(), 24);
                            WriteCellValue(
                                stigDetailsOpenXmlWriter,
                                LargeCellValueHandler(
                                    sqliteDataReader["Description"].ToString(),
                                    sqliteDataReader["VulnId"].ToString(),
                                    sqliteDataReader["AssetIdToReport"].ToString().Replace(",", Environment.NewLine),
                                    "Description"
                                ), 
                                20);
                            WriteCellValue(
                                stigDetailsOpenXmlWriter,
                                LargeCellValueHandler(
                                    sqliteDataReader["CheckContent"].ToString(),
                                    sqliteDataReader["VulnId"].ToString(),
                                    sqliteDataReader["AssetIdToReport"].ToString().Replace(",", Environment.NewLine),
                                    "CheckContent"
                                ), 
                                20);
                            WriteCellValue(
                                stigDetailsOpenXmlWriter,
                                LargeCellValueHandler(
                                    sqliteDataReader["FixText"].ToString(),
                                    sqliteDataReader["VulnId"].ToString(),
                                    sqliteDataReader["AssetIdToReport"].ToString().Replace(",", Environment.NewLine),
                                    "FixText"
                                ), 
                                20);
                            WriteCellValue(stigDetailsOpenXmlWriter, sqliteDataReader["HostName"].ToString(), 24);
                            WriteCellValue(stigDetailsOpenXmlWriter, sqliteDataReader["IpAddress"].ToString(), 20);
                            WriteCellValue(stigDetailsOpenXmlWriter, sqliteDataReader["Status"].ToString(), 24);
                            WriteCellValue(
                                stigDetailsOpenXmlWriter,
                                LargeCellValueHandler(
                                    sqliteDataReader["Comments"].ToString(),
                                    sqliteDataReader["VulnId"].ToString(),
                                    sqliteDataReader["AssetIdToReport"].ToString().Replace(",", Environment.NewLine),
                                    "Comments"
                                ), 
                                20);
                            WriteCellValue(
                                stigDetailsOpenXmlWriter,
                                LargeCellValueHandler(
                                    sqliteDataReader["FindingDetails"].ToString(),
                                    sqliteDataReader["VulnId"].ToString(),
                                    sqliteDataReader["AssetIdToReport"].ToString().Replace(",", Environment.NewLine),
                                    "FindingDetails"
                                ), 
                                20);
                            WriteCellValue(stigDetailsOpenXmlWriter, sqliteDataReader["FileName"].ToString(), 24);
                            WriteCellValue(stigDetailsOpenXmlWriter, sqliteDataReader["GroupName"].ToString(), 24);
                            WriteCellValue(stigDetailsOpenXmlWriter, string.Empty, 24);
                            WriteCellValue(stigDetailsOpenXmlWriter, string.Empty, 20);
                            stigDetailsOpenXmlWriter.WriteEndElement();
                        }
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to insert STIG Detail item.");
                throw exception;
            }
        }

        private void EndStigDetails()
        {
            try
            {
                stigDetailsOpenXmlWriter.WriteEndElement();
                stigDetailsOpenXmlWriter.WriteEndElement();
                stigDetailsOpenXmlWriter.Dispose();
            }
            catch (Exception exception)
            {
                log.Error("Unable to finalize STIG Details tab.");
                throw exception;
            }
        }

        #endregion

        #region Create FPR Details

        private void StartFprDetails(WorkbookPart workbookPart, Sheets sheets)
        {
            try
            {
                WorksheetPart worksheetPart = workbookPart.AddNewPart<WorksheetPart>();
                Sheet sheet = new Sheet() { Id = workbookPart.GetIdOfPart(worksheetPart), SheetId = sheetIndex, Name = "Fortify Details" };
                sheetIndex++;
                sheets.Append(sheet);
                fprDetailsOpenXmlWriter = OpenXmlWriter.Create(worksheetPart);
                fprDetailsOpenXmlWriter.WriteStartElement(new Worksheet());
                WriteFprDetailsColumns();
                fprDetailsOpenXmlWriter.WriteStartElement(new SheetData());
                WriteFprDetailsHeaderRow();
            }
            catch (Exception exception)
            {
                log.Error("Unable to initialize Fortify Details tab.");
                throw exception;
            }
        }

        private void WriteFprDetailsColumns()
        {
            try
            {
                fprDetailsOpenXmlWriter.WriteStartElement(new Columns());
                fprDetailsOpenXmlWriter.WriteElement(new Column() { Min = 1U, Max = 1U, Width = 20.00d, CustomWidth = true });
                fprDetailsOpenXmlWriter.WriteElement(new Column() { Min = 2U, Max = 2U, Width = 20.00d, CustomWidth = true });
                fprDetailsOpenXmlWriter.WriteElement(new Column() { Min = 3U, Max = 3U, Width = 10.00d, CustomWidth = true });
                fprDetailsOpenXmlWriter.WriteElement(new Column() { Min = 4U, Max = 4U, Width = 25.00d, CustomWidth = true });
                fprDetailsOpenXmlWriter.WriteElement(new Column() { Min = 5U, Max = 5U, Width = 25.00d, CustomWidth = true });
                fprDetailsOpenXmlWriter.WriteElement(new Column() { Min = 6U, Max = 6U, Width = 10.00d, CustomWidth = true });
                fprDetailsOpenXmlWriter.WriteElement(new Column() { Min = 7U, Max = 7U, Width = 10.00d, CustomWidth = true });
                fprDetailsOpenXmlWriter.WriteElement(new Column() { Min = 8U, Max = 8U, Width = 15.00d, CustomWidth = true });
                fprDetailsOpenXmlWriter.WriteElement(new Column() { Min = 9U, Max = 9U, Width = 35.00d, CustomWidth = true });
                fprDetailsOpenXmlWriter.WriteElement(new Column() { Min = 10U, Max = 10U, Width = 35.00d, CustomWidth = true });
                fprDetailsOpenXmlWriter.WriteElement(new Column() { Min = 11U, Max = 11U, Width = 35.00d, CustomWidth = true });
                fprDetailsOpenXmlWriter.WriteElement(new Column() { Min = 12U, Max = 12U, Width = 35.00d, CustomWidth = true });
                fprDetailsOpenXmlWriter.WriteElement(new Column() { Min = 13U, Max = 13U, Width = 10.00d, CustomWidth = true });
                fprDetailsOpenXmlWriter.WriteElement(new Column() { Min = 14U, Max = 14U, Width = 20.00d, CustomWidth = true });
                fprDetailsOpenXmlWriter.WriteElement(new Column() { Min = 15U, Max = 15U, Width = 15.00d, CustomWidth = true });
                fprDetailsOpenXmlWriter.WriteElement(new Column() { Min = 16U, Max = 16U, Width = 25.00d, CustomWidth = true });
                fprDetailsOpenXmlWriter.WriteElement(new Column() { Min = 17U, Max = 17U, Width = 15.00d, CustomWidth = true });
                fprDetailsOpenXmlWriter.WriteElement(new Column() { Min = 18U, Max = 18U, Width = 35.00d, CustomWidth = true });
                fprDetailsOpenXmlWriter.WriteEndElement();
            }
            catch (Exception exception)
            {
                log.Error("Unable to generate Fortify Details columns.");
                throw exception;
            }
        }

        private void WriteFprDetailsHeaderRow()
        {
            try
            {
                fprDetailsOpenXmlWriter.WriteStartElement(new Row());
                WriteCellValue(fprDetailsOpenXmlWriter, "Class ID", 4);
                WriteCellValue(fprDetailsOpenXmlWriter, "Instance ID", 4);
                WriteCellValue(fprDetailsOpenXmlWriter, "STIG ID", 4);
                WriteCellValue(fprDetailsOpenXmlWriter, "Categorization", 4);
                WriteCellValue(fprDetailsOpenXmlWriter, "Vulnerability Title", 4);
                WriteCellValue(fprDetailsOpenXmlWriter, "Raw Risk", 4);
                WriteCellValue(fprDetailsOpenXmlWriter, "Risk Factor", 4);
                WriteCellValue(fprDetailsOpenXmlWriter, "Status", 4);
                WriteCellValue(fprDetailsOpenXmlWriter, "Description", 4);
                WriteCellValue(fprDetailsOpenXmlWriter, "Risk Statement", 4);
                WriteCellValue(fprDetailsOpenXmlWriter, "Fix Text", 4);
                WriteCellValue(fprDetailsOpenXmlWriter, "Comments", 4);
                WriteCellValue(fprDetailsOpenXmlWriter, "NIST Control", 4);
                WriteCellValue(fprDetailsOpenXmlWriter, "Software Name", 4);
                WriteCellValue(fprDetailsOpenXmlWriter, "Fortify Source", 4);
                WriteCellValue(fprDetailsOpenXmlWriter, "Filename", 4);
                WriteCellValue(fprDetailsOpenXmlWriter, "Review Status", 4);
                WriteCellValue(fprDetailsOpenXmlWriter, "Notes", 4);
                fprDetailsOpenXmlWriter.WriteEndElement();
            }
            catch (Exception exception)
            {
                log.Error("Unable to generate Fortify Details header row.");
                throw exception;
            }
        }

        private void WriteFprDetailsItems(string findingType)
        {
            try
            {
                using (SQLiteCommand sqliteCommand = FindingsDatabaseActions.sqliteConnection.CreateCommand())
                {
                    sqliteCommand.Parameters.Add(new SQLiteParameter("FindingType", findingType));
                    sqliteCommand.CommandText = SetSqliteCommandText(false, findingType);
                    using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
                    {
                        while (sqliteDataReader.Read())
                        {
                            fprDetailsOpenXmlWriter.WriteStartElement(new Row());
                            WriteCellValue(fprDetailsOpenXmlWriter, sqliteDataReader["VulnId"].ToString(), 24);
                            WriteCellValue(fprDetailsOpenXmlWriter, sqliteDataReader["CrossReferences"].ToString(), 24);
                            WriteCellValue(fprDetailsOpenXmlWriter, sqliteDataReader["StigId"].ToString(), 24);
                            WriteCellValue(
                                fprDetailsOpenXmlWriter,
                                LargeCellValueHandler(
                                    sqliteDataReader["CheckContent"].ToString(),
                                    sqliteDataReader["VulnId"].ToString(),
                                    sqliteDataReader["AssetIdToReport"].ToString().Replace(",", Environment.NewLine),
                                    "CheckContent"
                                ), 20);
                            WriteCellValue(fprDetailsOpenXmlWriter, sqliteDataReader["VulnTitle"].ToString(), 20);
                            WriteCellValue(fprDetailsOpenXmlWriter, sqliteDataReader["RawRisk"].ToString(), 24);
                            WriteCellValue(fprDetailsOpenXmlWriter, sqliteDataReader["Impact"].ToString(), 24);
                            WriteCellValue(fprDetailsOpenXmlWriter, sqliteDataReader["Status"].ToString(), 24);
                            WriteCellValue(
                                fprDetailsOpenXmlWriter, LargeCellValueHandler(
                                    sqliteDataReader["Description"].ToString(),
                                    sqliteDataReader["VulnId"].ToString(),
                                    sqliteDataReader["AssetIdToReport"].ToString().Replace(",", Environment.NewLine),
                                    "Description"
                                ), 
                                20);
                            WriteCellValue(
                                fprDetailsOpenXmlWriter,
                                LargeCellValueHandler(
                                    sqliteDataReader["RiskStatement"].ToString(),
                                    sqliteDataReader["VulnId"].ToString(),
                                    sqliteDataReader["AssetIdToReport"].ToString().Replace(",", Environment.NewLine),
                                    "RiskStatement"
                                ), 
                                20);
                            WriteCellValue(
                                fprDetailsOpenXmlWriter,
                                LargeCellValueHandler(
                                    sqliteDataReader["FixText"].ToString(),
                                    sqliteDataReader["VulnId"].ToString(),
                                    sqliteDataReader["AssetIdToReport"].ToString().Replace(",", Environment.NewLine),
                                    "FixText"
                                ), 
                                20);
                            WriteCellValue(
                                fprDetailsOpenXmlWriter,
                                LargeCellValueHandler(
                                    sqliteDataReader["Comments"].ToString(),
                                    sqliteDataReader["VulnId"].ToString(),
                                    sqliteDataReader["AssetIdToReport"].ToString().Replace(",", Environment.NewLine),
                                    "Comments"
                                ), 
                                20);
                            WriteCellValue(fprDetailsOpenXmlWriter, sqliteDataReader["NistControl"].ToString(), 24);
                            WriteCellValue(fprDetailsOpenXmlWriter, sqliteDataReader["AssetIdToReport"].ToString(), 24);
                            WriteCellValue(fprDetailsOpenXmlWriter, sqliteDataReader["Source"].ToString() + " :: " +
                                sqliteDataReader["Version"].ToString(), 24);
                            WriteCellValue(fprDetailsOpenXmlWriter, sqliteDataReader["FileName"].ToString(), 24);
                            WriteCellValue(fprDetailsOpenXmlWriter, string.Empty, 24);
                            WriteCellValue(fprDetailsOpenXmlWriter, string.Empty, 20);
                            fprDetailsOpenXmlWriter.WriteEndElement();
                        }
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to insert Fortify Detail item.");
                throw exception;
            }
        }

        private void EndFprDetails()
        {
            try
            {
                fprDetailsOpenXmlWriter.WriteEndElement();
                fprDetailsOpenXmlWriter.WriteEndElement();
                fprDetailsOpenXmlWriter.Dispose();

            }
            catch (Exception exception)
            {
                log.Error("Unable to finalize Fortify Details tab.");
                throw exception;
            }
        }

        #endregion

        #region Create Discrepancies

        private void StartDiscrepancies(WorkbookPart workbookPart, Sheets sheets)
        {
            try
            {
                WorksheetPart worksheetPart = workbookPart.AddNewPart<WorksheetPart>();
                Sheet sheet = new Sheet() { Id = workbookPart.GetIdOfPart(worksheetPart), SheetId = sheetIndex, Name = @"Discrepancies" };
                sheetIndex++;
                sheets.Append(sheet);
                discrepanciesOpenXmlWriter = OpenXmlWriter.Create(worksheetPart);
                discrepanciesOpenXmlWriter.WriteStartElement(new Worksheet());
                WriteDiscrepanciesColumns();
                discrepanciesOpenXmlWriter.WriteStartElement(new SheetData());
                WriteDiscrepanciesTabHeaderRow();
            }
            catch (Exception exception)
            {
                log.Error("Unable to initialize Discrepancies tab.");
                throw exception;
            }
        }

        private void WriteDiscrepanciesColumns()
        {
            try
            {
                discrepanciesOpenXmlWriter.WriteStartElement(new Columns());
                discrepanciesOpenXmlWriter.WriteElement(new Column() { Min = 1U, Max = 1U, Width = 30d, CustomWidth = true });
                discrepanciesOpenXmlWriter.WriteElement(new Column() { Min = 2U, Max = 2U, Width = 10d, CustomWidth = true });
                discrepanciesOpenXmlWriter.WriteElement(new Column() { Min = 3U, Max = 3U, Width = 30d, CustomWidth = true });
                discrepanciesOpenXmlWriter.WriteElement(new Column() { Min = 4U, Max = 4U, Width = 15d, CustomWidth = true });
                discrepanciesOpenXmlWriter.WriteElement(new Column() { Min = 5U, Max = 5U, Width = 15d, CustomWidth = true });
                discrepanciesOpenXmlWriter.WriteElement(new Column() { Min = 6U, Max = 6U, Width = 55d, CustomWidth = true });
                discrepanciesOpenXmlWriter.WriteElement(new Column() { Min = 7U, Max = 7U, Width = 55d, CustomWidth = true });
                discrepanciesOpenXmlWriter.WriteElement(new Column() { Min = 8U, Max = 8U, Width = 55d, CustomWidth = true });
                discrepanciesOpenXmlWriter.WriteElement(new Column() { Min = 9U, Max = 9U, Width = 55d, CustomWidth = true });
                discrepanciesOpenXmlWriter.WriteElement(new Column() { Min = 10U, Max = 10U, Width = 20d, CustomWidth = true });
                discrepanciesOpenXmlWriter.WriteElement(new Column() { Min = 11U, Max = 11U, Width = 20d, CustomWidth = true });
                discrepanciesOpenXmlWriter.WriteEndElement();
            }
            catch (Exception exception)
            {
                log.Error("Unable to generate Discrepancies columns.");
                throw exception;
            }
        }

        private void WriteDiscrepanciesTabHeaderRow()
        {
            try
            {
                discrepanciesOpenXmlWriter.WriteStartElement(new Row());
                WriteCellValue(discrepanciesOpenXmlWriter, "Source", 4);
                WriteCellValue(discrepanciesOpenXmlWriter, "Vuln ID", 4);
                WriteCellValue(discrepanciesOpenXmlWriter, "Vuln Title", 4);
                WriteCellValue(discrepanciesOpenXmlWriter, "STIG Status", 4);
                WriteCellValue(discrepanciesOpenXmlWriter, "SCAP Status", 4);
                WriteCellValue(discrepanciesOpenXmlWriter, "STIG Comments", 4);
                WriteCellValue(discrepanciesOpenXmlWriter, "STIG Finding Details", 4);
                WriteCellValue(discrepanciesOpenXmlWriter, "STIG File Name", 4);
                WriteCellValue(discrepanciesOpenXmlWriter, "SCAP File Name", 4);
                WriteCellValue(discrepanciesOpenXmlWriter, "STIG Affected Asset", 4);
                WriteCellValue(discrepanciesOpenXmlWriter, "SCAP Affected Asset", 4);
                discrepanciesOpenXmlWriter.WriteEndElement();
            }
            catch (Exception exception)
            {
                log.Error("Unable to generate Discrepancies header row.");
                throw exception;
            }
        }

        private void WriteIndividualDiscrepancies(AsyncObservableCollection<MitigationItem> mitigationList)
        {
            try
            {
                List<DiscrepancyItem> stigList = ObtainDiscrepancyItemsForComparisson("CKL");
                List<DiscrepancyItem> scapList = ObtainDiscrepancyItemsForComparisson("XCCDF");
                if (stigList.Count > 0 && scapList.Count > 0)
                {
                    foreach (DiscrepancyItem item in stigList)
                    {
                        MitigationItem mitigationItem = mitigationList.FirstOrDefault(
                            x => x.MitigationGroupName == item.Group && x.MitigationVulnerabilityId == item.VulnId);
                        if (mitigationItem != null)
                        { item.Status = mitigationItem.MitigationStatus; }
                    }

                    foreach (DiscrepancyItem item in scapList)
                    {
                        MitigationItem mitigationItem = mitigationList.FirstOrDefault(
                            x => x.MitigationGroupName == item.Group && x.MitigationVulnerabilityId == item.VulnId);
                        if (mitigationItem != null)
                        { item.Status = mitigationItem.MitigationStatus; }
                        DiscrepancyItem discrepancy = stigList.FirstOrDefault(
                            x => x.RuleId == item.RuleId && x.AssetId == item.AssetId && x.Status != item.Status);
                        if (discrepancy != null)
                        {
                            discrepanciesOpenXmlWriter.WriteStartElement(new Row());
                            WriteCellValue(discrepanciesOpenXmlWriter, discrepancy.Source, 20);
                            WriteCellValue(discrepanciesOpenXmlWriter, discrepancy.VulnId, 24);
                            WriteCellValue(discrepanciesOpenXmlWriter, discrepancy.VulnTitle, 20);
                            WriteCellValue(discrepanciesOpenXmlWriter, discrepancy.Status, 24);
                            WriteCellValue(discrepanciesOpenXmlWriter, item.Status, 24);
                            WriteCellValue(
                                discrepanciesOpenXmlWriter,
                                LargeCellValueHandler(
                                    discrepancy.Comments,
                                    discrepancy.VulnId,
                                    discrepancy.AssetId,
                                    "Comments"
                                ),
                                20);
                            WriteCellValue(
                                discrepanciesOpenXmlWriter,
                                LargeCellValueHandler(
                                    discrepancy.FindingDetails,
                                    discrepancy.VulnId,
                                    discrepancy.AssetId,
                                    "FindingDetails"
                                ), 
                                20);
                            WriteCellValue(discrepanciesOpenXmlWriter, discrepancy.FileName, 20);
                            WriteCellValue(discrepanciesOpenXmlWriter, item.FileName, 20);
                            WriteCellValue(discrepanciesOpenXmlWriter, discrepancy.AssetId, 24);
                            WriteCellValue(discrepanciesOpenXmlWriter, item.AssetId, 24);
                            discrepanciesOpenXmlWriter.WriteEndElement();
                        }
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to insert discrepancy.");
                throw exception;
            }
        }

        private void EndDiscrepancies()
        {
            try
            {
                discrepanciesOpenXmlWriter.WriteEndElement();
                discrepanciesOpenXmlWriter.WriteEndElement();
                discrepanciesOpenXmlWriter.Dispose();
            }
            catch (Exception exception)
            {
                log.Error("Unable to finalize Discrepancies tab.");
                throw exception;
            }
        }

        #endregion Create Discrepancies

        #region Create Test Plan

        private void StartTestPlan(WorkbookPart workbookPart, Sheets sheets)
        {
            try
            {
                WorksheetPart worksheetPart = workbookPart.AddNewPart<WorksheetPart>();
                Sheet sheet = new Sheet() { Id = workbookPart.GetIdOfPart(worksheetPart), SheetId = sheetIndex, Name = "Test Plan" };
                sheetIndex++;
                sheets.Append(sheet);
                testPlanOpenXmlWriter = OpenXmlWriter.Create(worksheetPart);
                testPlanOpenXmlWriter.WriteStartElement(new Worksheet());
                WriteTestPlanColumns();
                testPlanOpenXmlWriter.WriteStartElement(new SheetData());
            }
            catch (Exception exception)
            {
                log.Error("Unable to initialize Test Plan tab.");
                throw exception;
            }
        }

        private void WriteTestPlanColumns()
        {
            try
            {
                testPlanOpenXmlWriter.WriteStartElement(new Columns());
                testPlanOpenXmlWriter.WriteElement(new Column() { Min = 1U, Max = 1U, Width = 62d, CustomWidth = true });
                testPlanOpenXmlWriter.WriteElement(new Column() { Min = 2U, Max = 2U, Width = 15d, CustomWidth = true });
                testPlanOpenXmlWriter.WriteElement(new Column() { Min = 3U, Max = 3U, Width = 16d, CustomWidth = true });
                testPlanOpenXmlWriter.WriteElement(new Column() { Min = 3U, Max = 3U, Width = 16d, CustomWidth = true });
                testPlanOpenXmlWriter.WriteElement(new Column() { Min = 4U, Max = 4U, Width = 16d, CustomWidth = true });
                testPlanOpenXmlWriter.WriteElement(new Column() { Min = 5U, Max = 5U, Width = 16d, CustomWidth = true });
                testPlanOpenXmlWriter.WriteElement(new Column() { Min = 6U, Max = 6U, Width = 16d, CustomWidth = true });
                testPlanOpenXmlWriter.WriteElement(new Column() { Min = 7U, Max = 7U, Width = 45d, CustomWidth = true });
                testPlanOpenXmlWriter.WriteEndElement();
            }
            catch (Exception exception)
            {
                log.Error("Unable to generate Test Plan columns.");
                throw exception;
            }
        }

        private void WriteTestPlanHeaderRowOne()
        {
            try
            {
                testPlanOpenXmlWriter.WriteStartElement(new Row() { Height = 25, CustomHeight = true });
                WriteCellValue(testPlanOpenXmlWriter, "Test Plan", 3);
                WriteCellValue(testPlanOpenXmlWriter, string.Empty, 3);
                WriteCellValue(testPlanOpenXmlWriter, string.Empty, 3);
                WriteCellValue(testPlanOpenXmlWriter, string.Empty, 3);
                WriteCellValue(testPlanOpenXmlWriter, string.Empty, 3);
                WriteCellValue(testPlanOpenXmlWriter, string.Empty, 3);
                testPlanOpenXmlWriter.WriteEndElement();
                testPlanMergeCellReferences.Add("A" + testPlanRowCounterIndex.ToString() + ":F" + testPlanRowCounterIndex.ToString());
                testPlanRowCounterIndex++;
            }
            catch (Exception exception)
            {
                log.Error("Unable to generate first Test Plan header row.");
                throw exception;
            }
        }

        private void WriteTestPlanHeaderRowTwo()
        {
            try
            {
                testPlanOpenXmlWriter.WriteStartElement(new Row());
                WriteCellValue(testPlanOpenXmlWriter, "System Name:", 2);
                WriteCellValue(testPlanOpenXmlWriter, "System Acronym:", 2);
                WriteCellValue(testPlanOpenXmlWriter, "eMASS ID:", 2);
                WriteCellValue(testPlanOpenXmlWriter, "Confidentiality:", 2);
                WriteCellValue(testPlanOpenXmlWriter, "Integrity:", 2);
                WriteCellValue(testPlanOpenXmlWriter, "Availability:", 2);
                testPlanOpenXmlWriter.WriteEndElement();
                testPlanRowCounterIndex++;
            }
            catch (Exception exception)
            {
                log.Error("Unable to generate second Test Plan header row.");
                throw exception;
            }
        }

        private void WriteTestPlanHeaderRowThree()
        {
            try
            {
                testPlanOpenXmlWriter.WriteStartElement(new Row());
                WriteCellValue(testPlanOpenXmlWriter, string.Empty, 20);
                WriteCellValue(testPlanOpenXmlWriter, string.Empty, 20);
                WriteCellValue(testPlanOpenXmlWriter, string.Empty, 20);
                WriteCellValue(testPlanOpenXmlWriter, string.Empty, 20);
                WriteCellValue(testPlanOpenXmlWriter, string.Empty, 20);
                WriteCellValue(testPlanOpenXmlWriter, string.Empty, 20);
                testPlanOpenXmlWriter.WriteEndElement();
                testPlanRowCounterIndex++;
            }
            catch (Exception exception)
            {
                log.Error("Unable to generate third Test Plan header row.");
                throw exception;
            }
        }

        private void ObtainTestPlanItems(string findingType)
        {
            try
            {
                using (SQLiteCommand sqliteCommand = FindingsDatabaseActions.sqliteConnection.CreateCommand())
                {
                    sqliteCommand.CommandText = "SELECT DISTINCT Source, Version, Release, HostName, IpAddress, FileName " +
                        "FROM UniqueFinding NATURAL JOIN FileNames NATURAL JOIN Assets " +
                        "NATURAL JOIN VulnerabilitySources NATURAL JOIN FindingTypes " +
                        "WHERE FindingType = @FindingType ORDER BY Source, Version, Release;";
                    sqliteCommand.Parameters.Add(new SQLiteParameter("FindingType", findingType));
                    using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
                    {
                        if (sqliteDataReader.HasRows)
                        {
                            WriteTestTypeHeaderRowOne(findingType);
                            WriteTestTypeHeaderRowTwo(findingType);
                            WriteTestPlanItems(sqliteDataReader);
                        }
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to obtain test plan items.");
                throw exception;
            }
        }

        private void WriteTestTypeHeaderRowOne(string findingType)
        {
            try
            {
                testPlanOpenXmlWriter.WriteStartElement(new Row());
                testPlanOpenXmlWriter.WriteEndElement();
                testPlanRowCounterIndex++;
                testPlanOpenXmlWriter.WriteStartElement(new Row());
                switch (findingType)
                {
                    case "ACAS":
                        {
                            WriteCellValue(testPlanOpenXmlWriter, "Remediation Scan", 3);
                            break;
                        }
                    case "XCCDF":
                        {
                            WriteCellValue(testPlanOpenXmlWriter, "STIG Benchmark(s)", 3);
                            break;
                        }
                    case "CKL":
                        {
                            WriteCellValue(testPlanOpenXmlWriter, "STIG Checklist(s)", 3);
                            break;
                        }
                    default:
                        {
                            WriteCellValue(testPlanOpenXmlWriter, string.Empty, 3);
                            break;
                        }
                }
                WriteCellValue(testPlanOpenXmlWriter, string.Empty, 3);
                WriteCellValue(testPlanOpenXmlWriter, string.Empty, 3);
                WriteCellValue(testPlanOpenXmlWriter, string.Empty, 3);
                WriteCellValue(testPlanOpenXmlWriter, string.Empty, 3);
                WriteCellValue(testPlanOpenXmlWriter, string.Empty, 3);
                WriteCellValue(testPlanOpenXmlWriter, string.Empty, 3);
                WriteCellValue(testPlanOpenXmlWriter, string.Empty, 3);
                testPlanOpenXmlWriter.WriteEndElement();
                testPlanMergeCellReferences.Add("A" + testPlanRowCounterIndex.ToString() + ":H" + testPlanRowCounterIndex.ToString());
                testPlanRowCounterIndex++;
            }
            catch (Exception exception)
            {
                log.Error("Unable to create Test Plan finding type header row.");
                throw exception;
            }
        }

        private void WriteTestTypeHeaderRowTwo(string findingType)
        {
            testPlanOpenXmlWriter.WriteStartElement(new Row());
            switch (findingType)
            {
                case "ACAS":
                    {
                        WriteCellValue(testPlanOpenXmlWriter, "Scan Tool", 17);
                        WriteCellValue(testPlanOpenXmlWriter, "Scanner Version", 17);
                        WriteCellValue(testPlanOpenXmlWriter, "Plugin Engine", 17);
                        break;
                    }
                case "XCCDF":
                    {
                        WriteCellValue(testPlanOpenXmlWriter, "Benchmark Title", 17);
                        WriteCellValue(testPlanOpenXmlWriter, "Version", 17);
                        WriteCellValue(testPlanOpenXmlWriter, "Release", 17);
                        break;
                    }
                case "CKL":
                    {
                        WriteCellValue(testPlanOpenXmlWriter, "Checklist Title", 17);
                        WriteCellValue(testPlanOpenXmlWriter, "Version", 17);
                        WriteCellValue(testPlanOpenXmlWriter, "Release", 17);
                        break;
                    }
                default:
                    {
                        WriteCellValue(testPlanOpenXmlWriter, "Tool", 17);
                        WriteCellValue(testPlanOpenXmlWriter, "Version", 17);
                        WriteCellValue(testPlanOpenXmlWriter, "Release", 17);
                        break;
                    }
            }
            if (!findingType.Equals("FPR"))
            { WriteCellValue(testPlanOpenXmlWriter, "Host Name", 17); }
            else
            { WriteCellValue(testPlanOpenXmlWriter, "Software Name", 17); }
            WriteCellValue(testPlanOpenXmlWriter, "IP Address", 17);
            WriteCellValue(testPlanOpenXmlWriter, "Test Date", 17);
            WriteCellValue(testPlanOpenXmlWriter, "File Name", 17);
            WriteCellValue(testPlanOpenXmlWriter, string.Empty, 17);
            testPlanOpenXmlWriter.WriteEndElement();
            testPlanMergeCellReferences.Add("G" + testPlanRowCounterIndex.ToString() + ":H" + testPlanRowCounterIndex.ToString());
            testPlanRowCounterIndex++;
        }

        private void WriteTestPlanItems(SQLiteDataReader sqliteDataReader)
        {
            try
            {
                while (sqliteDataReader.Read())
                {
                    testPlanOpenXmlWriter.WriteStartElement(new Row());
                    WriteCellValue(testPlanOpenXmlWriter, sqliteDataReader["Source"].ToString(), 18);
                    WriteCellValue(testPlanOpenXmlWriter, sqliteDataReader["Version"].ToString(), 18);
                    WriteCellValue(testPlanOpenXmlWriter, sqliteDataReader["Release"].ToString(), 18);
                    WriteCellValue(testPlanOpenXmlWriter, sqliteDataReader["HostName"].ToString(), 18);
                    WriteCellValue(testPlanOpenXmlWriter, sqliteDataReader["IpAddress"].ToString(), 18);
                    WriteCellValue(testPlanOpenXmlWriter, string.Empty, 18);
                    WriteCellValue(testPlanOpenXmlWriter, sqliteDataReader["FileName"].ToString(), 18);
                    WriteCellValue(testPlanOpenXmlWriter, string.Empty, 18);
                    testPlanOpenXmlWriter.WriteEndElement();
                    testPlanMergeCellReferences.Add("G" + testPlanRowCounterIndex.ToString() + ":H" + testPlanRowCounterIndex.ToString());
                    testPlanRowCounterIndex++;
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to write test plan items.");
                throw exception;
            }
        }

        private void EndTestPlan()
        {
            try
            {
                testPlanOpenXmlWriter.WriteEndElement();
                WriteTestPlanMergeCells();
                testPlanOpenXmlWriter.WriteEndElement();
                testPlanOpenXmlWriter.Dispose();
            }
            catch (Exception exception)
            {
                log.Error("Unable to finalize Test Plan report.");
                throw exception;
            }
        }

        private void WriteTestPlanMergeCells()
        {
            try
            {
                testPlanOpenXmlWriter.WriteStartElement(new MergeCells());
                foreach (string reference in testPlanMergeCellReferences)
                { testPlanOpenXmlWriter.WriteElement(new MergeCell() { Reference = reference }); }
                testPlanOpenXmlWriter.WriteEndElement();
            }
            catch (Exception exception)
            {
                log.Error("Unable to generate Test Plan MergeCells element.");
                throw exception;
            }
        }

        #endregion

        #region Handle Cell Data

        private void WriteCellValue(OpenXmlWriter openXmlWriter, string cellValue, int styleIndex)
        {
            try
            {
                List<OpenXmlAttribute> openXmlAttributes = new List<OpenXmlAttribute>();
                openXmlAttributes.Add(new OpenXmlAttribute("s", null, styleIndex.ToString()));
                int parseResult;
                if (int.TryParse(cellValue, out parseResult))
                {
                    openXmlWriter.WriteStartElement(new Cell(), openXmlAttributes);
                    openXmlWriter.WriteElement(new CellValue(cellValue));
                    openXmlWriter.WriteEndElement();
                }
                else
                {
                    openXmlAttributes.Add(new OpenXmlAttribute("t", null, "s"));
                    openXmlWriter.WriteStartElement(new Cell(), openXmlAttributes);
                    if (!sharedStringDictionary.ContainsKey(cellValue))
                    {
                        sharedStringDictionary.Add(cellValue, sharedStringMaxIndex);
                        sharedStringMaxIndex++;
                    }
                    openXmlWriter.WriteElement(new CellValue(sharedStringDictionary[cellValue].ToString()));
                    openXmlWriter.WriteEndElement();
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to write cell value to Excel report.");
                throw exception;
            }
        }

        private void CreateSharedStringPart(WorkbookPart workbookPart)
        {
            try
            {
                if (sharedStringMaxIndex > 0)
                {
                    SharedStringTablePart sharedStringTablePart = workbookPart.AddNewPart<SharedStringTablePart>();
                    using (OpenXmlWriter openXmlWriter = OpenXmlWriter.Create(sharedStringTablePart))
                    {
                        openXmlWriter.WriteStartElement(new SharedStringTable());
                        foreach (var item in sharedStringDictionary)
                        {
                            openXmlWriter.WriteStartElement(new SharedStringItem());
                            openXmlWriter.WriteElement(new Text(item.Key));
                            openXmlWriter.WriteEndElement();
                        }
                        openXmlWriter.WriteEndElement();
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to create SharedStringPart in Excel report.");
                throw exception;
            }
        }

        #endregion Handle Cell Data

        #region Data Preparation

        private bool FilterBySeverity(string impact, string rawRisk)
        {
            try
            {
                bool riskFactorMatch = true;
                bool stigSeverityMatch = true;
                bool riskFactorToStigSeverityCrossRef = true;
                if (!string.IsNullOrWhiteSpace(impact))
                {
                    switch (impact)
                    {
                        case "Critical":
                            { riskFactorMatch = IncludeCriticalFindings; riskFactorToStigSeverityCrossRef = IncludCatIFindings; break; }
                        case "High":
                            { riskFactorMatch = IncludeHighFindings; riskFactorToStigSeverityCrossRef = IncludCatIFindings; break; }
                        case "Medium":
                            { riskFactorMatch = IncludeMediumFindings; riskFactorToStigSeverityCrossRef = IncludCatIIFindings; break; }
                        case "Low":
                            { riskFactorMatch = IncludeLowFindings; riskFactorToStigSeverityCrossRef = IncludCatIIIFindings; break; }
                        case "Informational":
                            { riskFactorMatch = IncludeInformationalFindings; riskFactorToStigSeverityCrossRef = IncludCatIVFindings; break; }
                        default:
                            { break; }
                    }
                }
                if (!string.IsNullOrWhiteSpace(rawRisk))
                {
                    switch (rawRisk)
                    {
                        case "I":
                            { stigSeverityMatch = IncludCatIFindings; break; }
                        case "II":
                            { stigSeverityMatch = IncludCatIIFindings; break; }
                        case "III":
                            { stigSeverityMatch = IncludCatIIIFindings; break; }
                        case "IV":
                            { stigSeverityMatch = IncludCatIVFindings; break; }
                        default:
                            { break; }
                    }
                }
                if (!riskFactorMatch || !stigSeverityMatch || !riskFactorToStigSeverityCrossRef)
                { return false; }
                else
                { return true; }
            }
            catch (Exception exception)
            {
                log.Error("Unable to filter Excel report results by severity value.");
                throw exception;
            }
        }

        private bool FilterByStatus(string status)
        {
            try
            {
                bool severityMatch = true;
                switch (status)
                {
                    case "Ongoing":
                        { severityMatch = IncludeOngoingFindings; break; }
                    case "Completed":
                        { severityMatch = IncludeCompletedFindings; break; }
                    case "Not Reviewed":
                        { severityMatch = IncludeNotReviewedFindings; break; }
                    case "Not Applicable":
                        { severityMatch = IncludeNotApplicableFindings; break; }
                    case "Unknown":
                        { break; }
                    case "Undetermined":
                        { break; }
                    default:
                        { break; }
                }
                if (!severityMatch)
                { return false; }
                else
                { return true; }
            }
            catch (Exception exception)
            {
                log.Error("Unable to filter Excel report by status value.");
                throw exception;
            }
        }

        private string ConvertAcasSeverityToDisaCategory(string acasSeverity)
        {
            try
            {
                switch (acasSeverity)
                {
                    case "Critical":
                        { return "I"; }
                    case "High":
                        { return "I"; }
                    case "Medium":
                        { return "II"; }
                    case "Low":
                        { return "III"; }
                    case "Informational":
                        { return "IV"; }
                    default:
                        { return "Unknown"; }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to convert ACAS severity value to DISA category.");
                throw exception;
            }
        }

        private string ConvertAcasSeverityToRmfImpact(string acasSeverity)
        {
            switch (acasSeverity)
            {
                case "Critical":
                    { return "VH"; }
                case "High":
                    { return "H"; }
                case "Medium":
                    { return "M"; }
                case "Low":
                    { return "L"; }
                case "Informational":
                    { return "VL"; }
                default:
                    { return "Unknown"; }
            }
        }

        private string CompareIavmAgeToUserSettings(string iavmAge)
        {
            try
            {
                int iavmAgeAsInt = int.Parse(iavmAge);

                if (iavmAgeAsInt > IavmFilterFour)
                { return "> " + IavmFilterFour.ToString() + " Days"; }
                else if (iavmAgeAsInt > IavmFilterThree)
                { return "> " + IavmFilterThree.ToString() + " Days"; }
                else if (iavmAgeAsInt > IavmFilterTwo)
                { return "> " + IavmFilterTwo.ToString() + " Days"; }
                else if (iavmAgeAsInt > IavmFilterOne)
                { return "> " + IavmFilterOne.ToString() + " Days"; }
                else
                { return "< " + IavmFilterOne.ToString() + " Days"; }
            }
            catch (Exception exception)
            {
                log.Error("Unable to compare IAVM age to user settings.");
                throw exception;
            }
        }

        private string LargeCellValueHandler(string cellValue, string pluginId, string assetName, string columnName)
        {
            try
            {
                if (cellValue.Length < 32000)
                { return cellValue; }
                string regexPattern = "\\n((?![a-z])|(?=[udp])|(?=[tcp]))";
                Regex regex = new Regex(regexPattern);
                cellValue = regex.Replace(cellValue, "\r\n");
                if (assetName.Contains("\r\n"))
                { assetName = "MergedResults"; }
                assetName = assetName.Replace("\\", "-");
                assetName = assetName.Replace("/", "-");
                string outputPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop) + @"\Vulnerator - " + DateTime.Now.ToShortDateString().Replace('/', '-');
                string outputTextFile = string.Empty;
                outputTextFile = outputPath + @"\" + assetName + "_" + pluginId + "_" + "_" + columnName + ".txt";
                if (!Directory.Exists(outputPath))
                { Directory.CreateDirectory(outputPath); }
                if (!File.Exists(outputTextFile))
                {
                    using (FileStream fs = new FileStream(outputTextFile, FileMode.Append, FileAccess.Write))
                    using (StreamWriter sw = new StreamWriter(fs))
                    {
                        sw.WriteLine(cellValue);
                        sw.Close();
                    }
                }
                return "Output text exceeds the maximum character allowance for an Excel cell; " +
                    "please see \"" + outputTextFile + "\" for full output details.";
            }
            catch (Exception exception)
            {
                log.Error("Unable to handle large cell value.");
                throw exception;
            }
        }

        private List<DiscrepancyItem> ObtainDiscrepancyItemsForComparisson(string findingType)
        {
            try
            {
                List<DiscrepancyItem> itemList = new List<DiscrepancyItem>();
                using (SQLiteCommand sqliteCommand = FindingsDatabaseActions.sqliteConnection.CreateCommand())
                {
                    sqliteCommand.Parameters.Add(new SQLiteParameter("FindingType", findingType));
                    sqliteCommand.CommandText = "SELECT VulnId, VulnTitle, RuleId, Status, AssetIdToReport, FileName, Source, " +
                        "Comments, FindingDetails, GroupName FROM UniqueFinding NATURAL JOIN Vulnerability " +
                        "NATURAL JOIN FileNames NATURAL JOIN Assets NATURAL JOIN VulnerabilitySources " +
                        "NATURAL JOIN FindingTypes NATURAL JOIN FindingStatuses NATURAL JOIN Groups " +
                        "WHERE FindingType = @FindingType;";
                    using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
                    {
                        while (sqliteDataReader.Read())
                        {
                            DiscrepancyItem discrepancyItem = new DiscrepancyItem();
                            discrepancyItem.VulnId = sqliteDataReader["VulnId"].ToString();
                            discrepancyItem.VulnTitle = sqliteDataReader["VulnTitle"].ToString();
                            discrepancyItem.RuleId = sqliteDataReader["RuleId"].ToString();
                            discrepancyItem.Status = sqliteDataReader["Status"].ToString();
                            discrepancyItem.AssetId = sqliteDataReader["AssetIdToReport"].ToString();
                            discrepancyItem.FileName = sqliteDataReader["FileName"].ToString();
                            discrepancyItem.Source = sqliteDataReader["Source"].ToString();
                            discrepancyItem.Comments = sqliteDataReader["Comments"].ToString();
                            discrepancyItem.FindingDetails = sqliteDataReader["FindingDetails"].ToString();
                            discrepancyItem.Group = sqliteDataReader["GroupName"].ToString();
                            itemList.Add(discrepancyItem);
                        }
                    }
                }

                return itemList;
            }
            catch (Exception exception)
            {
                log.Error("Unable to obtain discrepancies for comparisson.");
                throw exception;
            }
        }

        #endregion Data Preparation

        #region Create Stylesheet

        private Stylesheet CreateStylesheet()
        {
            try
            {
                HorizontalAlignmentValues leftHorizontal = HorizontalAlignmentValues.Left;
                HorizontalAlignmentValues rightHorizontal = HorizontalAlignmentValues.Right;
                HorizontalAlignmentValues centerHorizontal = HorizontalAlignmentValues.Center;
                VerticalAlignmentValues topVertical = VerticalAlignmentValues.Top;
                VerticalAlignmentValues centerVertical = VerticalAlignmentValues.Center;

                return new Stylesheet(
                    new Fonts(
                    /*Index 0 - Black*/ CreateFont("000000", false),
                    /*Index 1 - Bold Black*/ CreateFont("000000", true),
                    /*Index 2 - Purple*/ CreateFont("660066", false),
                    /*Index 3 - Bold Purple*/ CreateFont("660066", true),
                    /*Index 4 - Red*/ CreateFont("990000", false),
                    /*Index 5 - Bold Red*/ CreateFont("990000", true),
                    /*Index 6 - Orange*/ CreateFont("FF6600", false),
                    /*Index 7 - Bold Orange*/ CreateFont("FF6600", true),
                    /*Index 8 - Blue*/ CreateFont("0066FF", false),
                    /*Index 9 - Bold Blue*/ CreateFont("0066FF", true),
                    /*Index 10 - Green*/ CreateFont("339900", false),
                    /*Index 11 - Bold Green*/ CreateFont("339900", true),
                    /*Index 12 - Bold Black Large*/ CreateFont("000000", true)
                        ),
                    new Fills(
                    /*Index 0 - Default Fill (None)*/ CreateFill(string.Empty, PatternValues.None),
                    /*Index 1 - Default Fill (Gray125)*/ CreateFill(string.Empty, PatternValues.Gray125),
                    /*Index 2 - Dark Gray Fill*/ CreateFill("BBBBBB", PatternValues.Solid),
                    /*Index 3 - Light Gray Fill*/ CreateFill("EEEEEE", PatternValues.Solid),
                    /*Index 4 - Yellow Gray Fill*/ CreateFill("FFCC00", PatternValues.Solid)
                        ),
                    new Borders(
                    /*Index 0 - Default Border (None)*/ CreateBorder(false, false, false, false),
                    /*Index 1 - All Borders*/ CreateBorder(true, true, true, true),
                    /*Index 2 - Top & Bottom Borders*/ CreateBorder(true, false, true, false)
                        ),
                    new CellFormats(
                    /*Index 0 - Black Font, No Fill, No Borders, Wrap Text*/ CreateCellFormat(0, 0, 0, leftHorizontal, null, true),
                    /*Index 1 - Black Font, No Fill, No Borders, Horizontally Centered*/ CreateCellFormat(0, 0, 0, centerHorizontal, null, false),
                    /*Index 2 - Bold Black Font, Dark Gray Fill, All Borders*/ CreateCellFormat(1, 2, 1, null, null, false),
                    /*Index 3 - Bold Black Font, Dark Gray Fill, Top & Bottom Borders, Centered*/ CreateCellFormat(1, 2, 2, centerHorizontal, centerVertical, false),
                    /*Index 4 - Bold Black Font, Dark Gray Fill, All Borders, Centered*/ CreateCellFormat(1, 2, 1, centerHorizontal, centerVertical, false),
                    /*Index 5 - Bold Purple Font, Light Gray Fill, Top & Bottom Borders, Centered*/ CreateCellFormat(3, 3, 2, centerHorizontal, centerVertical, false),
                    /*Index 6 - Bold Red Font, Light Gray Fill, Top & Bottom Borders, Centered*/ CreateCellFormat(5, 3, 2, centerHorizontal, centerVertical, false),
                    /*Index 7 - Bold Orange Font, Light Gray Fill, Top & Bottom Borders, Centered*/ CreateCellFormat(7, 3, 2, centerHorizontal, centerVertical, false),
                    /*Index 8 - Bold Blue Font, Light Gray Fill, Top & Bottom Borders, Centered*/ CreateCellFormat(9, 3, 2, centerHorizontal, centerVertical, false),
                    /*Index 9 - Bold Green Font, Light Gray Fill, Top & Bottom Borders, Centered*/ CreateCellFormat(11, 3, 2, centerHorizontal, centerVertical, false),
                    /*Index 10 - Purple Font, No Fill, Top & Bottom Borders, Centered*/ CreateCellFormat(2, 0, 2, centerHorizontal, centerVertical, false),
                    /*Index 11 - Red Font, No Fill, Top & Bottom Borders, Centered*/ CreateCellFormat(4, 0, 2, centerHorizontal, centerVertical, false),
                    /*Index 12 - Orange Font, No Fill, Top & Bottom Borders, Centered*/ CreateCellFormat(6, 0, 2, centerHorizontal, centerVertical, false),
                    /*Index 13 - Blue Font , No Fill, Top & Bottom Borders, Centered*/ CreateCellFormat(8, 0, 2, centerHorizontal, centerVertical, false),
                    /*Index 14 - Green Font, No Fill, Top & Bottom Borders, Centered*/ CreateCellFormat(10, 0, 2, centerHorizontal, centerVertical, false),
                    /*Index 15 - Bold Black Font, Yellow Fill, All Borders, Centered, Wrap Text*/ CreateCellFormat(1, 4, 1, centerHorizontal, centerVertical, true),
                    /*Index 16 - Bold Black Font, No Fill, All Borders, Wrap Text*/ CreateCellFormat(1, 0, 1, centerHorizontal, centerVertical, true),
                    /*Index 17 - Bold Black Font, Light Gray Fill, Top & Bottom Borders, Centered*/ CreateCellFormat(1, 3, 2, centerHorizontal, centerVertical, false),
                    /*Index 18 - Bold Black Font, No Fill, Top & Bottom Borders, Centered*/ CreateCellFormat(0, 0, 2, centerHorizontal, centerVertical, false),
                    /*Index 19 - Bold Black Font, Dark Gray Fill, Top & Bottom Borders, Centered Vertically*/ CreateCellFormat(1, 2, 1, null, centerVertical, false),
                    /*Index 20 - Black Font, No Fill, All Borders, Top Aligned, Wrap Text*/ CreateCellFormat(0, 0, 1, null, topVertical, true),
                    /*Index 21 - Black Font, No Fill, All Borders, Centered Vertically, Wrap Text*/ CreateCellFormat(0, 0, 1, null, centerVertical, true),
                    /*Index 22 - Black Font, No Fill, All Borders, Centered, Wrap Text*/ CreateCellFormat(0, 0, 1, centerHorizontal, centerVertical, true),
                    /*Index 23 - Black Font, No Fill, All Borders, Centered Vertically, Right Aligned*/ CreateCellFormat(0, 0, 1, rightHorizontal, centerVertical, false),
                    /*Index 24 - Black Font, No Fill, All Borders, Centered Horizontally, Top Aligned, Wrap Text*/ CreateCellFormat(0, 0, 1, centerHorizontal, topVertical, true),
                    /*Index 25 - Bold Black Font, No Fill, No Borders, Wrap Text*/ CreateCellFormat(1, 0, 0, leftHorizontal, topVertical, false),
                    /*Index 4 - Bold Black Font, Dark Gray Fill, All Borders, Centered, Wrap Text*/ CreateCellFormat(1, 2, 1, centerHorizontal, centerVertical, true)
                        )
                    );
            }
            catch (Exception exception)
            {
                log.Error("Unable to create Excel report Stylesheet.");
                throw exception;
            }
        }

        private Font CreateFont(string fontColor, bool isBold)
        {
            try
            {
                Font font = new Font();
                font.FontSize = new FontSize() { Val = 10 };
                font.Color = new Color { Rgb = new HexBinaryValue() { Value = fontColor } };
                font.FontName = new FontName() { Val = "Calibri" };
                if (isBold)
                { font.Bold = new Bold(); }
                return font;
            }
            catch (Exception exception)
            {
                log.Error("Unable to create Font.");
                throw exception;
            }
        }

        private Fill CreateFill(string fillColor, PatternValues patternValue)
        {
            try
            {
                Fill fill = new Fill();
                PatternFill patternfill = new PatternFill();
                patternfill.PatternType = patternValue;
                if (!string.IsNullOrWhiteSpace(fillColor))
                { patternfill.ForegroundColor = new ForegroundColor() { Rgb = new HexBinaryValue { Value = fillColor } }; }
                fill.PatternFill = patternfill;

                return fill;
            }
            catch (Exception exception)
            {
                log.Error("Unable to create Fill.");
                throw exception;
            }
        }

        private Border CreateBorder(bool topBorderRequired, bool rightBorderRequired, bool bottomBorderRequired, bool leftBorderRequired)
        {
            try
            {
                Border border = new Border();
                if (!topBorderRequired && !rightBorderRequired && !bottomBorderRequired && !leftBorderRequired)
                {
                    border.TopBorder = new TopBorder();
                    border.RightBorder = new RightBorder();
                    border.BottomBorder = new BottomBorder();
                    border.LeftBorder = new LeftBorder();
                    border.DiagonalBorder = new DiagonalBorder();
                }
                else
                {
                    if (topBorderRequired)
                    { border.TopBorder = new TopBorder(new Color() { Auto = true }) { Style = BorderStyleValues.Thin }; }
                    if (rightBorderRequired)
                    { border.RightBorder = new RightBorder(new Color() { Auto = true }) { Style = BorderStyleValues.Thin }; }
                    if (bottomBorderRequired)
                    { border.BottomBorder = new BottomBorder(new Color() { Auto = true }) { Style = BorderStyleValues.Thin }; }
                    if (leftBorderRequired)
                    { border.LeftBorder = new LeftBorder(new Color() { Auto = true }) { Style = BorderStyleValues.Thin }; }
                    border.DiagonalBorder = new DiagonalBorder();
                }
                return border;
            }
            catch (Exception exception)
            {
                log.Error("Unable to create Border.");
                throw exception;
            }
        }

        private CellFormat CreateCellFormat(UInt32Value fontId, UInt32Value fillId, UInt32Value borderId,
            HorizontalAlignmentValues? horizontalAlignment, VerticalAlignmentValues? verticalAlignment, bool wrapText)
        {
            try
            {
                CellFormat cellFormat = new CellFormat();
                Alignment alignment = new Alignment();
                if (horizontalAlignment != null)
                { alignment.Horizontal = horizontalAlignment; }
                if (verticalAlignment != null)
                { alignment.Vertical = verticalAlignment; }
                alignment.WrapText = wrapText;
                cellFormat.Alignment = alignment;
                cellFormat.FontId = fontId;
                cellFormat.FillId = fillId;
                cellFormat.BorderId = borderId;
                return cellFormat;
            }
            catch (Exception exception)
            {
                log.Error("Unable to create CellFormat.");
                throw exception;
            }
        }

        #endregion Create Stylesheet

        private string SetSqliteCommandText(bool isMerged, string findingType)
        {
            try
            {
                if (isMerged)
                {
                    if (findingType != "FPR")
                    {
                        return "SELECT FindingType, GroupName, VulnId, RuleId, VulnTitle, RawRisk, Impact, Description, IaControl, " +
                            "NistControl, Status, Source, Version, Release, Comments, FindingDetails, RiskStatement, CciNumber, " +
                            "GROUP_CONCAT(DISTINCT AssetIdToReport) AS AssetIdToReport FROM UniqueFinding " +
                            "NATURAL JOIN FindingTypes NATURAL JOIN VulnerabilitySources " +
                            "NATURAL JOIN FindingStatuses NATURAL JOIN Vulnerability NATURAL JOIN Groups " +
                            "NATURAL JOIN Assets WHERE FindingType = @FindingType GROUP BY RuleId, Status;";
                    }
                    else
                    {
                        return "SELECT FindingType, GroupName, VulnId, RuleId, VulnTitle, RawRisk, Impact, Description, IaControl, " +
                            "NistControl, Status, Source, Version, Release, Comments, FindingDetails, RiskStatement, CciNumber, " +
                            "GROUP_CONCAT(DISTINCT AssetIdToReport) AS AssetIdToReport FROM UniqueFinding " +
                            "NATURAL JOIN FindingTypes NATURAL JOIN VulnerabilitySources " +
                            "NATURAL JOIN FindingStatuses NATURAL JOIN Vulnerability NATURAL JOIN Groups " +
                            "NATURAL JOIN Assets WHERE FindingType = @FindingType GROUP BY VulnId, Status;";
                    }
                }
                else
                {
                    return "SELECT * FROM UniqueFinding NATURAL JOIN FindingTypes NATURAL JOIN FileNames " +
                        "NATURAL JOIN VulnerabilitySources NATURAL JOIN FindingStatuses NATURAL JOIN Assets " +
                        "NATURAL JOIN Vulnerability NATURAL JOIN Groups WHERE FindingType = @FindingType;";
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to set SQLite command text for Excel report.");
                throw exception;
            }
        }

        private string SetCredentialedString(string ipAddress)
        {
            try
            {
                string credentialedString = "No";
                using (SQLiteCommand sqliteCommand = FindingsDatabaseActions.sqliteConnection.CreateCommand())
                {
                    sqliteCommand.Parameters.Add(new SQLiteParameter("IpAddress", ipAddress));
                    sqliteCommand.CommandText = "SELECT Found21745, Found26917 FROM Assets WHERE IpAddress = @IpAddress;";
                    using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
                    {
                        while (sqliteDataReader.Read())
                        {
                            if (!string.IsNullOrWhiteSpace(sqliteDataReader[0].ToString()) && !credentialedString.Contains("21745"))
                            { credentialedString = credentialedString + "; 21745"; }
                            if (!string.IsNullOrWhiteSpace(sqliteDataReader[1].ToString()) && !credentialedString.Contains("26917"))
                            { credentialedString = credentialedString + "; 26917"; }
                        }
                    }
                }
                return credentialedString;
            }
            catch (Exception exception)
            {
                log.Error("Unable to set credentialed string for Excel report.");
                throw exception;
            }
        }

        private string ConvertDiacapToRmf(string diacapControls)
        {
            try
            {
                string nistControls = string.Empty;
                if (diacapControls.Contains(','))
                {
                    string[] diacapControlArray = diacapControls.Split(',').ToArray();

                    foreach (string control in diacapControlArray)
                    {
                        string value;
                        if (RevisionThreeSelected && DiacapToRmf.RevisionThree.TryGetValue(control, out value))
                        { nistControls = nistControls + value + Environment.NewLine; }
                        else if (DiacapToRmf.RevisionFour.TryGetValue(control, out value))
                        { nistControls = nistControls + value + Environment.NewLine; }
                    }
                }
                else
                {
                    string value;
                    if (RevisionThreeSelected && DiacapToRmf.RevisionThree.TryGetValue(diacapControls, out value))
                    { nistControls = nistControls + value + Environment.NewLine; }
                    else if (DiacapToRmf.RevisionFour.TryGetValue(diacapControls, out value))
                    { nistControls = nistControls + value + Environment.NewLine; }
                }
                return nistControls;
            }
            catch (Exception exception)
            {
                log.Error("Unable to convert DIACAP control(s) " + diacapControls + " to NIST control(s).");
                throw exception;
            }
        }

        private void AddIavmsToObservableCollection(AsyncObservableCollection<Iavm> iavmList, DataRow acasFindingRow)
        {
            try
            {
                if (!string.IsNullOrWhiteSpace(acasFindingRow["IavmNumber"].ToString()))
                {
                    iavmList.Add(new Iavm(false, acasFindingRow["IavmNumber"].ToString(), acasFindingRow["VulnId"].ToString(), acasFindingRow["VulnTitle"].ToString(),
                        acasFindingRow["HostName"].ToString(), CompareIavmAgeToUserSettings(acasFindingRow["Age"].ToString()), acasFindingRow["SystemName"].ToString()));
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to add IAVM to ObservableCollection.");
                throw exception;
            }
        }
    }
}
