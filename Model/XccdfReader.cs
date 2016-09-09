using log4net;
using System;
using System.Collections.ObjectModel;
using System.Data;
using System.Data.SQLite;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using Vulnerator.ViewModel;

namespace Vulnerator.Model
{
    /// <summary>
    /// Class to read XCCDF files.  Designed to read files regardless
    /// of whether they are pulled from SCC, HBSS Policy Auditor, or
    /// ACAS.
    /// </summary>
    public class XccdfReader
    {
        private static DataTable joinedCciDatatable = CreateCciDataTable();
        private string fileNameWithoutPath = string.Empty;
        private string xccdfTitle = string.Empty;
        private string versionInfo = string.Empty;
        private string releaseInfo = string.Empty;
        private string acasXccdfHostName = string.Empty;
        private string acasXccdfHostIp = string.Empty;
        private bool UserPrefersHostName { get { return bool.Parse(ConfigAlter.ReadSettingsFromDictionary("rbHostIdentifier")); } }
        private static readonly ILog log = LogManager.GetLogger(typeof(Logger));

        public string ReadXccdfFile(string fileName, ObservableCollection<MitigationItem> mitigationsList, string systemName)
        {
            try
            {
                if (fileName.IsFileInUse())
                {
                    log.Error(fileName + " is in use; please close any open instances and try again.");
                    return "Failed; File In Use";
                }

                ParseXccdfWithXmlReader(fileName, mitigationsList, systemName);
                return "Processed";
            }
            catch (Exception exception)
            {
                log.Error("Unable to process XCCDF file.");
                log.Debug("Exception details:", exception);
                return "Failed; See Log";
            }
        }

        private void ParseXccdfWithXmlReader(string fileName, ObservableCollection<MitigationItem> mitigationsList, string systemName)
        {
            try
            {
                XmlReaderSettings xmlReaderSettings = new XmlReaderSettings();
                xmlReaderSettings.IgnoreWhitespace = true;
                xmlReaderSettings.IgnoreComments = true;
                xmlReaderSettings.ValidationType = ValidationType.Schema;
                xmlReaderSettings.ValidationFlags = System.Xml.Schema.XmlSchemaValidationFlags.ProcessInlineSchema;
                xmlReaderSettings.ValidationFlags = System.Xml.Schema.XmlSchemaValidationFlags.ProcessSchemaLocation;
                fileNameWithoutPath = Path.GetFileName(fileName);

                using (SQLiteTransaction sqliteTransaction = FindingsDatabaseActions.sqliteConnection.BeginTransaction())
                {
                    using (SQLiteCommand sqliteCommand = FindingsDatabaseActions.sqliteConnection.CreateCommand())
                    {
                        sqliteCommand.Parameters.Add(new SQLiteParameter("GroupName", systemName));
                        sqliteCommand.CommandText = SetSqliteCommandText("Groups");
                        sqliteCommand.ExecuteNonQuery();
                        sqliteCommand.Parameters.Add(new SQLiteParameter("FindingType", "XCCDF"));
                        sqliteCommand.Parameters.Add(new SQLiteParameter("FileName", fileNameWithoutPath));
                        sqliteCommand.CommandText = SetSqliteCommandText("FileNames");
                        sqliteCommand.ExecuteNonQuery();
                        using (XmlReader xmlReader = XmlReader.Create(fileName, xmlReaderSettings))
                        {
                            while (xmlReader.Read())
                            {
                                if (xmlReader.IsStartElement())
                                {
                                    switch (xmlReader.Prefix)
                                    {
                                        case "cdf":
                                            {
                                                ParseXccdfFromScc(xmlReader, systemName, sqliteCommand);
                                                break;
                                            }
                                        case "xccdf":
                                            {
                                                ParseXccdfFromAcas(xmlReader, sqliteCommand);
                                                break;
                                            }
                                        case "":
                                            {
                                                ParseXccdfFromScc(xmlReader, systemName, sqliteCommand);
                                                break;
                                            }
                                        default:
                                            { break; }
                                    }
                                }
                            }
                        }
                    }
                    sqliteTransaction.Commit();
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to parse XCCDF using XML reader.");
                throw exception;
            }
        }

        #region Parse XCCDF File From SCC

        private void ParseXccdfFromScc(XmlReader xmlReader, string systemName, SQLiteCommand sqliteCommand)
        {
            try
            {
                while (xmlReader.Read())
                {
                    if (xmlReader.IsStartElement())
                    {
                        switch (xmlReader.Name)
                        {
                            case "cdf:title":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Source", GetSccXccdfTitle(xmlReader)));
                                    break;
                                }
                            case "cdf:plain-text":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Release", GetSccXccdfRelease(xmlReader)));
                                    break;
                                }
                            case "cdf:version":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Version", GetSccXccdfVersion(xmlReader)));
                                    sqliteCommand.CommandText = SetSqliteCommandText("VulnerabilitySources");
                                    sqliteCommand.ExecuteNonQuery();
                                    break;
                                }
                            case "cdf:Group":
                                {
                                    GetSccXccdfVulnerabilityInformation(xmlReader, sqliteCommand, systemName);
                                    InsertVulnerabilityCommand(sqliteCommand);
                                    if (sqliteCommand.Parameters.Contains("NistControl"))
                                    { sqliteCommand.Parameters.Remove(sqliteCommand.Parameters["NistControl"]); }
                                    if (sqliteCommand.Parameters.Contains("IaControls"))
                                    { sqliteCommand.Parameters.Remove(sqliteCommand.Parameters["IaControls"]); }
                                    break;
                                }
                            case "cdf:TestResult":
                                {
                                    ParseSccXccdfTestResult(xmlReader, sqliteCommand);
                                    break;
                                }
                            default:
                                { break; }
                        }
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to parse SCC XCCDF.");
                throw exception;
            }
        }

        private string GetSccXccdfTitle(XmlReader xmlReader)
        {
            try
            {
                xmlReader.Read();
                xccdfTitle = xmlReader.Value + " Benchmark";
                return xccdfTitle;
            }
            catch (Exception exception)
            {
                log.Error("Unable to get XCCDF title.");
                throw exception;
            }
        }
        
        private string GetSccXccdfRelease(XmlReader xmlReader)
        {
            try
            {
                if (!string.IsNullOrWhiteSpace(xmlReader.GetAttribute("id")) && xmlReader.GetAttribute("id").Equals("release-info"))
                {
                    xmlReader.Read();
                    releaseInfo = xmlReader.Value.Split(' ')[1].Split(' ')[0];
                }
                return releaseInfo;
            }
            catch (Exception exception)
            {
                log.Error("Unable to get XCCDF release.");
                throw exception;
            }
        }

        private string GetSccXccdfVersion(XmlReader xmlReader)
        {
            try
            {
                xmlReader.Read();
                versionInfo = xmlReader.Value;
                return versionInfo;
            }
            catch (Exception exception)
            {
                log.Error("Unable to get XCCDF version.");
                throw exception;
            }
        }

        private void GetSccXccdfVulnerabilityInformation(XmlReader xmlReader, SQLiteCommand sqliteCommand, string systemName)
        {
            try
            {
                sqliteCommand.Parameters.Add(new SQLiteParameter("VulnId", xmlReader.GetAttribute("id")));

                while (xmlReader.Read())
                {
                    if (xmlReader.IsStartElement() && xmlReader.Name.Equals("cdf:Rule"))
                    {
                        sqliteCommand.Parameters.Add(new SQLiteParameter("RuleId", xmlReader.GetAttribute("id")));
                        sqliteCommand.Parameters.Add(new SQLiteParameter("RawRisk",
                            ConvertSeverityToRawRisk(xmlReader.GetAttribute("severity"))));
                        sqliteCommand.Parameters.Add(new SQLiteParameter("Impact",
                            ConvertSeverityToImpact(xmlReader.GetAttribute("severity"))));

                        while (xmlReader.Read())
                        {
                            if (xmlReader.IsStartElement())
                            {
                                switch (xmlReader.Name)
                                {
                                    case "cdf:title":
                                        {
                                            xmlReader.Read();
                                            sqliteCommand.Parameters.Add(new SQLiteParameter("VulnTitle", xmlReader.Value));
                                            break;
                                        }
                                    case "cdf:description":
                                        {
                                            xmlReader.Read();
                                            GetDescriptionAndIacFromSccFile(xmlReader.Value, sqliteCommand);
                                            break;
                                        }
                                    case "cdf:ident":
                                        {
                                            if (xmlReader.GetAttribute("system").Equals(@"http://iase.disa.mil/cci"))
                                            {
                                                xmlReader.Read();
                                                string cciRef = xmlReader.Value;
                                                string cciValue = string.Empty;
                                                if (!string.IsNullOrWhiteSpace(cciRef))
                                                {
                                                    foreach (DataRow cciControlDataRow in joinedCciDatatable.AsEnumerable().Where(x => x["CciRef"].Equals(cciRef)))
                                                    { cciValue = cciValue + cciControlDataRow["CciControl"].ToString() + Environment.NewLine; }
                                                    sqliteCommand.Parameters.Add(new SQLiteParameter("NistControl", cciValue));
                                                }
                                            }
                                            break;
                                        }
                                    case "cdf:fixtext":
                                        {
                                            xmlReader.Read();
                                            sqliteCommand.Parameters.Add(new SQLiteParameter("FixText", xmlReader.Value.Replace("&gt;", ">")));
                                            break;
                                        }
                                    default:
                                        { break; }
                                }
                            }
                            else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("cdf:Rule"))
                            { return; }
                        }
                    }

                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to get XCCDF vulnerability information.");
                throw exception;
            }
        }

        private void ParseSccXccdfTestResult(XmlReader xmlReader, SQLiteCommand sqliteCommand)
        {
            try
            {
                while (xmlReader.Read())
                {
                    if (xmlReader.IsStartElement())
                    {
                        switch (xmlReader.Name)
                        {
                            case "cdf:target-facts":
                                {
                                    SetAffectedAssetInformationFromSccFile(xmlReader, sqliteCommand);
                                    InsertAssetCommand(sqliteCommand);
                                    break;
                                }
                            case "cdf:rule-result":
                                {
                                    SetXccdfScanResultFromSccFile(xmlReader, sqliteCommand);
                                    sqliteCommand.CommandText = SetSqliteCommandText("UniqueFinding");
                                    sqliteCommand.ExecuteNonQuery();
                                    break;
                                }
                            case "cdf:score":
                                {
                                    SetXccdfScoreFromSccFile(xmlReader, sqliteCommand);
                                    sqliteCommand.CommandText = SetSqliteCommandText("ScapScores");
                                    sqliteCommand.ExecuteNonQuery();
                                    break;
                                }
                            default:
                                { break; }
                        }
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to parse XCCDF test results.");
                throw exception;
            }
        }

        private void SetAffectedAssetInformationFromSccFile(XmlReader xmlReader, SQLiteCommand sqliteCommand)
        {
            try
            {
                while (xmlReader.Read())
                {
                    if (xmlReader.IsStartElement() && xmlReader.Name.Equals("cdf:fact"))
                    {
                        switch (xmlReader.GetAttribute("name"))
                        {
                            case "urn:scap:fact:asset:identifier:host_name":
                                {
                                    xmlReader.Read();
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("HostName", xmlReader.Value));
                                    break;
                                }
                            case "urn:scap:fact:asset:identifier:ipv4":
                                {
                                    xmlReader.Read();
                                    if (!sqliteCommand.Parameters.Contains("IpAddress"))
                                    { sqliteCommand.Parameters.Add(new SQLiteParameter("IpAddress", xmlReader.Value)); }
                                    else
                                    { sqliteCommand.Parameters["IpAddress"].Value += @"/" + xmlReader.Value; }
                                    break;
                                }
                            default:
                                { break; }
                        }
                    }
                    else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("cdf:target-facts"))
                    {
                        if (sqliteCommand.Parameters.Contains("HostName") && UserPrefersHostName)
                        {
                            sqliteCommand.Parameters.Add(new SQLiteParameter(
                                "AssetIdToReport", sqliteCommand.Parameters["HostName"].Value));
                        }
                        else
                        {
                            sqliteCommand.Parameters.Add(new SQLiteParameter(
                                "AssetIdToReport", sqliteCommand.Parameters["IpAddress"].Value));
                        }
                        return;
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to set affected asset information.");
                throw exception;
            }
        }

        private void SetXccdfScanResultFromSccFile(XmlReader xmlReader, SQLiteCommand sqliteCommand)
        {
            try
            {
                if (sqliteCommand.Parameters.Contains("RuleId"))
                { sqliteCommand.Parameters["RuleId"].Value = xmlReader.GetAttribute("idref"); }
                else
                { sqliteCommand.Parameters.Add(new SQLiteParameter("RuleId", xmlReader.GetAttribute("idref"))); }
                while (xmlReader.Read())
                {
                    if (xmlReader.IsStartElement() && xmlReader.Name.Equals("cdf:result"))
                    {
                        xmlReader.Read();
                        sqliteCommand.Parameters.Add(new SQLiteParameter("Status", ConvertXccdfResultToStatus(xmlReader.Value)));
                        break;
                    }
                    else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("cdf:rule-result"))
                    { return; }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to set XCCDF scan result.");
                throw exception;
            }
        }
        
        private void SetXccdfScoreFromSccFile(XmlReader xmlReader, SQLiteCommand sqliteCommand)
        {
            if (!string.IsNullOrWhiteSpace(xmlReader.GetAttribute("system")) && xmlReader.GetAttribute("system").Equals("urn:xccdf:scoring:default"))
            {
                xmlReader.Read();
                sqliteCommand.Parameters.Add(new SQLiteParameter("ScapScore", xmlReader.Value));
            }
        }

        private void GetDescriptionAndIacFromSccFile(string description, SQLiteCommand sqliteCommand)
        {
            try
            {
                description.Replace("&lt;", "<");
                description.Replace("&gt;", ">");
                description = description.Insert(0, "<root>");
                description = description.Insert(description.Length, "</root>");
                if (description.Contains(@"<link>"))
                { description = description.Replace(@"<link>", "\"link\""); }
                if (description.Contains(@"<link"))
                {
                    int falseStartElementIndex = description.IndexOf("<link");
                    int falseEndElementIndex = description.IndexOf(">", falseStartElementIndex);
                    StringBuilder stringBuilder = new StringBuilder(description);
                    stringBuilder[falseEndElementIndex] = '\"';
                    description = stringBuilder.ToString();
                    description = description.Replace(@"<link", "\"link");
                }
                XmlReaderSettings xmlReaderSettings = new XmlReaderSettings();
                xmlReaderSettings.IgnoreWhitespace = true;
                xmlReaderSettings.IgnoreComments = true;

                using (Stream stream = GenerateStreamFromString(description))
                {
                    using (XmlReader descriptionXmlReader = XmlReader.Create(stream, xmlReaderSettings))
                    {
                        while (descriptionXmlReader.Read())
                        {
                            if (descriptionXmlReader.IsStartElement() && descriptionXmlReader.Name.Equals("VulnDiscussion"))
                            {
                                descriptionXmlReader.Read();
                                sqliteCommand.Parameters.Add(new SQLiteParameter("Description", descriptionXmlReader.Value));
                            }
                            else if (descriptionXmlReader.IsStartElement() && descriptionXmlReader.Name.Equals("IaControl"))
                            {
                                descriptionXmlReader.Read();
                                if (descriptionXmlReader.NodeType == XmlNodeType.Text)
                                { sqliteCommand.Parameters.Add(new SQLiteParameter("IaControl", descriptionXmlReader.Value)); }
                            }
                        }
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to retrieve description and/or IAC.");
                throw exception;
            }
        }

        #endregion

        #region Parse XCCDF File From ACAS

        private void ParseXccdfFromAcas(XmlReader xmlReader, SQLiteCommand sqliteCommand)
        {
            try
            {
                while (xmlReader.Read())
                {
                    if (xmlReader.IsStartElement())
                    {
                        switch (xmlReader.Name)
                        {
                            case "xccdf:benchmark":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Source", GetAcasXccdfTitle(xmlReader)));
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Version", versionInfo));
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Release", releaseInfo));
                                    sqliteCommand.CommandText = SetSqliteCommandText("VulnerabilitySources");
                                    sqliteCommand.ExecuteNonQuery();
                                    break;
                                }
                            case "xccdf:target-facts":
                                {
                                    GetAcasXccdfTargetInfo(xmlReader, sqliteCommand);
                                    if (sqliteCommand.Parameters.Contains("HostName") && UserPrefersHostName)
                                    {
                                        sqliteCommand.Parameters.Add(new SQLiteParameter(
                                          "AssetIdToReport", sqliteCommand.Parameters["HostName"].Value));
                                    }
                                    else
                                    {
                                        sqliteCommand.Parameters.Add(new SQLiteParameter(
                                          "AssetIdToReport", sqliteCommand.Parameters["IpAddress"].Value));
                                    }
                                    sqliteCommand.CommandText = SetSqliteCommandText("Assets");
                                    InsertAssetCommand(sqliteCommand);
                                    break;
                                }
                            case "xccdf:rule-result":
                                {
                                    ParseAcasXccdfTestResult(xmlReader, sqliteCommand);
                                    sqliteCommand.CommandText = SetSqliteCommandText("Vulnerability");
                                    InsertVulnerabilityCommand(sqliteCommand);
                                    sqliteCommand.CommandText = SetSqliteCommandText("UniqueFinding");
                                    sqliteCommand.ExecuteNonQuery();
                                    break;
                                }
                            case "xccdf:score":
                                {
                                    xmlReader.Read();
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("ScapScore", xmlReader.Value));
                                    sqliteCommand.CommandText = SetSqliteCommandText("ScapScores");
                                    sqliteCommand.ExecuteNonQuery();
                                    break;
                                }
                            default:
                                { break; }
                        }
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to parse ACAS XCCDF.");
                throw exception;
            }
        }

        private string GetAcasXccdfTitle(XmlReader xmlReader)
        {
            try
            {
                xccdfTitle = xmlReader.GetAttribute("href");
                xccdfTitle = xccdfTitle.Split(new string[] { "_SCAP" }, StringSplitOptions.None)[0].Replace('_', ' ');
                if (Regex.IsMatch(xccdfTitle, @"\bU \b"))
                { xccdfTitle = Regex.Replace(xccdfTitle, @"\bU \b", ""); }
                Match match = Regex.Match(xccdfTitle, @"V\dR\d{1,10}");
                if (match.Success)
                {
                    versionInfo = match.Value.Split('R')[0].Replace("V", "");
                    releaseInfo = match.Value.Split('R')[1];
                }
                xccdfTitle = xccdfTitle.Replace(match.Value + " ", "") + " Benchmark";
                return xccdfTitle;
            }
            catch (Exception exception)
            {
                log.Error("Unable to obtain XCCDF title.");
                throw exception;
            }
        }

        private void GetAcasXccdfTargetInfo(XmlReader xmlReader, SQLiteCommand sqliteCommand)
        {
            try
            {
                while (xmlReader.Read())
                {
                    if (xmlReader.IsStartElement())
                    {
                        switch (xmlReader.GetAttribute("name"))
                        {
                            case "urn:xccdf:fact:asset:identifier:host_name":
                                {
                                    xmlReader.Read();
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("HostName", xmlReader.Value));
                                    break;
                                }
                            case "urn:xccdf:fact:asset:identifier:ipv4":
                                {
                                    xmlReader.Read();
                                    if (!sqliteCommand.Parameters.Contains("IpAddress"))
                                    { sqliteCommand.Parameters.Add(new SQLiteParameter("IpAddress", xmlReader.Value)); }
                                    else
                                    { sqliteCommand.Parameters["IpAddress"].Value += @"/" + xmlReader.Value; }
                                    break;
                                }
                            default:
                                { break; }
                        }
                    }
                    else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("xccdf:target-facts"))
                    { return; }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to obtain XCCDF target information.");
                throw exception;
            }
        }

        private void ParseAcasXccdfTestResult(XmlReader xmlReader, SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.Parameters.Add(new SQLiteParameter(
                    "VulnId", xmlReader.GetAttribute("idref").Replace("_rule", "")));
                sqliteCommand.Parameters.Add(new SQLiteParameter(
                    "RuleId", xmlReader.GetAttribute("idref").Replace("_rule", "")));
                sqliteCommand.Parameters.Add(new SQLiteParameter(
                    "RawRisk", ConvertSeverityToRawRisk(xmlReader.GetAttribute("severity"))));
                sqliteCommand.Parameters.Add(new SQLiteParameter(
                    "Impact", ConvertSeverityToImpact(xmlReader.GetAttribute("severity"))));
                sqliteCommand.Parameters.Add(new SQLiteParameter(
                    "Description", "XCCDF Result was generated via ACAS; description is not available."));
                sqliteCommand.Parameters.Add(new SQLiteParameter(
                    "VulnTitle", "XCCDF Result was generated via ACAS; title is not available."));

                while (xmlReader.Read())
                {
                    if (xmlReader.IsStartElement())
                    {
                        switch (xmlReader.Name)
                        {
                            case "xccdf:result":
                                {
                                    xmlReader.Read();
                                    sqliteCommand.Parameters.Add(new SQLiteParameter(
                                        "Status", ConvertXccdfResultToStatus(xmlReader.Value)));
                                    break;
                                }
                            case "xccdf:ident":
                                {
                                    if (xmlReader.GetAttribute("system").Equals(@"http://iase.disa.mil/cci"))
                                    {
                                        xmlReader.Read();
                                        string cciRef = xmlReader.Value;
                                        if (!string.IsNullOrWhiteSpace(cciRef))
                                        {
                                            foreach (DataRow cciControlDataRow in joinedCciDatatable.AsEnumerable().Where(x => x["CciRef"].Equals(cciRef)))
                                            {
                                                if (!sqliteCommand.Parameters.Contains("NistControl"))
                                                {
                                                    sqliteCommand.Parameters.Add(new SQLiteParameter(
                                                      "NistControl", cciControlDataRow["CciControl"].ToString()));
                                                }
                                                else
                                                {
                                                    sqliteCommand.Parameters["NistControl"].Value =
                                                        sqliteCommand.Parameters["NistControl"].Value + Environment.NewLine +
                                                        cciControlDataRow["CciControl"].ToString();
                                                }
                                            }
                                        }
                                    }
                                    break;
                                }
                            default:
                                { break; }
                        }
                    }
                    else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("xccdf:rule-result"))
                    { return; }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to parse XCCDF test results.");
                throw exception;
            }
        }

        #endregion

        #region Parse XCCDF File From OpenSCAP

        //TODO: Add this functionality

        #endregion

        #region Data Manipulation Functions

        private string ConvertSeverityToRawRisk(string severity)
        {
            try
            {
                switch (severity)
                {
                    case "high":
                        { return "I"; }
                    case "medium":
                        { return "II"; }
                    case "low":
                        { return "III"; }
                    case "unknown":
                        { return "Unknown"; }
                    default:
                        { return "Unknown"; }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to convert severity to raw risk.");
                throw exception;
            }
        }

        private string ConvertSeverityToImpact(string severity)
        {
            try
            {
                switch (severity)
                {
                    case "high":
                        { return "High"; }
                    case "medium":
                        { return "Medium"; }
                    case "low":
                        { return "Low"; }
                    case "unknown":
                        { return "Unknown"; }
                    default:
                        { return "Unknown"; }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to convert severity to impact.");
                throw exception;
            }
        } 

        private string ConvertXccdfResultToStatus(string xccdfResult)
        {
            try
            {
                if (xccdfResult.Equals("pass"))
                { return "Completed"; }
                else
                { return "Ongoing"; }
            }
            catch (Exception exception)
            {
                log.Error("Unable to convert XCCDF test result to status.");
                throw exception;
            }
        }

        #endregion

        private Stream GenerateStreamFromString(string streamString)
        {
            try
            {
                MemoryStream memoryStream = new MemoryStream();
                StreamWriter streamWriter = new StreamWriter(memoryStream);
                streamWriter.Write(streamString);
                streamWriter.Flush();
                memoryStream.Position = 0;
                return memoryStream;
            }
            catch (Exception exception)
            {
                log.Error("Unable to generate a Stream from the provided string.");
                throw exception;
            }
        }

        private static DataTable CreateCciDataTable()
        {
            try
            {
                DataTable cciItemDataTable = MainWindowViewModel.cciDs.Tables["cci_item"];
                DataTable referencesDataTable = MainWindowViewModel.cciDs.Tables["references"];
                DataTable referenceDataTable = MainWindowViewModel.cciDs.Tables["reference"];

                joinedCciDatatable = new DataTable();
                joinedCciDatatable.Columns.Add("CciRef", typeof(string));
                joinedCciDatatable.Columns.Add("CciControl", typeof(string));

                var query =
                    from cciItem in cciItemDataTable.AsEnumerable()
                    join references in referencesDataTable.AsEnumerable()
                    on cciItem["cci_item_id"] equals references["cci_item_id"]
                    join reference in referenceDataTable.AsEnumerable()
                    on references["references_id"] equals reference["references_id"]
                    select cciItem.ItemArray.Concat(reference.ItemArray).ToArray();

                foreach (object[] values in query)
                {
                    DataRow cciRow = joinedCciDatatable.NewRow();
                    cciRow["CciRef"] = values[7].ToString();
                    cciRow["CciControl"] = values[13].ToString();
                    joinedCciDatatable.Rows.Add(cciRow);
                }
                return joinedCciDatatable;
            }
            catch (Exception exception)
            {
                log.Error("Unable to generate CCI DataTable.");
                throw exception;
            }
        }

        private string SetSqliteCommandText(string tableName)
        {
            try
            {
                switch (tableName)
                {
                    case "Groups":
                        { return "INSERT INTO Groups VALUES (NULL, @GroupName);"; }
                    case "VulnerabilitySources":
                        { return "INSERT INTO VulnerabilitySources VALUES (NULL, @Source, @Version, @Release);"; }
                    case "Assets":
                        { return "INSERT INTO Assets (AssetIdToReport, GroupIndex) VALUES (@AssetIdToReport, " +
                                "(SELECT GroupIndex FROM Groups WHERE GroupName = @GroupName));"; }
                    case "FileNames":
                        { return "INSERT INTO FileNames VALUES (NULL, @FileName);"; }
                    case "ScapScores":
                        {
                            return "INSERT INTO ScapScores VALUES (@ScapScore, " +
                                "(SELECT AssetIndex FROM Assets WHERE AssetIdToReport = @AssetIdToReport), " +
                                "(SELECT SourceIndex FROM VulnerabilitySources WHERE Source = @Source));";
                        }
                    case "Vulnerability":
                        {
                            return "INSERT INTO Vulnerability (VulnId, VulnTitle, Description, RawRisk, " +
                                "Impact, RuleId) VALUES (@VulnId, @VulnTitle, @Description, @RawRisk, @Impact, @RuleId);";
                        }
                    case "UniqueFinding":
                        {
                            return "INSERT INTO UniqueFinding (FindingTypeIndex, SourceIndex, StatusIndex, " +
                                "FileNameIndex, VulnerabilityIndex, AssetIndex) VALUES (" +
                                "(SELECT FindingTypeIndex FROM FindingTypes WHERE FindingType = @FindingType), " +
                                "(SELECT SourceIndex FROM VulnerabilitySources WHERE Source = @Source), " +
                                "(SELECT StatusIndex FROM FindingStatuses WHERE Status = @Status), " +
                                "(SELECT FileNameIndex FROM FileNames WHERE FileName = @FileName), " +
                                "(SELECT VulnerabilityIndex FROM Vulnerability WHERE RuleId = @RuleId), " +
                                "(SELECT AssetIndex FROM Assets WHERE AssetIdToReport = @AssetIdToReport));";
                        }
                    default:
                        { break; }
                }
                return "";
            }
            catch (Exception exception)
            {
                log.Error("Unable to set SQLite command text.");
                throw exception;
            }
        }

        private void InsertVulnerabilityCommand(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = SetSqliteCommandText("Vulnerability");
                foreach (SQLiteParameter parameter in sqliteCommand.Parameters)
                {
                    if (parameter.ParameterName.Equals("NistControl"))
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(92, "@NistControl, "); }
                    if (parameter.ParameterName.Equals("IaControls"))
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(92, "@IaControl, "); }
                }
                foreach (SQLiteParameter parameter in sqliteCommand.Parameters)
                {
                    if (parameter.ParameterName.Equals("NistControl"))
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(27, "NistControl, "); }
                    if (parameter.ParameterName.Equals("IaControls"))
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(27, "IaControl, "); }
                }
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                log.Error("Unable to set command to insert vulnerability.");
                throw exception;
            }
        }

        private void InsertAssetCommand(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = SetSqliteCommandText("Assets");
                foreach (SQLiteParameter parameter in sqliteCommand.Parameters)
                {
                    if (parameter.ParameterName.Equals("HostName"))
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(57, "@HostName, "); }
                    if (parameter.ParameterName.Equals("IpAddress"))
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(57, "@IpAddress, "); }
                }
                foreach (SQLiteParameter parameter in sqliteCommand.Parameters)
                {
                    if (parameter.ParameterName.Equals("HostName"))
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(20, "HostName, "); }
                    if (parameter.ParameterName.Equals("IpAddress"))
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(20, "IpAddress, "); }
                }
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                log.Error("Unable to set command to insert asset.");
                throw exception;
            }
        }
    }
}
