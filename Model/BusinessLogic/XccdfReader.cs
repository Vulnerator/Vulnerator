using log4net;
using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SQLite;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Schema;
using Vulnerator.Model.DataAccess;
using Vulnerator.Model.ModelHelper;
using Vulnerator.Model.Object;
using Vulnerator.ViewModel;

namespace Vulnerator.Model.BusinessLogic
{
    /// <summary>
    /// Class to read XCCDF files.  Designed to read files regardless
    /// of whether they are pulled from SCC, HBSS Policy Auditor, or
    /// ACAS.
    /// </summary>
    public class XccdfReader
    {
        private Assembly assembly = Assembly.GetExecutingAssembly();
        DatabaseInterface databaseInterface = new DatabaseInterface();
        private string fileNameWithoutPath = string.Empty;
        private string xccdfTitle = string.Empty;
        private string versionInfo = string.Empty;
        private string releaseInfo = string.Empty;
        private string acasXccdfHostName = string.Empty;
        private string acasXccdfHostIp = string.Empty;
        private string firstDiscovered = DateTime.Now.ToShortDateString();
        private string lastObserved = DateTime.Now.ToShortDateString();
        private bool incorrectFileType = false;
        private List<string> ccis = new List<string>();
        private List<string> ips = new List<string>();
        private List<string> macs = new List<string>();
        private List<string> responsibilities = new List<string>();
        private List<string> iaControls = new List<string>();
        private static readonly ILog log = LogManager.GetLogger(typeof(Logger));

        public string ReadXccdfFile(Object.File file)
        {
            try
            {
                if (file.FileName.IsFileInUse())
                {
                    log.Error(file.FileName + " is in use; please close any open instances and try again.");
                    return "Failed; File In Use";
                }

                ParseXccdfWithXmlReader(file);
                if (!incorrectFileType)
                { return "Processed"; }
                else
                { return "Report Type (OVAL) Not Supported"; }
            }
            catch (Exception exception)
            {
                log.Error("Unable to process XCCDF file.");
                log.Debug("Exception details:", exception);
                return "Failed; See Log";
            }
        }

        private void ParseXccdfWithXmlReader(Object.File file)
        {
            try
            {
                XmlReaderSettings xmlReaderSettings = GenerateXmlReaderSettings();
                fileNameWithoutPath = Path.GetFileName(file.FileName);
                if (DatabaseBuilder.sqliteConnection.State.ToString().Equals("Closed"))
                { DatabaseBuilder.sqliteConnection.Open(); }
                using (SQLiteTransaction sqliteTransaction = DatabaseBuilder.sqliteConnection.BeginTransaction())
                {
                    using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                    {
                        InsertParameterPlaceholders(sqliteCommand);
                        sqliteCommand.Parameters.Add(new SQLiteParameter("GroupName", file.FileSystemName));
                        databaseInterface.InsertGroup(sqliteCommand, file);
                        sqliteCommand.Parameters.Add(new SQLiteParameter("FindingType", "XCCDF"));
                        sqliteCommand.Parameters.Add(new SQLiteParameter("FileName", fileNameWithoutPath));
                        databaseInterface.InsertParsedFile(sqliteCommand, file);
                        using (XmlReader xmlReader = XmlReader.Create(file.FilePath, xmlReaderSettings))
                        {
                            while (xmlReader.Read())
                            {
                                if (xmlReader.IsStartElement())
                                {
                                    switch (xmlReader.Prefix)
                                    {
                                        case "cdf":
                                            {
                                                ParseXccdfFromScc(xmlReader, sqliteCommand);
                                                break;
                                            }
                                        case "xccdf":
                                            {
                                                //ParseXccdfFromAcas(xmlReader, sqliteCommand);
                                                break;
                                            }
                                        case "oval-res":
                                            {
                                                incorrectFileType = true;
                                                return;
                                            }
                                        case "oval-var":
                                            {
                                                incorrectFileType = true;
                                                return;
                                            }
                                        case "":
                                            {
                                                ParseXccdfFromScc(xmlReader, sqliteCommand);
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
                DatabaseBuilder.sqliteConnection.Close();
            }
            catch (Exception exception)
            {
                log.Error("Unable to parse XCCDF using XML reader.");
                throw exception;
            }
        }

        #region Parse XCCDF File From SCC

        private void ParseXccdfFromScc(XmlReader xmlReader, SQLiteCommand sqliteCommand)
        {
            try
            {
                ReadBenchmarkNode(sqliteCommand, xmlReader);
                while (xmlReader.Read())
                {
                    if (xmlReader.IsStartElement())
                    {
                        switch (xmlReader.Name)
                        {
                            case "cdf:Group":
                                {
                                    GetSccXccdfVulnerabilityInformation(xmlReader, sqliteCommand);
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

        private void ReadBenchmarkNode(SQLiteCommand sqliteCommand, XmlReader xmlReader)
        {
            try
            {
                sqliteCommand.Parameters.Add(new SQLiteParameter("Source_Secondary_Identifier", xmlReader.GetAttribute("id")));
                while (xmlReader.Read())
                {
                    if (xmlReader.IsStartElement())
                    {
                        switch (xmlReader.Name)
                        {
                            case "cdf:title":
                                {
                                    string sourceName = ObtainCurrentNodeValue(xmlReader).Replace('_', ' ');
                                    sourceName = SanitizeSourceName(sourceName);
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Source_Name", sourceName));
                                    break;
                                }
                            case "cdf:description":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Source_Description", ObtainCurrentNodeValue(xmlReader)));
                                    break;
                                }
                            case "cdf:plain-text":
                                {
                                    string release = ObtainCurrentNodeValue(xmlReader);
                                    if (release.Contains(" "))
                                    {
                                        Regex regex = new Regex(Properties.Resources.RegexRawStigRelease);
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("Source_Release", regex.Match(release)));
                                    }
                                    else
                                    { sqliteCommand.Parameters.Add(new SQLiteParameter("Source_Release", release)); }
                                    break;
                                }
                            case "cdf:version":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Source_Version", ObtainCurrentNodeValue(xmlReader)));
                                    break;
                                }
                            case "cdf:Profile":
                                {
                                    databaseInterface.InsertVulnerabilitySource(sqliteCommand);
                                    databaseInterface.UpdateVulnerabilitySource(sqliteCommand, "CKL");
                                    return;
                                }
                            default:
                                { break; }
                        }
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to process Benchmark node.");
                throw exception;
            }
        }

        private void GetSccXccdfVulnerabilityInformation(XmlReader xmlReader, SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.Parameters["Vulnerability_Group_ID"].Value = xmlReader.GetAttribute("id");
                while (xmlReader.Read())
                {
                    if (xmlReader.IsStartElement())
                    {
                        switch (xmlReader.Name)
                        {
                            case "cdf:title":
                                {
                                    sqliteCommand.Parameters["Vulnerability_Group_Title"].Value = ObtainCurrentNodeValue(xmlReader);
                                    break;
                                }
                            case "cdf:Rule":
                                {
                                    ParseSccXccdfRuleNode(sqliteCommand, xmlReader);
                                    return;
                                }
                            default:
                                { break; }
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

        private void ParseSccXccdfRuleNode(SQLiteCommand sqliteCommand, XmlReader xmlReader)
        { 
            try
            {
                string rule = xmlReader.GetAttribute("id");
                string ruleVersion = string.Empty;
                if (rule.Contains("_"))
                { rule = rule.Split('_')[0]; }
                if (rule.Contains("r"))
                {
                    ruleVersion = rule.Split('r')[1];
                    rule = rule.Split('r')[0];
                }
                sqliteCommand.Parameters.Add(new SQLiteParameter("Unique_Vulnerability_Identifier", rule));
                sqliteCommand.Parameters.Add(new SQLiteParameter("Vulnerability_Version", ruleVersion));
                sqliteCommand.Parameters["Raw_Risk"].Value = ConvertSeverityToRawRisk(xmlReader.GetAttribute("severity"));
                while (xmlReader.Read())
                {
                    if (xmlReader.IsStartElement())
                    {
                        switch (xmlReader.Name)
                        {
                            case "cdf:title":
                                {
                                    sqliteCommand.Parameters["Vulnerability_Title"].Value = ObtainCurrentNodeValue(xmlReader);
                                    break;
                                }
                            case "cdf:description":
                                {
                                    ProcessRuleDescriptionNode(sqliteCommand, ObtainCurrentNodeValue(xmlReader));
                                    break;
                                }
                            case "cdf:ident":
                                {
                                    if (xmlReader.GetAttribute("system").Equals("http://iase.disa.mil/cci"))
                                    { ccis.Add(ObtainCurrentNodeValue(xmlReader).Replace("CCI-", string.Empty)); }
                                    break;
                                }
                            case "cdf:fixtext":
                                {
                                    sqliteCommand.Parameters["Fix_Text"].Value = ObtainCurrentNodeValue(xmlReader);
                                    break;
                                }
                            default:
                                { break; }
                        }
                    }
                    else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("cdf:Group"))
                    {
                        databaseInterface.UpdateVulnerability(sqliteCommand);
                        databaseInterface.InsertVulnerability(sqliteCommand);
                        databaseInterface.MapVulnerabilityToSource(sqliteCommand);
                        if (ccis.Count > 0)
                        {
                            foreach (string cci in ccis)
                            {
                                sqliteCommand.Parameters["CCI"].Value = cci;
                                databaseInterface.MapVulnerabilityToCci(sqliteCommand);
                                sqliteCommand.Parameters["CCI"].Value = string.Empty;
                            }
                        }
                        return;
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to parse SCC XCCDF \"Rule\" node."));
                throw exception;
            }
        }

        private void ProcessRuleDescriptionNode(SQLiteCommand sqliteCommand, string descriptionNodeValue)
        {
            try
            {
                string rootNode = @"<root></root>";
                descriptionNodeValue = rootNode.Insert(6, descriptionNodeValue);
                using (XmlReader xmlReader = XmlReader.Create(GenerateStreamFromString(descriptionNodeValue)))
                {
                    while (xmlReader.Read())
                    {
                        if (xmlReader.IsStartElement())
                        {
                            switch (xmlReader.Name)
                            {
                                case "VulnDiscussion":
                                    {
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("Vulnerability_Description", ObtainCurrentNodeValue(xmlReader)));
                                        break;
                                    }
                                case "FalsePositives":
                                    {
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("False_Positives", ObtainCurrentNodeValue(xmlReader)));
                                        break;
                                    }
                                case "FalseNegatives":
                                    {
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("False_Negatives", ObtainCurrentNodeValue(xmlReader)));
                                        break;
                                    }
                                case "Documentable":
                                    {
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("Documentable", ObtainCurrentNodeValue(xmlReader)));
                                        break;
                                    }
                                case "Mitigations":
                                    {
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("Mitigations", ObtainCurrentNodeValue(xmlReader)));
                                        break;
                                    }
                                case "SeverityOverrideGuidance":
                                    {
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("Severity_Override_Guidance", ObtainCurrentNodeValue(xmlReader)));
                                        break;
                                    }
                                case "PotentialImpacts":
                                    {
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("Potential_Impacts", ObtainCurrentNodeValue(xmlReader)));
                                        break;
                                    }
                                case "ThirdPartyTools":
                                    {
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("Third_Party_Tools", ObtainCurrentNodeValue(xmlReader)));
                                        break;
                                    }
                                case "MitigationControl":
                                    {
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("Mitigation_Control", ObtainCurrentNodeValue(xmlReader)));
                                        break;
                                    }
                                case "Responsibility":
                                    {
                                        responsibilities.Add(ObtainCurrentNodeValue(xmlReader));
                                        break;
                                    }
                                case "IAControls":
                                    {
                                        iaControls.Add(ObtainCurrentNodeValue(xmlReader));
                                        break;
                                    }
                                default:
                                    { break; }
                            }
                        }
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to process Rule description node.");
                throw exception;
            }
        }

        private void ParseSccXccdfTestResult(XmlReader xmlReader, SQLiteCommand sqliteCommand)
        {
            try
            {
                DateTime scanEndTime;
                if (DateTime.TryParse(xmlReader.GetAttribute("end-time"), out scanEndTime))
                { firstDiscovered = lastObserved = scanEndTime.ToShortDateString(); }
                while (xmlReader.Read())
                {
                    if (xmlReader.IsStartElement())
                    {
                        switch (xmlReader.Name)
                        {
                            case "cdf:target-facts":
                                {
                                    SetAffectedAssetInformationFromSccFile(xmlReader, sqliteCommand);
                                    break;
                                }
                            case "cdf:rule-result":
                                {
                                    SetXccdfScanResultFromSccFile(xmlReader, sqliteCommand);
                                    break;
                                }
                            case "cdf:score":
                                {
                                    SetXccdfScoreFromSccFile(xmlReader, sqliteCommand);
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
                                    sqliteCommand.Parameters["Host_Name"].Value = ObtainCurrentNodeValue(xmlReader);
                                    break;
                                }
                            case "urn:scap:fact:asset:identifier:ipv4":
                                {
                                    ips.Add(ObtainCurrentNodeValue(xmlReader));
                                    break;
                                }
                            case "urn:scap:fact:asset:identifier:ipv6":
                                {
                                    ips.Add(ObtainCurrentNodeValue(xmlReader));
                                    break;
                                }
                            case "urn:scap:fact:asset:identifier:mac":
                                {
                                    macs.Add(ObtainCurrentNodeValue(xmlReader));
                                    break;
                                }
                            case "urn:scap:fact:asset:identifier:fqdn":
                                {
                                    sqliteCommand.Parameters["FQDN"].Value = ObtainCurrentNodeValue(xmlReader);
                                    break;
                                }
                            default:
                                { break; }
                        }
                    }
                    else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("cdf:target-facts"))
                    {
                        databaseInterface.InsertHardware(sqliteCommand);
                        databaseInterface.InsertAndMapIpAddress(sqliteCommand);
                        databaseInterface.MapHardwareToGroup(sqliteCommand);
                        if (ips.Count > 0)
                        {
                            foreach (string ip in ips)
                            {
                                sqliteCommand.Parameters["IP_Address"].Value = ip;
                                databaseInterface.InsertAndMapIpAddress(sqliteCommand);
                                sqliteCommand.Parameters["MAC_Address"].Value = string.Empty;
                            }
                        }
                        if (macs.Count > 0)
                        {
                            foreach (string mac in macs)
                            {
                                sqliteCommand.Parameters["IP_Address"].Value = mac;
                                databaseInterface.InsertAndMapMacAddress(sqliteCommand);
                                sqliteCommand.Parameters["MAC_Address"].Value = string.Empty;
                            }
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
                string rule = xmlReader.GetAttribute("idref");
                string ruleVersion = string.Empty;
                if (rule.Contains("_"))
                { rule = rule.Split('_')[0]; }
                if (rule.Contains("r"))
                {
                    ruleVersion = rule.Split('r')[1];
                    rule = rule.Split('r')[0];
                }
                sqliteCommand.Parameters["Unique_Vulnerability_Identifier"].Value = rule;
                sqliteCommand.Parameters["Vulnerability_Version"].Value = ruleVersion;
                while (xmlReader.Read())
                {
                    if (xmlReader.IsStartElement() && xmlReader.Name.Equals("cdf:result"))
                    { sqliteCommand.Parameters["Status"].Value = ConvertXccdfResultToStatus(ObtainCurrentNodeValue(xmlReader)); }
                    else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("cdf:rule-result"))
                    {
                        PrepareUniqueFinding(sqliteCommand);
                        return;
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to set XCCDF scan result.");
                throw exception;
            }
        }

        private void PrepareUniqueFinding(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.Parameters.Add(new SQLiteParameter("Last_Observed", lastObserved));
                sqliteCommand.Parameters.Add(new SQLiteParameter("Delta_Analysis_Required", "False"));
                sqliteCommand.Parameters.Add(new SQLiteParameter("Approval_Status", "Not Approved"));
                sqliteCommand.Parameters.Add(new SQLiteParameter("First_Discovered", firstDiscovered));
                databaseInterface.UpdateUniqueFinding(sqliteCommand, "CKL");
                databaseInterface.InsertUniqueFinding(sqliteCommand);
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to create a uniqueFinding record for plugin \"{0}\".",
                    sqliteCommand.Parameters["Unique_Vulnerability_Identifier"].Value.ToString()));
                throw exception;
            }
        }

        private void SetXccdfScoreFromSccFile(XmlReader xmlReader, SQLiteCommand sqliteCommand)
        {
            while (!xmlReader.Name.Equals("cdf:TestResult"))
            {
                if (!string.IsNullOrWhiteSpace(xmlReader.GetAttribute("system")) && xmlReader.GetAttribute("system").Equals("urn:xccdf:scoring:default"))
                {
                    sqliteCommand.Parameters.Add(new SQLiteParameter("Score", ObtainCurrentNodeValue(xmlReader)));
                    sqliteCommand.Parameters["Scan_Date"].Value = DateTime.Now.ToShortDateString();
                    databaseInterface.InsertScapScore(sqliteCommand);
                }
                else
                { xmlReader.Read(); }
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

        //#region Parse XCCDF File From ACAS

        //private void ParseXccdfFromAcas(XmlReader xmlReader, SQLiteCommand sqliteCommand)
        //{
        //    try
        //    {
        //        while (xmlReader.Read())
        //        {
        //            if (xmlReader.IsStartElement())
        //            {
        //                switch (xmlReader.Name)
        //                {
        //                    case "xccdf:benchmark":
        //                        {
        //                            bool sourceExists = false;
        //                            sqliteCommand.Parameters.Add(new SQLiteParameter("Source", GetAcasXccdfTitle(xmlReader)));
        //                            if (!string.IsNullOrWhiteSpace(versionInfo))
        //                            { sqliteCommand.Parameters.Add(new SQLiteParameter("Version", versionInfo)); }
        //                            else
        //                            { sqliteCommand.Parameters.Add(new SQLiteParameter("Version", "V?")); }
        //                            if (!string.IsNullOrWhiteSpace(releaseInfo))
        //                            { sqliteCommand.Parameters.Add(new SQLiteParameter("Release", releaseInfo)); }
        //                            else
        //                            { sqliteCommand.Parameters.Add(new SQLiteParameter("Release", "R?")); }
        //                            sqliteCommand.CommandText = "SELECT * FROM VulnerabilitySources WHERE Source = @Source AND Version = @Version AND Release = @Release;";
        //                            using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
        //                            {
        //                                if (sqliteDataReader.HasRows)
        //                                { sourceExists = true; }
        //                            }
        //                            if (!sourceExists)
        //                            {
        //                                sqliteCommand.CommandText = SetSqliteCommandText("VulnerabilitySources");
        //                                sqliteCommand.ExecuteNonQuery();
        //                            }
        //                            break;
        //                        }
        //                    case "xccdf:target-facts":
        //                        {
        //                            GetAcasXccdfTargetInfo(xmlReader, sqliteCommand);
        //                            if (sqliteCommand.Parameters.Contains("HostName") && UserPrefersHostName)
        //                            {
        //                                sqliteCommand.Parameters.Add(new SQLiteParameter(
        //                                  "AssetIdToReport", sqliteCommand.Parameters["HostName"].Value));
        //                            }
        //                            else
        //                            {
        //                                sqliteCommand.Parameters.Add(new SQLiteParameter(
        //                                  "AssetIdToReport", sqliteCommand.Parameters["IpAddress"].Value));
        //                            }
        //                            sqliteCommand.CommandText = SetSqliteCommandText("Assets");
        //                            InsertAssetCommand(sqliteCommand);
        //                            break;
        //                        }
        //                    case "xccdf:rule-result":
        //                        {
        //                            ParseAcasXccdfTestResult(xmlReader, sqliteCommand);
        //                            sqliteCommand.CommandText = SetSqliteCommandText("Vulnerability");
        //                            InsertVulnerabilityCommand(sqliteCommand);
        //                            sqliteCommand.CommandText = SetSqliteCommandText("UniqueFinding");
        //                            sqliteCommand.ExecuteNonQuery();
        //                            sqliteCommand.Parameters.Remove(sqliteCommand.Parameters["NistControl"]);
        //                            break;
        //                        }
        //                    case "xccdf:score":
        //                        {
        //                            xmlReader.Read();
        //                            sqliteCommand.Parameters.Add(new SQLiteParameter("ScapScore", xmlReader.Value));
        //                            sqliteCommand.CommandText = SetSqliteCommandText("ScapScores");
        //                            sqliteCommand.ExecuteNonQuery();
        //                            break;
        //                        }
        //                    default:
        //                        { break; }
        //                }
        //            }
        //        }
        //    }
        //    catch (Exception exception)
        //    {
        //        log.Error("Unable to parse ACAS XCCDF.");
        //        throw exception;
        //    }
        //}

        //private string GetAcasXccdfTitle(XmlReader xmlReader)
        //{
        //    try
        //    {
        //        xccdfTitle = xmlReader.GetAttribute("href");
        //        xccdfTitle = xccdfTitle.Split(new string[] { "_SCAP" }, StringSplitOptions.None)[0].Replace('_', ' ');
        //        if (Regex.IsMatch(xccdfTitle, @"\bU \b"))
        //        { xccdfTitle = Regex.Replace(xccdfTitle, @"\bU \b", ""); }
        //        Match match = Regex.Match(xccdfTitle, @"V\dR\d{1,10}");
        //        if (match.Success)
        //        {
        //            versionInfo = match.Value.Split('R')[0];
        //            releaseInfo = "R" + match.Value.Split('R')[1];
        //        }
        //        xccdfTitle = xccdfTitle.Replace(match.Value + " ", "") + " Benchmark";
        //        return xccdfTitle;
        //    }
        //    catch (Exception exception)
        //    {
        //        log.Error("Unable to obtain XCCDF title.");
        //        throw exception;
        //    }
        //}

        //private void GetAcasXccdfTargetInfo(XmlReader xmlReader, SQLiteCommand sqliteCommand)
        //{
        //    try
        //    {
        //        while (xmlReader.Read())
        //        {
        //            if (xmlReader.IsStartElement())
        //            {
        //                switch (xmlReader.GetAttribute("name"))
        //                {
        //                    case "urn:xccdf:fact:asset:identifier:host_name":
        //                        {
        //                            xmlReader.Read();
        //                            sqliteCommand.Parameters.Add(new SQLiteParameter("HostName", xmlReader.Value));
        //                            break;
        //                        }
        //                    case "urn:xccdf:fact:asset:identifier:ipv4":
        //                        {
        //                            xmlReader.Read();
        //                            if (!sqliteCommand.Parameters.Contains("IpAddress"))
        //                            { sqliteCommand.Parameters.Add(new SQLiteParameter("IpAddress", xmlReader.Value)); }
        //                            else
        //                            { sqliteCommand.Parameters["IpAddress"].Value += @"/" + xmlReader.Value; }
        //                            break;
        //                        }
        //                    default:
        //                        { break; }
        //                }
        //            }
        //            else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("xccdf:target-facts"))
        //            { return; }
        //        }
        //    }
        //    catch (Exception exception)
        //    {
        //        log.Error("Unable to obtain XCCDF target information.");
        //        throw exception;
        //    }
        //}

        //private void ParseAcasXccdfTestResult(XmlReader xmlReader, SQLiteCommand sqliteCommand)
        //{
        //    try
        //    {
        //        sqliteCommand.Parameters.Add(new SQLiteParameter(
        //            "VulnId", xmlReader.GetAttribute("idref").Replace("_rule", "")));
        //        sqliteCommand.Parameters.Add(new SQLiteParameter(
        //            "RuleId", xmlReader.GetAttribute("idref").Replace("_rule", "")));
        //        sqliteCommand.Parameters.Add(new SQLiteParameter(
        //            "RawRisk", ConvertSeverityToRawRisk(xmlReader.GetAttribute("severity"))));
        //        sqliteCommand.Parameters.Add(new SQLiteParameter(
        //            "Impact", ConvertSeverityToImpact(xmlReader.GetAttribute("severity"))));
        //        sqliteCommand.Parameters.Add(new SQLiteParameter(
        //            "Description", "XCCDF Result was generated via ACAS; description is not available."));
        //        sqliteCommand.Parameters.Add(new SQLiteParameter(
        //            "VulnTitle", "XCCDF Result was generated via ACAS; title is not available."));

        //        while (xmlReader.Read())
        //        {
        //            if (xmlReader.IsStartElement())
        //            {
        //                switch (xmlReader.Name)
        //                {
        //                    case "xccdf:result":
        //                        {
        //                            xmlReader.Read();
        //                            sqliteCommand.Parameters.Add(new SQLiteParameter(
        //                                "Status", ConvertXccdfResultToStatus(xmlReader.Value)));
        //                            break;
        //                        }
        //                    case "xccdf:ident":
        //                        {
        //                            if (xmlReader.GetAttribute("system").Equals(@"http://iase.disa.mil/cci"))
        //                            {
        //                                xmlReader.Read();
        //                                string cciRef = xmlReader.Value;
        //                                if (!string.IsNullOrWhiteSpace(cciRef))
        //                                {
        //                                    foreach (CciToNist cciToNist in MainWindowViewModel.cciToNistList.Where(x => x.CciNumber.Equals(cciRef)))
        //                                    {
        //                                        if (!sqliteCommand.Parameters.Contains("NistControl"))
        //                                        {
        //                                            if (RevisionThreeSelected && cciToNist.Revision.Contains("Rev. 3"))
        //                                            { sqliteCommand.Parameters.Add(new SQLiteParameter("NistControl", cciToNist.NistControl)); }
        //                                            if (RevisionFourSelected && cciToNist.Revision.Contains("Rev. 4"))
        //                                            { sqliteCommand.Parameters.Add(new SQLiteParameter("NistControl", cciToNist.NistControl)); }
        //                                            if (AppendixASelected && cciToNist.Revision.Contains("53A"))
        //                                            { sqliteCommand.Parameters.Add(new SQLiteParameter("NistControl", cciToNist.NistControl)); }
        //                                        }
        //                                        else
        //                                        {
        //                                            if (RevisionThreeSelected && cciToNist.Revision.Contains("Rev. 3") && 
        //                                                !sqliteCommand.Parameters["NistControl"].Value.ToString().Contains(cciToNist.NistControl))
        //                                            {
        //                                                sqliteCommand.Parameters["NistControl"].Value =
        //                                                  sqliteCommand.Parameters["NistControl"].Value + Environment.NewLine + cciToNist.NistControl;
        //                                            }
        //                                            if (RevisionFourSelected && cciToNist.Revision.Contains("Rev. 4") &&
        //                                                !sqliteCommand.Parameters["NistControl"].Value.ToString().Contains(cciToNist.NistControl))
        //                                            {
        //                                                sqliteCommand.Parameters["NistControl"].Value =
        //                                                  sqliteCommand.Parameters["NistControl"].Value + Environment.NewLine + cciToNist.NistControl;
        //                                            }
        //                                            if (AppendixASelected && cciToNist.Revision.Contains("53A") &&
        //                                                !sqliteCommand.Parameters["NistControl"].Value.ToString().Contains(cciToNist.NistControl))
        //                                            {
        //                                                sqliteCommand.Parameters["NistControl"].Value =
        //                                                  sqliteCommand.Parameters["NistControl"].Value + Environment.NewLine + cciToNist.NistControl;
        //                                            }
        //                                        }
        //                                    }
        //                                    sqliteCommand.Parameters.Add(new SQLiteParameter("CciNumber", cciRef));
        //                                }
        //                            }
        //                            break;
        //                        }
        //                    default:
        //                        { break; }
        //                }
        //            }
        //            else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("xccdf:rule-result"))
        //            { return; }
        //        }
        //    }
        //    catch (Exception exception)
        //    {
        //        log.Error("Unable to parse XCCDF test results.");
        //        throw exception;
        //    }
        //}

        //#endregion

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
                switch (xccdfResult)
                {
                    case "pass":
                        return "Completed";
                    case "fail":
                        return "Ongoing";
                    case "error":
                        return "Error";
                    case "unknown":
                        return "Not Reviewed";
                    case "notapplicable":
                        return "Not Applicable";
                    case "notchecked":
                        return "Not Reviewed";
                    case "notselected":
                        return "Not Reviewed";
                    case "informational":
                        return "Informational";
                    case "fixed":
                        return "Completed";
                    default:
                        return "Not Reviewed";
                }
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

        private XmlReaderSettings GenerateXmlReaderSettings()
        {
            try
            {
                XmlReaderSettings xmlReaderSettings = new XmlReaderSettings();
                xmlReaderSettings.IgnoreWhitespace = true;
                xmlReaderSettings.IgnoreComments = true;
                xmlReaderSettings.ValidationType = ValidationType.Schema;
                if (NetworkInterface.GetIsNetworkAvailable())
                {
                    xmlReaderSettings.ValidationFlags = XmlSchemaValidationFlags.ProcessInlineSchema;
                    xmlReaderSettings.ValidationFlags = XmlSchemaValidationFlags.ProcessSchemaLocation;
                }
                return xmlReaderSettings;
            }
            catch (Exception exception)
            {
                log.Error("Unable to generate XmlReaderSettings.");
                throw exception;
            }
        }

        private void InsertParameterPlaceholders(SQLiteCommand sqliteCommand)
        {
            try
            {
                string[] parameters = new string[]
                {
                    // Groups Table
                    "Group_ID", "Group_Name", "Is_Accreditation", "Accreditation_ID", "Organization_ID",
                    // Hardware Table
                    "Hardware_ID", "Host_Name", "FQDN", "NetBIOS", "Is_Virtual_Server", "NIAP_Level", "Manufacturer", "ModelNumber",
                    "Is_IA_Enabled", "SerialNumber", "Role", "Lifecycle_Status_ID", "Scan_IP",
                    // IP_Addresses Table
                    "IP_Address_ID", "IP_Address",
                    // MAC_Addresses Table
                    "MAC_Address_ID", "MAC_Address",
                    // UniqueFindings Table
                    "Unique_Finding_ID", "Instance_Identifier", "Tool_Generated_Output", "Comments", "Finding_Details", "Technical_Mitigation",
                    "Proposed_Mitigation", "Predisposing_Conditions", "Impact", "Likelihood", "Severity", "Risk", "Residual_Risk",
                    "First_Discovered", "Last_Observed", "Approval_Status", "Approval_Date", "Approval_Expiration_Date",
                    "Delta_Analysis_Required", "Finding_Type_ID", "Finding_Source_ID", "Status", "Vulnerability_ID", "Hardware_ID",
                    "Severity_Override", "Severity_Override_Justification", "Technology_Area", "Web_DB_Site", "Web_DB_Instance",
                    "Classification", "CVSS_Environmental_Score", "CVSS_Environmental_Vector",
                    // UniqueFindingSourceFiles Table
                    "Finding_Source_File_ID", "Finding_Source_File_Name", 
                    // Vulnerabilities Table
                    "Vulnerability_ID", "Unique_Vulnerability_Identifier", "Vulnerability_Group_ID", "Vulnerability_Group_Title",
                    "Secondary_Vulnerability_Identifier", "VulnerabilityFamilyOrClass", "Vulnerability_Version", "Vulnerability_Release",
                    "Vulnerability_Title", "Vulnerability_Description", "Risk_Statement", "Fix_Text", "Published_Date", "Modified_Date",
                    "Fix_Published_Date", "Raw_Risk", "CVSS_Base_Score", "CVSS_Base_Vector", "CVSS_Temporal_Score", "CVSS_Temporal_Vector",
                    "Check_Content", "False_Positives", "False_Negatives", "Documentable", "Mitigations", "Mitigation_Control",
                    "Potential_Impacts", "Third_Party_Tools", "Security_Override_Guidance", "Overflow",
                    // VulnerabilityReferences Table
                    "Reference_ID", "Reference", "Reference_Type",
                    // VulnerabilitySources Table
                    "Vulnerability_Source_ID", "Source_Name", "Source_Secondary_Identifier", "Vulnerability_Source_File_Name",
                    "Source_Description", "Source_Version", "Source_Release",
                    // CCI Table
                    "CCI",
                    // ScapScores Table
                    "Score", "Scan_Date"
                };
                foreach (string parameter in parameters)
                { sqliteCommand.Parameters.Add(new SQLiteParameter(parameter, string.Empty)); }
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to insert SQLiteParameter placeholders into SQLiteCommand"));
                throw exception;
            }
        }

        private string ObtainCurrentNodeValue(XmlReader xmlReader)
        {
            try
            {
                xmlReader.Read();
                string value = xmlReader.Value;
                value = value.Replace("&gt", ">");
                value = value.Replace("&lt", "<");
                return value;
            }
            catch (Exception exception)
            {
                log.Error("Unable to obtain currently accessed node value.");
                throw exception;
            }
        }

        private string SanitizeSourceName(string sourceName)
        {
            try
            {
                bool isSRG = sourceName.Contains("SRG") || sourceName.Contains("Security Requirement") ? true : false;
                string value = sourceName;
                string[] replaceArray = new string[] { "STIG", "Security", "Technical", "Implementation", "Guide", "(", ")", "Requirements", "Technologies", "SRG", "  " };
                foreach (string item in replaceArray)
                {
                    if (item.Equals("  "))
                    { value = value.Replace(item, " "); }
                    else
                    { value = value.Replace(item, ""); }
                }
                value = value.Trim();
                if (!isSRG)
                {
                    value = string.Format("{0} Security Technical Implementation Guide", value);
                    return value;
                }
                value = string.Format("{0} Security Requirements Guide", value);
                return value;
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to sanitize source name \"{0}\".", sourceName));
                log.Debug("Exception details:", exception);
                return sourceName;
            }
        }
    }
}
