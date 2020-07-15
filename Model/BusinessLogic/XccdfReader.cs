using log4net;
using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SQLite;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Reflection;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Schema;
using Vulnerator.Model.DataAccess;
using Vulnerator.Helper;
using Vulnerator.Model.Object;
using Vulnerator.ViewModel;
using PropertyAttributes = System.Reflection.PropertyAttributes;

namespace Vulnerator.Model.BusinessLogic
{
    /// <summary>
    /// Class to read XCCDF files.  Designed to read files regardless
    /// of whether they are pulled from SCC, HBSS Policy Auditor, or
    /// ACAS.
    /// </summary>
    public class XccdfReader
    {
        DatabaseInterface databaseInterface = new DatabaseInterface();
        private string fileNameWithoutPath = string.Empty;
        private DateTime firstDiscovered = DateTime.Now;
        private DateTime lastObserved = DateTime.Now;
        private bool incorrectFileType = false;
        private List<string> ccis = new List<string>();
        private List<string> ips = new List<string>();
        private List<string> macs = new List<string>();
        private List<string> responsibilities = new List<string>();
        private List<string> iaControls = new List<string>();
        private string[] persistentParameters = { "Name", "FindingSourceFileName", "SourceName", "SourceVersion", "SourceRelease", "VulnerabilityRelease", "PublishedDate" };

        public string ReadXccdfFile(Object.File file)
        {
            try
            {
                if (file.FileName.IsFileInUse())
                {
                    LogWriter.LogError($"'{file.FileName}' is in use; please close any open instances and try again.");
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
                string error = $"Unable to process XCCDF file '{file.FileName}'.";
                LogWriter.LogErrorWithDebug(error, exception);
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
                        databaseInterface.InsertParameterPlaceholders(sqliteCommand);
                        sqliteCommand.Parameters.Add(new SQLiteParameter("FindingType", "XCCDF"));
                        sqliteCommand.Parameters["GroupName"].Value = "All";
                        sqliteCommand.Parameters["FindingSourceFileName"].Value = fileNameWithoutPath;
                        sqliteCommand.Parameters["VulnerabilityRelease"].Value = string.Empty;
                        databaseInterface.InsertParsedFileSource(sqliteCommand, file);
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
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to parse XCCDF using XML reader.");
                throw exception;
            }
            finally
            { DatabaseBuilder.sqliteConnection.Close(); }
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
                LogWriter.LogError("Unable to parse SCC XCCDF.");
                throw exception;
            }
        }

        private void ReadBenchmarkNode(SQLiteCommand sqliteCommand, XmlReader xmlReader)
        {
            try
            {
                sqliteCommand.Parameters.Add(new SQLiteParameter("SourceSecondaryIdentifier", xmlReader.GetAttribute("id")));
                while (xmlReader.Read())
                {
                    if (xmlReader.IsStartElement())
                    {
                        switch (xmlReader.Name)
                        {
                            case "cdf:title":
                                {
                                    string sourceName = xmlReader.ObtainCurrentNodeValue(true).ToString().Replace('_', ' ');
                                    sourceName = sourceName.ToSanitizedSource();
                                    sqliteCommand.Parameters["SourceName"].Value = sourceName;
                                    break;
                                }
                            case "cdf:description":
                                {
                                    sqliteCommand.Parameters["SourceDescription"].Value = xmlReader.ObtainCurrentNodeValue(true);
                                    break;
                                }
                            case "plain-text":
                                {
                                    string release = xmlReader.ObtainCurrentNodeValue(false).ToString();
                                    Regex regex = new Regex(Properties.Resources.RegexStigDate);
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("PublishedDate", DateTime
                                        .ParseExact(regex.Match(release).ToString(), "dd MMM yyyy", CultureInfo.InvariantCulture)
                                        .ToShortDateString()));
                                    break;
                                }
                            case "cdf:version":
                                {
                                    string rawVersion = xmlReader.ObtainCurrentNodeValue(true).ToString();
                                    Regex regex = new Regex(Properties.Resources.RegexStigVersion);
                                    sqliteCommand.Parameters["SourceVersion"].Value =
                                        regex.Match(rawVersion).Value;
                                    regex = new Regex(Properties.Resources.RegexStigRelease);
                                    sqliteCommand.Parameters["SourceRelease"].Value =
                                        regex.Match(rawVersion).Value;
                                    break;
                                }
                            case "cdf:Profile":
                                {
                                    databaseInterface.InsertVulnerabilitySource(sqliteCommand);
                                    return;
                                }
                        }
                    }
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to process 'Benchmark' node.");
                throw exception;
            }
        }

        private void GetSccXccdfVulnerabilityInformation(XmlReader xmlReader, SQLiteCommand sqliteCommand)
        {
            try
            {
                string vulnerabilityGroupIdentifier = xmlReader.GetAttribute("id");
                Regex regexVulnerabilityGroupIdentifier = new Regex(Properties.Resources.RegexVulnerabilityGroupIdentifier);
                vulnerabilityGroupIdentifier =
                    regexVulnerabilityGroupIdentifier.Match(vulnerabilityGroupIdentifier).Value;
                sqliteCommand.Parameters["VulnerabilityGroupIdentifier"].Value = vulnerabilityGroupIdentifier;
                while (xmlReader.Read())
                {
                    if (xmlReader.IsStartElement())
                    {
                        switch (xmlReader.Name)
                        {
                            case "cdf:title":
                                {
                                    sqliteCommand.Parameters["VulnerabilityGroupTitle"].Value = xmlReader.ObtainCurrentNodeValue(true);
                                    break;
                                }
                            case "cdf:Rule":
                                {
                                    ParseSccXccdfRuleNode(sqliteCommand, xmlReader);
                                    return;
                                }
                        }
                    }

                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to get XCCDF vulnerability information.");
                throw exception;
            }
        }

        private void ParseSccXccdfRuleNode(SQLiteCommand sqliteCommand, XmlReader xmlReader)
        {
            try
            {
                string rule = xmlReader.GetAttribute("id");
                string ruleVersion = string.Empty;
                Regex xccdfRuleRegex = new Regex(Properties.Resources.RegexXccdfRule);
                rule = xccdfRuleRegex.Match(rule).Value;
                if (rule.Contains("r"))
                {
                    ruleVersion = rule.Split('r')[1];
                    rule = rule.Split('r')[0];
                }
                sqliteCommand.Parameters["UniqueVulnerabilityIdentifier"].Value = rule;
                sqliteCommand.Parameters["VulnerabilityVersion"].Value = ruleVersion;
                sqliteCommand.Parameters["PrimaryRawRiskIndicator"].Value = xmlReader.GetAttribute("severity").ToRawRisk();
                while (xmlReader.Read())
                {
                    if (xmlReader.IsStartElement())
                    {
                        switch (xmlReader.Name)
                        {
                            case "cdf:version":
                                {
                                    sqliteCommand.Parameters["SecondaryVulnerabilityIdentifier"].Value = xmlReader.ObtainCurrentNodeValue(true);
                                    break;
                                }
                            case "cdf:title":
                                {
                                    sqliteCommand.Parameters["VulnerabilityTitle"].Value = xmlReader.ObtainCurrentNodeValue(true);
                                    break;
                                }
                            case "cdf:description":
                                {
                                    ProcessRuleDescriptionNode(sqliteCommand, xmlReader.ObtainCurrentNodeValue(true).ToString());
                                    break;
                                }
                            case "cdf:ident":
                                {
                                    if (xmlReader.GetAttribute("system").Equals("http://iase.disa.mil/cci"))
                                    { ccis.Add(xmlReader.ObtainCurrentNodeValue(true).ToString().Replace("CCI-", string.Empty)); }
                                    break;
                                }
                            case "cdf:fixtext":
                                {
                                    sqliteCommand.Parameters["FixText"].Value = xmlReader.ObtainCurrentNodeValue(true);
                                    break;
                                }
                        }
                    }
                    else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("cdf:Group"))
                    {
                        databaseInterface.InsertVulnerability(sqliteCommand);
                        databaseInterface.MapVulnerabilityToSource(sqliteCommand);
                        if (ccis.Count > 0)
                        {
                            foreach (string cci in ccis)
                            {
                                sqliteCommand.Parameters["CCI_Number"].Value = cci;
                                databaseInterface.MapVulnerabilityToCci(sqliteCommand);
                                sqliteCommand.Parameters["CCI_Number"].Value = DBNull.Value;
                            }
                            ccis.Clear();
                        }
                        return;
                    }
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to parse SCC XCCDF 'Rule' node.");
                throw exception;
            }
        }

        private void ProcessRuleDescriptionNode(SQLiteCommand sqliteCommand, string descriptionNodeValue)
        {
            try
            {
                string rootNode = @"<root></root>";
                descriptionNodeValue = rootNode.Insert(6, descriptionNodeValue);
                if (descriptionNodeValue.Contains(@"<link>"))
                { descriptionNodeValue = descriptionNodeValue.Replace(@"<link>", "\"link\""); }
                if (descriptionNodeValue.Contains(@"<link"))
                {
                    int falseStartElementIndex = descriptionNodeValue.IndexOf("<link");
                    int falseEndElementIndex = descriptionNodeValue.IndexOf(">", falseStartElementIndex);
                    StringBuilder stringBuilder = new StringBuilder(descriptionNodeValue);
                    stringBuilder[falseEndElementIndex] = '\"';
                    descriptionNodeValue = stringBuilder.ToString();
                    descriptionNodeValue = descriptionNodeValue.Replace(@"<link", "\"link");
                }
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
                                        sqliteCommand.Parameters["VulnerabilityDescription"].Value = xmlReader.ObtainCurrentNodeValue(true);
                                        break;
                                    }
                                case "FalsePositives":
                                    {
                                        sqliteCommand.Parameters["FalsePositives"].Value = xmlReader.ObtainCurrentNodeValue(true);
                                        break;
                                    }
                                case "FalseNegatives":
                                    {
                                        sqliteCommand.Parameters["FalseNegatives"].Value = xmlReader.ObtainCurrentNodeValue(true);
                                        break;
                                    }
                                case "Documentable":
                                    {
                                        sqliteCommand.Parameters["IsDocumentable"].Value = xmlReader.ObtainCurrentNodeValue(true);
                                        break;
                                    }
                                case "Mitigations":
                                    {
                                        sqliteCommand.Parameters["Mitigations"].Value = xmlReader.ObtainCurrentNodeValue(true);
                                        break;
                                    }
                                case "SeverityOverrideGuidance":
                                    {
                                        sqliteCommand.Parameters["SeverityOverrideGuidance"].Value = xmlReader.ObtainCurrentNodeValue(true);
                                        break;
                                    }
                                case "PotentialImpacts":
                                    {
                                        sqliteCommand.Parameters["PotentialImpacts"].Value = xmlReader.ObtainCurrentNodeValue(true);
                                        break;
                                    }
                                case "ThirdPartyTools":
                                    {
                                        sqliteCommand.Parameters["ThirdPartyTools"].Value = xmlReader.ObtainCurrentNodeValue(true);
                                        break;
                                    }
                                case "MitigationControl":
                                    {
                                        sqliteCommand.Parameters["MitigationControl"].Value = xmlReader.ObtainCurrentNodeValue(true);
                                        break;
                                    }
                                case "Responsibility":
                                    {
                                        responsibilities.Add(xmlReader.ObtainCurrentNodeValue(true).ToString());
                                        break;
                                    }
                                case "IAControls":
                                    {
                                        iaControls.Add(xmlReader.ObtainCurrentNodeValue(true).ToString());
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
                LogWriter.LogError("Unable to process Rule 'description' node.");
                throw exception;
            }
        }

        private void ParseSccXccdfTestResult(XmlReader xmlReader, SQLiteCommand sqliteCommand)
        {
            try
            {
                DateTime scanEndTime;
                if (DateTime.TryParse(xmlReader.GetAttribute("end-time"), out scanEndTime))
                { firstDiscovered = lastObserved = scanEndTime; }
                while (xmlReader.Read())
                {
                    if (xmlReader.IsStartElement())
                    {
                        switch (xmlReader.Name)
                        {
                            case "cdf:profile":
                            {
                                Regex regex = new Regex(Properties.Resources.RegexXccdfProfile);
                                sqliteCommand.Parameters["ScanProfile"].Value = regex.Match(xmlReader.GetAttribute("idref")).Value;
                                break;
                            }
                            case "cdf:identity":
                            {
                                sqliteCommand.Parameters["UserIsPrivileged"].Value =
                                    xmlReader.GetAttribute("privileged");
                                sqliteCommand.Parameters["UserIsAuthenticated"].Value =
                                    xmlReader.GetAttribute("authenticated");
                                sqliteCommand.Parameters["ScanUser"].Value =
                                    xmlReader.ObtainCurrentNodeValue(true);
                                break;
                            }
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
                        }
                    }
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to parse XCCDF test results.");
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
                                    string hostName = xmlReader.ObtainCurrentNodeValue(true).ToString();
                                    sqliteCommand.Parameters["DiscoveredHostName"].Value = hostName;
                                    sqliteCommand.Parameters["DisplayedHostName"].Value = hostName;
                                    break;
                                }
                            case "urn:scap:fact:asset:identifier:ipv4":
                                {
                                    ips.Add(xmlReader.ObtainCurrentNodeValue(true).ToString());
                                    break;
                                }
                            case "urn:scap:fact:asset:identifier:ipv6":
                                {
                                    ips.Add(xmlReader.ObtainCurrentNodeValue(true).ToString());
                                    break;
                                }
                            case "urn:scap:fact:asset:identifier:mac":
                                {
                                    macs.Add(xmlReader.ObtainCurrentNodeValue(true).ToString());
                                    break;
                                }
                            case "urn:scap:fact:asset:identifier:fqdn":
                                {
                                    sqliteCommand.Parameters["FQDN"].Value = xmlReader.ObtainCurrentNodeValue(true);
                                    break;
                                }
                        }
                    }
                    else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("cdf:target-facts"))
                    {
                        databaseInterface.InsertHardware(sqliteCommand);
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
                                sqliteCommand.Parameters["MAC_Address"].Value = mac;
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
                LogWriter.LogError("Unable to set affected asset information from SCC XCCDF file.");
                throw exception;
            }
        }

        private void SetXccdfScanResultFromSccFile(XmlReader xmlReader, SQLiteCommand sqliteCommand)
        {
            try
            {
                string rule = xmlReader.GetAttribute("idref");
                string ruleVersion = string.Empty;
                Regex xccdfRuleRegex = new Regex(Properties.Resources.RegexXccdfRule);
                rule = xccdfRuleRegex.Match(rule).Value;
                if (rule.Contains("r"))
                {
                    ruleVersion = rule.Split('r')[1];
                    rule = rule.Split('r')[0];
                }
                sqliteCommand.Parameters["UniqueVulnerabilityIdentifier"].Value = rule;
                sqliteCommand.Parameters["VulnerabilityVersion"].Value = ruleVersion;
                while (xmlReader.Read())
                {
                    if (xmlReader.IsStartElement() && xmlReader.Name.Equals("cdf:result"))
                    { sqliteCommand.Parameters["Status"].Value = xmlReader.ObtainCurrentNodeValue(true).ToString().ToVulneratorStatus(); }
                    else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("cdf:rule-result"))
                    {
                        PrepareUniqueFinding(sqliteCommand);
                        return;
                    }
                }
                foreach (SQLiteParameter parameter in sqliteCommand.Parameters)
                {
                    if (!persistentParameters.Contains(parameter.ParameterName))
                    { parameter.Value = DBNull.Value; }
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to set XCCDF scan result.");
                throw exception;
            }
        }

        private void PrepareUniqueFinding(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.Parameters["LastObserved"].Value = lastObserved;
                sqliteCommand.Parameters["DeltaAnalysisIsRequired"].Value = "False";
                sqliteCommand.Parameters["FirstDiscovered"].Value = firstDiscovered;
                sqliteCommand.Parameters["FindingType"].Value = "XCCDF";
                sqliteCommand.Parameters["InstanceIdentifier"].Value =
                    $"{sqliteCommand.Parameters["DiscoveredHostName"].Value}_" +
                    $"{sqliteCommand.Parameters["UniqueVulnerabilityIdentifier"].Value}r{sqliteCommand.Parameters["VulnerabilityVersion"].Value}_" +
                    "XCCDF";
                databaseInterface.UpdateUniqueFinding(sqliteCommand);
                databaseInterface.InsertUniqueFinding(sqliteCommand);
            }
            catch (Exception exception)
            {
                LogWriter.LogError(
                    $"Unable to create a uniqueFinding record for plugin '{sqliteCommand.Parameters["UniqueVulnerabilityIdentifier"].Value}'.");
                throw exception;
            }
        }

        private void SetXccdfScoreFromSccFile(XmlReader xmlReader, SQLiteCommand sqliteCommand)
        {
            while (!xmlReader.Name.Equals("cdf:TestResult"))
            {
                if (!string.IsNullOrWhiteSpace(xmlReader.GetAttribute("system")) && xmlReader.GetAttribute("system").Equals("urn:xccdf:scoring:default"))
                {
                    sqliteCommand.Parameters["Score"].Value = xmlReader.ObtainCurrentNodeValue(true);
                    sqliteCommand.Parameters["ScanDate"].Value = DateTime.Now.ToShortDateString();
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
                LogWriter.LogError("Unable to retrieve description and/or IAC.");
                throw exception;
            }
        }

        #endregion

        #region Parse XCCDF File From OpenSCAP

        //TODO: Add this functionality

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
                LogWriter.LogError("Unable to generate a Stream from the provided string.");
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
                    xmlReaderSettings.ValidationFlags |= XmlSchemaValidationFlags.ProcessInlineSchema;
                    //xmlReaderSettings.ValidationFlags |= XmlSchemaValidationFlags.ProcessSchemaLocation;
                }
                return xmlReaderSettings;
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to generate XmlReaderSettings.");
                throw exception;
            }
        }

    }
}
