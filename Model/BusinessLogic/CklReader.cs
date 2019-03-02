using log4net;
using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.Linq;
using System.Reflection;
using System.Text.RegularExpressions;
using System.Xml;
using Vulnerator.Model.DataAccess;
using Vulnerator.Helper;
using Vulnerator.Model.Object;

namespace Vulnerator.Model.BusinessLogic
{
    /// <summary>
    /// Class housing all items required to parse DISA STIG *.ckl scan files.
    /// </summary>
    public class CklReader
    {
        private Assembly assembly = Assembly.GetExecutingAssembly();
        DatabaseInterface databaseInterface = new DatabaseInterface();
        private string stigInfo = string.Empty;
        private string versionInfo = string.Empty;
        private string releaseInfo = string.Empty;
        private string techArea = string.Empty;
        private string webDbSite = string.Empty;
        private string webDbInstance = string.Empty;
        private string classification = string.Empty;
        private List<string> ccis = new List<string>();
        private static readonly ILog log = LogManager.GetLogger(typeof(Logger));
        private string[] persistentParameters = new string[] {
            "Group_Name", "Finding_Source_File_Name", "Source_Name", "Source_Version", "Source_Release", "Host_Name", "Scan_IP", "FQDN", "NetBIOS", "Finding_Type"
        };

        /// <summary>
        /// Reads *.ckl files exported from the DISA STIG Viewer and writes the results to the appropriate DataTables.
        /// </summary>
        /// <param name="fileName">Name of *.ckl file to be parsed.</param>
        /// <param name="mitigationsList">List of mitigation items for vulnerabilities to be read against.</param>
        /// <param name="systemName">Name of the system that the mitigations check will be run against.</param>
        /// <returns>string Value</returns>
        public string ReadCklFile(File file)
        {
            try
            {
                if (file.FilePath.IsFileInUse())
                {
                    log.Error(file.FileName + " is in use; please close any open instances and try again.");
                    return "Failed; File In Use";
                }
                if (DatabaseBuilder.sqliteConnection.State.ToString().Equals("Closed"))
                { DatabaseBuilder.sqliteConnection.Open(); }
                using (SQLiteTransaction sqliteTransaction = DatabaseBuilder.sqliteConnection.BeginTransaction())
                {
                    using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                    {
                        databaseInterface.InsertParameterPlaceholders(sqliteCommand);
                        sqliteCommand.Parameters["Group_Name"].Value = "All";
                        databaseInterface.InsertParsedFileSource(sqliteCommand, file);
                        XmlReaderSettings xmlReaderSettings = GenerateXmlReaderSettings();
                        using (XmlReader xmlReader = XmlReader.Create(file.FilePath, xmlReaderSettings))
                        {
                            while (xmlReader.Read())
                            {
                                if (xmlReader.IsStartElement())
                                {
                                    switch (xmlReader.Name)
                                    {
                                        case "ASSET":
                                            {
                                                ParseAssetNode(xmlReader, sqliteCommand);
                                                break;
                                            }
                                        case "STIG_INFO":
                                            {
                                                ParseStigInfoNode(xmlReader, sqliteCommand);
                                                break;
                                            }
                                        case "VULN":
                                            {
                                                ParseVulnNode(xmlReader, sqliteCommand);
                                                break;
                                            }
                                        default:
                                            { break; }
                                    }
                                }
                            }
                        }
                        databaseInterface.DeleteRemovedVulnerabilities(sqliteCommand);
                    }
                    sqliteTransaction.Commit();
                }
                return "Processed";
            }
            catch (Exception exception)
            {
                log.Error($"Unable to process CKL file {file.FileName}.");
                log.Debug("Exception details:", exception);
                return "Failed; See Log";
            }
            finally
            { DatabaseBuilder.sqliteConnection.Close(); }
        }

        private void ParseAssetNode(XmlReader xmlReader, SQLiteCommand sqliteCommand)
        {
            try
            {
                string ip = string.Empty;
                string mac = string.Empty;
                while (xmlReader.Read())
                {
                    if (xmlReader.IsStartElement())
                    {
                        switch (xmlReader.Name)
                        {
                            case "ROLE":
                                {
                                    sqliteCommand.Parameters["Role"].Value = xmlReader.ObtainCurrentNodeValue(true);
                                    break;
                                }
                            case "HOST_NAME":
                                {
                                    string hostName = xmlReader.ObtainCurrentNodeValue(true);
                                    if (!string.IsNullOrWhiteSpace(hostName) && !hostName.Equals("HOST NAME"))
                                    {
                                        sqliteCommand.Parameters["Host_Name"].Value = hostName;
                                        sqliteCommand.Parameters["Displayed_Host_Name"].Value = hostName;
                                    }
                                    break;
                                }
                            case "HOST_IP":
                                {
                                    ip = xmlReader.ObtainCurrentNodeValue(true);
                                    break;
                                }
                            case "HOST_MAC":
                                {
                                    mac = xmlReader.ObtainCurrentNodeValue(true);
                                    break;
                                }
                            case "HOST_FQDN":
                                {
                                    sqliteCommand.Parameters["FQDN"].Value = xmlReader.ObtainCurrentNodeValue(true);
                                    break;
                                }
                            case "TECH_AREA":
                                {
                                    techArea = xmlReader.ObtainCurrentNodeValue(true);
                                    break;
                                }
                            case "WEB_DB_SITE":
                                {
                                    webDbSite = xmlReader.ObtainCurrentNodeValue(true);
                                    break;
                                }
                            case "WEB_DB_INSTANCE":
                                {
                                    webDbInstance = xmlReader.ObtainCurrentNodeValue(true);
                                    break;
                                }
                            default:
                                { break; }
                        }
                    }
                    else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("ASSET"))
                    {
                        sqliteCommand.Parameters["Is_Virtual_Server"].Value = "False";
                        databaseInterface.InsertHardware(sqliteCommand);
                        if (!string.IsNullOrWhiteSpace(ip) && !ip.Equals("IP"))
                        { ParseIpAndMacAddress(sqliteCommand, ip); }
                        if (!string.IsNullOrWhiteSpace(mac) && !mac.Equals("MAC"))
                        { ParseIpAndMacAddress(sqliteCommand, mac); }
                        return;
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to parse \"ASSET\" node.");
                throw exception;
            }
        }

        private void ParseIpAndMacAddress(SQLiteCommand sqliteCommand, string parameter)
        {
            try
            {
                string[] regexArray = new string[] { Properties.Resources.RegexIPv4, Properties.Resources.RegexIPv6, Properties.Resources.RegexMAC };
                foreach (string expression in regexArray)
                {
                    Regex regex = new Regex(expression);
                    foreach (Match match in regex.Matches(parameter))
                    {
                        switch (Array.IndexOf(regexArray, expression))
                        {
                            case 0:
                                {
                                    PrepareIpAndMacAddress(sqliteCommand, match.ToString(), "IP_Addresses");
                                    break;
                                }
                            case 1:
                                {
                                    PrepareIpAndMacAddress(sqliteCommand, match.ToString(), "IP_Addresses");
                                    break;
                                }
                            case 2:
                                {
                                    PrepareIpAndMacAddress(sqliteCommand, match.ToString(), "MAC_Addresses");
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
                log.Error("Unable to parse IP / MAC Address.");
                throw exception;
            }
        }

        private void PrepareIpAndMacAddress(SQLiteCommand sqliteCommand, string item, string table)
        {
            try
            {
                if (table.Equals("IP_Addresses"))
                {
                    sqliteCommand.Parameters["IP_Address"].Value = item;
                    databaseInterface.InsertAndMapIpAddress(sqliteCommand);
                }
                else
                {
                    sqliteCommand.Parameters["MAC_Address"].Value = item;
                    databaseInterface.InsertAndMapMacAddress(sqliteCommand);
                }
            }
            catch (Exception exception)
            {
                log.Error($"Unable to insert IP / MAC address \"{item}\" into database.");
                throw exception;
            }
        }

        private void ParseStigInfoNode(XmlReader xmlReader, SQLiteCommand sqliteCommand)
        {
            try
            {
                xmlReader.Read();
                if (xmlReader.Name.Equals("STIG_TITLE"))
                {
                    string sourceName = xmlReader.ObtainCurrentNodeValue(true).Replace('_', ' ');
                    sourceName = sourceName.ToSanitizedSource();
                    sqliteCommand.Parameters["Source_Name"].Value = sourceName;
                    databaseInterface.InsertVulnerabilitySource(sqliteCommand);
                }
                else
                {
                    while (xmlReader.Read())
                    {
                        if (xmlReader.IsStartElement() && xmlReader.Name.Equals("SID_NAME"))
                        {
                            xmlReader.Read();
                            switch (xmlReader.Value)
                            {
                                case "title":
                                    {
                                        string sourceName = ObtainStigInfoSubNodeValue(xmlReader).Replace('_', ' ');
                                        sourceName = sourceName.ToSanitizedSource();
                                        sqliteCommand.Parameters["Source_Name"].Value = sourceName;
                                        break;
                                    }
                                case "version":
                                    {
                                        sqliteCommand.Parameters["Source_Version"].Value = ObtainStigInfoSubNodeValue(xmlReader);
                                        break;
                                    }
                                case "releaseinfo":
                                    {
                                        string release = ObtainStigInfoSubNodeValue(xmlReader);
                                        if (release.Contains(" "))
                                        { sqliteCommand.Parameters["Source_Release"].Value = release.Split(' ')[1]; }
                                        else
                                        { sqliteCommand.Parameters["Source_Release"].Value = release; }
                                        break;
                                    }
                                case "stigid":
                                    {
                                        sqliteCommand.Parameters["Source_Secondary_Identifier"].Value = ObtainStigInfoSubNodeValue(xmlReader);
                                        break;
                                    }
                                case "description":
                                    {
                                        sqliteCommand.Parameters["Source_Description"].Value = ObtainStigInfoSubNodeValue(xmlReader);
                                        break;
                                    }
                                case "filename":
                                    {
                                        sqliteCommand.Parameters["Vulnerability_Source_File_Name"].Value = ObtainStigInfoSubNodeValue(xmlReader);
                                        break;
                                    }
                                default:
                                    { break; }
                            }
                        }
                        else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("STIG_INFO"))
                        {
                            databaseInterface.UpdateVulnerabilitySource(sqliteCommand);
                            databaseInterface.InsertVulnerabilitySource(sqliteCommand);
                            databaseInterface.MapHardwareToVulnerabilitySource(sqliteCommand);
                            return;
                        }
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to parse \"STIG_INFO\" node.");
                throw exception;
            }
        }

        private void ParseVulnNode(XmlReader xmlReader, SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.Parameters["Modified_Date"].Value = DateTime.Now.ToShortDateString();
                while (xmlReader.Read())
                {
                    if (xmlReader.IsStartElement() && xmlReader.Name.Equals("VULN_ATTRIBUTE"))
                    {
                        xmlReader.Read();
                        switch (xmlReader.Value)
                        {
                            case "Vuln_Num":
                                {
                                    sqliteCommand.Parameters["Vulnerability_Group_ID"].Value = ObtainAttributeDataNodeValue(xmlReader);
                                    break;
                                }
                            case "Severity":
                                {
                                    sqliteCommand.Parameters["Raw_Risk"].Value = ObtainAttributeDataNodeValue(xmlReader).ToRawRisk();
                                    break;
                                }
                            case "Group_Title":
                                {
                                    sqliteCommand.Parameters["Vulnerability_Group_Title"].Value = ObtainAttributeDataNodeValue(xmlReader);
                                    break;
                                }
                            case "Rule_ID":
                                {
                                    string rule = ObtainAttributeDataNodeValue(xmlReader);
                                    string ruleRelease = string.Empty;
                                    if (rule.Contains("_"))
                                    { rule = rule.Split('_')[0]; }
                                    if (rule.Contains("r"))
                                    {
                                        ruleRelease = rule.Split('r')[1];
                                        rule = rule.Split('r')[0];
                                    }
                                    sqliteCommand.Parameters["Unique_Vulnerability_Identifier"].Value = rule;
                                    sqliteCommand.Parameters["Vulnerability_Version"].Value = ruleRelease;
                                    break;
                                }
                            case "Rule_Ver":
                                {
                                    sqliteCommand.Parameters["Secondary_Vulnerability_Identifier"].Value = ObtainAttributeDataNodeValue(xmlReader);
                                    break;
                                }
                            case "Rule_Title":
                                {
                                    sqliteCommand.Parameters["Vulnerability_Title"].Value = ObtainAttributeDataNodeValue(xmlReader);
                                    break;
                                }
                            case "Vuln_Discuss":
                                {
                                    sqliteCommand.Parameters["Vulnerability_Description"].Value = ObtainAttributeDataNodeValue(xmlReader);
                                    break;
                                }
                            case "Check_Content":
                                {
                                    sqliteCommand.Parameters["Check_Content"].Value = ObtainAttributeDataNodeValue(xmlReader);
                                    break;
                                }
                            case "Fix_Text":
                                {
                                    sqliteCommand.Parameters["Fix_Text"].Value = ObtainAttributeDataNodeValue(xmlReader);
                                    break;
                                }
                            case "False_Positives":
                                {
                                    sqliteCommand.Parameters["False_Positives"].Value = ObtainAttributeDataNodeValue(xmlReader);
                                    break;
                                }
                            case "False_Negatives":
                                {
                                    sqliteCommand.Parameters["False_Negatives"].Value = ObtainAttributeDataNodeValue(xmlReader);
                                    break;
                                }
                            case "Documentable":
                                {
                                    sqliteCommand.Parameters["Documentable"].Value = ObtainAttributeDataNodeValue(xmlReader);
                                    break;
                                }
                            case "Mitigations":
                                {
                                    sqliteCommand.Parameters["Mitigations"].Value = ObtainAttributeDataNodeValue(xmlReader);
                                    break;
                                }
                            case "Potential_Impacts":
                                {
                                    sqliteCommand.Parameters["Potential_Impacts"].Value = ObtainAttributeDataNodeValue(xmlReader);
                                    break;
                                }
                            case "Third_Party_Tools":
                                {
                                    sqliteCommand.Parameters["Third_Party_Tools"].Value = ObtainAttributeDataNodeValue(xmlReader);
                                    break;
                                }
                            case "Mitigation_Control":
                                {
                                    sqliteCommand.Parameters["Mitigation_Control"].Value = ObtainAttributeDataNodeValue(xmlReader);
                                    break;
                                }
                            case "Responsibility":
                                {
                                    break;
                                }
                            case "Security_Override_Guidance":
                                {
                                    sqliteCommand.Parameters["Security_Override_Guidance"].Value = ObtainAttributeDataNodeValue(xmlReader);
                                    break;
                                }
                            case "CCI_REF":
                                {
                                    ccis.Add(ObtainAttributeDataNodeValue(xmlReader).Replace("CCI-", string.Empty));
                                    break;
                                }
                            case "Class":
                                {
                                    classification = ObtainAttributeDataNodeValue(xmlReader);
                                    break;
                                }
                            default:
                                { break; }
                        }
                    }
                    else if (xmlReader.IsStartElement() && xmlReader.Name.Equals("STATUS"))
                    {
                        switch (databaseInterface.CompareVulnerabilityVersions(sqliteCommand))
                        {
                            case "Record Not Found":
                                {
                                    databaseInterface.InsertVulnerability(sqliteCommand);
                                    databaseInterface.MapVulnerabilityToSource(sqliteCommand);
                                    break;
                                }
                            case "Ingested Version Is Newer":
                                {
                                    databaseInterface.UpdateVulnerability(sqliteCommand);
                                    databaseInterface.UpdateDeltaAnalysisFlags(sqliteCommand);
                                    break;
                                }
                            case "Existing Version Is Newer":
                                {
                                    databaseInterface.UpdateVulnerabilityDates(sqliteCommand);
                                    sqliteCommand.Parameters["Delta_Analysis_Required"].Value = "True";
                                    break;
                                }
                            case "Identical Versions":
                                {
                                    databaseInterface.UpdateVulnerabilityDates(sqliteCommand);
                                    break;
                                }
                            default:
                                { break; }
                        }
                        ParseUniqueFindingData(sqliteCommand, xmlReader);
                        if (ccis.Count > 0)
                        {
                            foreach (string cci in ccis)
                            {
                                sqliteCommand.Parameters["CCI"].Value = cci;
                                databaseInterface.MapVulnerabilityToCci(sqliteCommand);
                                sqliteCommand.Parameters["CCI"].Value = string.Empty;
                            }
                            ccis.Clear();
                        }
                        
                        foreach (SQLiteParameter parameter in sqliteCommand.Parameters)
                        {
                            if (!persistentParameters.Contains(parameter.ParameterName))
                            { parameter.Value = string.Empty; }
                        }
                        return;
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to parse \"VULN\" node.");
                throw exception;
            }
        }

        private void ParseUniqueFindingData(SQLiteCommand sqliteCommand, XmlReader xmlReader)
        {
            try
            {
                xmlReader.Read();
                sqliteCommand.Parameters["Status"].Value = xmlReader.Value.ToVulneratorStatus();
                while (xmlReader.Read())
                {
                    if (xmlReader.IsStartElement())
                    {
                        switch (xmlReader.Name)
                        {
                            case "FINDING_DETAILS":
                                {
                                    string nodeValue = xmlReader.ObtainCurrentNodeValue(true);
                                    if (nodeValue.Contains("<cdf:"))
                                    {
                                        sqliteCommand.Parameters["Tool_Generated_Output"].Value = nodeValue;
                                        sqliteCommand.Parameters["Finding_Details"].Value = string.Empty;
                                    }
                                    else
                                    {
                                        sqliteCommand.Parameters["Finding_Details"].Value = nodeValue;
                                        sqliteCommand.Parameters["Tool_Generated_Output"].Value = string.Empty;
                                    }
                                    break;
                                }
                            case "COMMENTS":
                                {
                                    sqliteCommand.Parameters["Comments"].Value = xmlReader.ObtainCurrentNodeValue(true);
                                    break;
                                }
                            case "SEVERITY_OVERRIDE":
                                {
                                    sqliteCommand.Parameters["Severity_Override"].Value = xmlReader.ObtainCurrentNodeValue(true);
                                    break;
                                }
                            case "SEVERITY_JUSTIFICATION":
                                {
                                    sqliteCommand.Parameters["Severity_Override_Justification"].Value = xmlReader.ObtainCurrentNodeValue(true);
                                    break;
                                }
                            default:
                                { break; }
                        }
                    }
                    else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("VULN"))
                    {
                        PrepareUniqueFinding(sqliteCommand);
                        return;
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to parse unique finding data.");
                throw exception;
            }
        }

        private void PrepareUniqueFinding(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.Parameters["Technology_Area"].Value = techArea;
                sqliteCommand.Parameters["Web_DB_Site"].Value = webDbSite;
                sqliteCommand.Parameters["Web_DB_Instance"].Value = webDbInstance;
                sqliteCommand.Parameters["Last_Observed"].Value = DateTime.Now.ToShortDateString();
                if (string.IsNullOrWhiteSpace(sqliteCommand.Parameters["Delta_Analysis_Required"].Value.ToString()))
                { sqliteCommand.Parameters["Delta_Analysis_Required"].Value = "False"; }
                sqliteCommand.Parameters["Approval_Status"].Value = "Not Approved";
                sqliteCommand.Parameters["First_Discovered"].Value = DateTime.Now.ToShortDateString();
                sqliteCommand.Parameters["Classification"].Value = classification;
                sqliteCommand.Parameters["Finding_Type"].Value = "CKL";
                databaseInterface.UpdateUniqueFinding(sqliteCommand);
                databaseInterface.InsertUniqueFinding(sqliteCommand);
            }
            catch (Exception exception)
            {
                log.Error(
                    $"Unable to create a Unique Finding record for plugin \"{sqliteCommand.Parameters["Unique_Vulnerability_Identifier"].Value.ToString()}\".");
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
                xmlReaderSettings.ValidationFlags = System.Xml.Schema.XmlSchemaValidationFlags.ProcessInlineSchema;
                xmlReaderSettings.ValidationFlags = System.Xml.Schema.XmlSchemaValidationFlags.ProcessSchemaLocation;
                return xmlReaderSettings;
            }
            catch (Exception exception)
            {
                log.Error("Unable to generate XmlReaderSettings.");
                throw exception;
            }
        }

        private string ObtainStigInfoSubNodeValue(XmlReader xmlReader)
        {
            try
            {
                string stigInfoPortion = xmlReader.Value;
                string stigInfoValue = string.Empty;
                while (xmlReader.Read())
                {
                    if (xmlReader.IsStartElement() && xmlReader.Name.Equals("SID_DATA"))
                    {
                        xmlReader.Read();
                        return xmlReader.Value;
                    }
                    else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("SI_DATA"))
                    { return string.Empty; }
                    else
                    { continue; }
                }
                return "Read too far!";
            }
            catch (Exception exception)
            {
                log.Error("Unable to obtain the value from the \"STIG_INFO\" sub-node");
                throw exception;
            }
        }

        private string ObtainAttributeDataNodeValue(XmlReader xmlReader)
        {
            try
            {
                while (!xmlReader.Name.Equals("ATTRIBUTE_DATA"))
                { xmlReader.Read(); }
                xmlReader.Read();
                string value = xmlReader.Value;
                value = value.Replace("&gt", ">");
                value = value.Replace("&lt", "<");
                return value;
            }
            catch (Exception exception)
            {
                log.Error("Unable to obtain \"ATTRIBUTE_DATA\" node value.");
                throw exception;
            }
        }

        private void ClearGlobals()
        {
            stigInfo = string.Empty;
            versionInfo = string.Empty;
            releaseInfo = string.Empty;
            techArea = string.Empty;
            webDbSite = string.Empty;
            webDbInstance = string.Empty;
            classification = string.Empty;
    }

        public File ObtainIdentifiers(File file)
        {
            try
            {
                XmlReaderSettings xmlReaderSettings = GenerateXmlReaderSettings();
                using (XmlReader xmlReader = XmlReader.Create(file.FilePath, xmlReaderSettings))
                {
                    while (xmlReader.Read())
                    {
                        if (xmlReader.IsStartElement())
                        {
                            switch (xmlReader.Name)
                            {
                                case "HOST_NAME":
                                    {
                                        file.SetFileHostName(xmlReader.ObtainCurrentNodeValue(true));
                                        break;
                                    }
                                case "HOST_IP":
                                    {
                                        file.SetFileIpAddress(xmlReader.ObtainCurrentNodeValue(true));
                                        break;
                                    }
                                case "HOST_MAC":
                                    {
                                        file.SetFileMacAddress(xmlReader.ObtainCurrentNodeValue(true));
                                        break;
                                    }
                                default:
                                    { break; }
                            }
                        }
                        else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("ASSET"))
                        { break; }
                    }
                }
                bool hostname = IdentifierRequired("HostName", file);
                bool ipAddress = IdentifierRequired("IpAddress", file);
                bool macAddress = IdentifierRequired("MacAddress", file);
                if (!hostname || !ipAddress || !macAddress)
                { file.IdentifiersProvided = "False"; }
                return file;
            }
            catch (Exception exception)
            {
                log.Error($"Unable to verify host \"{file.FileHostName}\" - \"{file.FileIpAddress}\" exists.");
                log.Debug("Exception details:", exception);
                return file;
            }
        }

        private bool IdentifierRequired(string fieldName, File file)
        {
            bool value = true;
            switch (fieldName)
            {
                case "HostName":
                    {
                        if (Properties.Settings.Default.CklRequiresHostName)
                        {
                            if (string.IsNullOrWhiteSpace(file.FileHostName) || file.FileHostName.Contains("HOST NAME"))
                            { value = false; }
                        }
                        break;
                    }
                case "IpAddress":
                    {
                        if (Properties.Settings.Default.CklRequiresIpAddress)
                        {
                            if (string.IsNullOrWhiteSpace(file.FileIpAddress) || file.FileIpAddress.Contains("IP"))
                            { value = false; }
                        }
                        break;
                    }
                case "MacAddress":
                    {
                        if (Properties.Settings.Default.CklrequiresMacAddress)
                        {
                            if (string.IsNullOrWhiteSpace(file.FileMacAddress) || file.FileMacAddress.Contains("MAC"))
                            { value = false; }
                        }
                        break;
                    }
                default:
                    { break; }
            }
            return value;
        }
    }
}
