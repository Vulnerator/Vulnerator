using log4net;
using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.Reflection;
using System.Text.RegularExpressions;
using System.Xml;
using Vulnerator.Model.DataAccess;
using Vulnerator.Model.ModelHelper;
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
                        InsertParameterPlaceholders(sqliteCommand);
                        databaseInterface.InsertGroup(sqliteCommand, file);
                        databaseInterface.InsertParsedFile(sqliteCommand, file);
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
                    }
                    sqliteTransaction.Commit();
                }
                DatabaseBuilder.sqliteConnection.Close();
                return "Processed";
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to process CKL file {0}.", file.FileName));
                log.Debug("Exception details:", exception);
                return "Failed; See Log";
            }
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
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Role", ObtainCurrentNodeValue(xmlReader)));
                                    break;
                                }
                            case "HOST_NAME":
                                {
                                    string hostName = ObtainCurrentNodeValue(xmlReader);
                                    if (!string.IsNullOrWhiteSpace(hostName) && !hostName.Equals("HOST NAME"))
                                    { sqliteCommand.Parameters.Add(new SQLiteParameter("Host_Name", hostName)); }
                                    else
                                    { sqliteCommand.Parameters.Add(new SQLiteParameter("Host_Name", "Unassigned")); }
                                    break;
                                }
                            case "HOST_IP":
                                {
                                    ip = ObtainCurrentNodeValue(xmlReader);
                                    break;
                                }
                            case "HOST_MAC":
                                {
                                    mac = ObtainCurrentNodeValue(xmlReader);
                                    break;
                                }
                            case "HOST_FQDN":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("FQDN", ObtainCurrentNodeValue(xmlReader)));
                                    break;
                                }
                            case "TECH_AREA":
                                {
                                    techArea = ObtainCurrentNodeValue(xmlReader);
                                    break;
                                }
                            case "WEB_DB_SITE":
                                {
                                    webDbSite = ObtainCurrentNodeValue(xmlReader);
                                    break;
                                }
                            case "WEB_DB_INSTANCE":
                                {
                                    webDbInstance = ObtainCurrentNodeValue(xmlReader);
                                    break;
                                }
                            default:
                                { break; }
                        }
                    }
                    else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("ASSET"))
                    {
                        sqliteCommand.Parameters.Add(new SQLiteParameter("Is_Virtual_Server", "False"));
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
                    sqliteCommand.CommandText = Properties.Resources.InsertIpAddress;
                    sqliteCommand.Parameters.Add(new SQLiteParameter("IP_Address", item));
                }
                else
                {
                    sqliteCommand.CommandText = Properties.Resources.InsertMacAddress;
                    sqliteCommand.Parameters.Add(new SQLiteParameter("MAC_Address", item));
                }
                sqliteCommand.ExecuteNonQuery();
                if (table.Equals("IP_Addresses"))
                { databaseInterface.InsertAndMapIpAddress(sqliteCommand); }
                else
                { databaseInterface.InsertAndMapMacAddress(sqliteCommand); }
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to insert IP / MAC address \"{0}\" into database.", item));
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
                    string sourceName = ObtainCurrentNodeValue(xmlReader).Replace('_', ' ');
                    sourceName = SanitizeSourceName(sourceName);
                    sqliteCommand.Parameters.Add(new SQLiteParameter("Source_Name",sourceName));
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
                                        sourceName = SanitizeSourceName(sourceName);
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("Source_Name", sourceName));
                                        break;
                                    }
                                case "version":
                                    {
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("Source_Version", ObtainStigInfoSubNodeValue(xmlReader)));
                                        break;
                                    }
                                case "releaseinfo":
                                    {
                                        string release = ObtainStigInfoSubNodeValue(xmlReader);
                                        if (release.Contains(" "))
                                        { sqliteCommand.Parameters.Add(new SQLiteParameter("Source_Release", release.Split(' ')[1])); }
                                        else
                                        { sqliteCommand.Parameters.Add(new SQLiteParameter("Source_Release", release)); }
                                        break;
                                    }
                                case "stigid":
                                    {
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("Source_Secondary_Identifier", ObtainStigInfoSubNodeValue(xmlReader)));
                                        break;
                                    }
                                case "description":
                                    {
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("Source_Description", ObtainStigInfoSubNodeValue(xmlReader)));
                                        break;
                                    }
                                case "filename":
                                    {
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("Vulnerability_Source_File_Name", ObtainStigInfoSubNodeValue(xmlReader)));
                                        break;
                                    }
                                default:
                                    { break; }
                            }
                        }
                        else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("STIG_INFO"))
                        {
                            databaseInterface.UpdateVulnerabilitySource(sqliteCommand, "CKL");
                            databaseInterface.InsertVulnerabilitySource(sqliteCommand);
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
                while (xmlReader.Read())
                {
                    if (xmlReader.IsStartElement() && xmlReader.Name.Equals("VULN_ATTRIBUTE"))
                    {
                        xmlReader.Read();
                        switch (xmlReader.Value)
                        {
                            case "Vuln_Num":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Vulnerability_Group_ID", ObtainAttributeDataNodeValue(xmlReader)));
                                    break;
                                }
                            case "Severity":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Raw_Risk", ConvertSeverityToRawRisk(ObtainAttributeDataNodeValue(xmlReader))));
                                    break;
                                }
                            case "Group_Title":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Vulnerability_Group_Title", ObtainAttributeDataNodeValue(xmlReader)));
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
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Unique_Vulnerability_Identifier", rule));
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Vulnerablity_Version", ruleRelease));
                                    break;
                                }
                            case "Rule_Ver":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Secondary_Vulnerability_Identifier", ObtainAttributeDataNodeValue(xmlReader)));
                                    break;
                                }
                            case "Rule_Title":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Vulnerability_Title", ObtainAttributeDataNodeValue(xmlReader)));
                                    break;
                                }
                            case "Vuln_Discuss":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Description", ObtainAttributeDataNodeValue(xmlReader)));
                                    break;
                                }
                            case "Check_Content":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Check_Content", ObtainAttributeDataNodeValue(xmlReader)));
                                    break;
                                }
                            case "Fix_Text":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Fix_Text", ObtainAttributeDataNodeValue(xmlReader)));
                                    break;
                                }
                            case "False_Positives":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("False_Positives", ObtainAttributeDataNodeValue(xmlReader)));
                                    break;
                                }
                            case "False_Negatives":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("False_Negatives", ObtainAttributeDataNodeValue(xmlReader)));
                                    break;
                                }
                            case "Documentable":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Documentable", ObtainAttributeDataNodeValue(xmlReader)));
                                    break;
                                }
                            case "Mitigations":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Mitigations", ObtainAttributeDataNodeValue(xmlReader)));
                                    break;
                                }
                            case "Potential_Impacts":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Potential_Impacts", ObtainAttributeDataNodeValue(xmlReader)));
                                    break;
                                }
                            case "Third_Party_Tools":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Third_Party_Tools", ObtainAttributeDataNodeValue(xmlReader)));
                                    break;
                                }
                            case "Mitigation_Control":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Mitigation_Control", ObtainAttributeDataNodeValue(xmlReader)));
                                    break;
                                }
                            case "Responsibility":
                                {
                                    break;
                                }
                            case "Security_Override_Guidance":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Security_Override_Guidance", ObtainAttributeDataNodeValue(xmlReader)));
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
                        databaseInterface.UpdateVulnerability(sqliteCommand);
                        databaseInterface.InsertVulnerability(sqliteCommand);
                        if (ccis.Count > 0)
                        {
                            foreach (string cci in ccis)
                            {
                                sqliteCommand.Parameters["CCI"].Value = cci;
                                databaseInterface.MapVulnerabilityToCci(sqliteCommand);
                                sqliteCommand.Parameters["CCI"].Value = string.Empty;
                            }
                        }
                        ParseUniqueFindingData(sqliteCommand, xmlReader);
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
                sqliteCommand.Parameters.Add(new SQLiteParameter("Status", MakeStatusUseable(xmlReader.Value)));
                while (xmlReader.Read())
                {
                    if (xmlReader.IsStartElement())
                    {
                        switch (xmlReader.Name)
                        {
                            case "FINDING_DETAILS":
                                {
                                    string nodeValue = ObtainCurrentNodeValue(xmlReader);
                                    if (nodeValue.Contains("<cdf:"))
                                    {
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("Tool_Generated_Output", nodeValue));
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("Finding_Details", string.Empty));
                                    }
                                    else
                                    {
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("Finding_Details", nodeValue));
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("Tool_Generated_Output", string.Empty));
                                    }
                                    break;
                                }
                            case "COMMENTS":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Comments", ObtainCurrentNodeValue(xmlReader)));
                                    break;
                                }
                            case "SEVERITY_OVERRIDE":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Severity_Override", ObtainCurrentNodeValue(xmlReader)));
                                    break;
                                }
                            case "SEVERITY_JUSTIFICATION":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Severity_Override_Justification", ObtainCurrentNodeValue(xmlReader)));
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
                sqliteCommand.Parameters.Add(new SQLiteParameter("Technology_Area", techArea));
                sqliteCommand.Parameters.Add(new SQLiteParameter("Web_DB_Site", webDbSite));
                sqliteCommand.Parameters.Add(new SQLiteParameter("Web_DB_Instance", webDbInstance));
                sqliteCommand.Parameters.Add(new SQLiteParameter("Last_Observed", DateTime.Now.ToShortDateString()));
                sqliteCommand.Parameters.Add(new SQLiteParameter("Delta_Analysis_Required", "False"));
                sqliteCommand.Parameters.Add(new SQLiteParameter("Approval_Status", "Not Approved"));
                sqliteCommand.Parameters.Add(new SQLiteParameter("First_Discovered", DateTime.Now.ToShortDateString()));
                sqliteCommand.Parameters.Add(new SQLiteParameter("Classification", classification));
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
                        { return "?"; }
                    default:
                        { return "?"; }
                }
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to convert severity \"{0}\" to raw risk.", severity));
                throw exception;
            }
        }

        private string MakeStatusUseable(string status)
        {
            try
            {
                switch (status)
                {
                    case "NotAFinding":
                        { return "Completed"; }
                    case "Not_Reviewed":
                        { return "Not Reviewed"; }
                    case "Open":
                        { return "Ongoing"; }
                    case "Not_Applicable":
                        { return "Not Applicable"; }
                    default:
                        { return status; }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to parse status to a usable state.");
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
                                        file.SetFileHostName(ObtainCurrentNodeValue(xmlReader));
                                        break;
                                    }
                                case "HOST_IP":
                                    {
                                        file.SetFileIpAddress(ObtainCurrentNodeValue(xmlReader));
                                        break;
                                    }
                                case "HOST_MAC":
                                    {
                                        file.SetFileMacAddress(ObtainCurrentNodeValue(xmlReader));
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
                log.Error(string.Format("Unable to verify host \"{0}\" - \"{1}\" exists.", file.FileHostName, file.FileIpAddress));
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
                    "Unique_Finding_ID", "Tool_Generated_Output", "Comments", "Finding_Details", "Technical_Mitigation",
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
                    "CCI"
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
    }
}
