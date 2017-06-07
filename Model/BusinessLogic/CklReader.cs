using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SQLite;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.RegularExpressions;
using log4net;
using System.Xml;
using Vulnerator.Model.DataAccess;
using Vulnerator.Model.ModelHelper;
using Vulnerator.Model.Object;
using Vulnerator.ViewModel;

namespace Vulnerator.Model.BusinessLogic
{
    /// <summary>
    /// Class housing all items required to parse DISA STIG *.ckl scan files.
    /// </summary>
    public class CklReader
    {
        private Assembly assembly = Assembly.GetExecutingAssembly();
        private string stigInfo = string.Empty;
        private string versionInfo = string.Empty;
        private string releaseInfo = string.Empty;
        private string techArea = string.Empty;
        private string webDbSite = string.Empty;
        private string webDbInstance = string.Empty;
        private int referencePrimaryKey = 0;
        private int hardwarePrimaryKey = 0;
        private int lastVulnerabilitySourceId = 0;
        private int lastVulnerabilityId = 0;
        private int groupPrimaryKey = 0;
        private int sourceFilePrimaryKey = 0;
        private List<string> ccis = new List<string>();
        private static readonly ILog log = LogManager.GetLogger(typeof(Logger));

        /// <summary>
        /// Reads *.ckl files exported from the DISA STIG Viewer and writes the results to the appropriate DataTables.
        /// </summary>
        /// <param name="fileName">Name of *.ckl file to be parsed.</param>
        /// <param name="mitigationsList">List of mitigation items for vulnerabilities to be read against.</param>
        /// <param name="systemName">Name of the system that the mitigations check will be run against.</param>
        /// <returns>string Value</returns>
        public string ReadCklFile(Object.File file)
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
                        InsertGroup(sqliteCommand, file);
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

        private void InsertGroup(SQLiteCommand sqliteCommand, Object.File file)
        {
            try
            {
                sqliteCommand.CommandText = Properties.Resources.InsertGroup;
                sqliteCommand.Parameters.Add(new SQLiteParameter("Group_Name", file.FileSystemName));
                sqliteCommand.ExecuteNonQuery();
                sqliteCommand.CommandText = "SELECT last_insert_rowid();";
                groupPrimaryKey = (int)sqliteCommand.ExecuteScalar();
                sqliteCommand.Parameters.Clear();
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to insert group \"{0}\" into database.", file.FileSystemName));
                throw exception;
            }
        }

        private void InsertSourceFile(SQLiteCommand sqliteCommand, Object.File file)
        {

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
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Host_Name", ObtainCurrentNodeValue(xmlReader)));
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
                        InsertHardware(sqliteCommand);
                        if (!string.IsNullOrWhiteSpace(ip))
                        { ParseIpAndMacAddress(sqliteCommand, ip, "IP_Addresses"); }
                        if (!string.IsNullOrWhiteSpace(mac))
                        { ParseIpAndMacAddress(sqliteCommand, mac, "MAC_Addresses"); }
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to parse \"ASSET\" node.");
                throw exception;
            }
        }

        private void InsertHardware(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.Parameters.Add(new SQLiteParameter("Is_Virtual_Server", "False"));
                sqliteCommand.Parameters.Add(new SQLiteParameter("NIAP_Level", string.Empty));
                sqliteCommand.Parameters.Add(new SQLiteParameter("Manufacturer", string.Empty));
                sqliteCommand.Parameters.Add(new SQLiteParameter("ModelNumber", string.Empty));
                sqliteCommand.Parameters.Add(new SQLiteParameter("Is_IA_Enabled", string.Empty));
                sqliteCommand.Parameters.Add(new SQLiteParameter("SerialNumber", string.Empty));
                sqliteCommand.CommandText = Properties.Resources.InsertHardware;
                sqliteCommand.ExecuteNonQuery();
                sqliteCommand.CommandText = "SELECT last_insert_rowid();";
                hardwarePrimaryKey = (int)sqliteCommand.ExecuteScalar();
                sqliteCommand.Parameters.Clear();
            }
            catch (Exception exception)
            {
                log.Error("Unable to insert hardware into database.");
                throw exception;
            }
        }

        private void ParseIpAndMacAddress(SQLiteCommand sqliteCommand, string parameter, string table)
        {
            try
            {
                Regex regex = new Regex(",|;");
                if (regex.IsMatch(parameter))
                {
                    char[] delimiters = new char[] { ',', ';' };
                    foreach (char delimiter in delimiters)
                    {
                        if (parameter.Contains(delimiter))
                        {
                            string[] parameters = parameter.Split(delimiter).ToArray();
                            foreach (string item in parameters)
                            { InsertAndMapIpMacAddress(sqliteCommand, item, table); }
                        }
                    }
                    return;
                }
                else
                { InsertAndMapIpMacAddress(sqliteCommand, parameter, table); }
            }
            catch (Exception exception)
            {
                log.Error("Unable to parse IP / MAC Address.");
                throw exception;
            }
        }

        private void InsertAndMapIpMacAddress(SQLiteCommand sqliteCommand, string item, string table)
        {
            try
            {
                if (table.Equals("IP_Addresses"))
                { sqliteCommand.CommandText = Properties.Resources.InsertIpAddress; }
                else
                { sqliteCommand.CommandText = Properties.Resources.InsertMacAddress; }
                sqliteCommand.Parameters.Add(new SQLiteParameter("IP_Address", item));
                sqliteCommand.ExecuteNonQuery();
                sqliteCommand.CommandText = "SELECT last_insert_rowid();";
                int id = (int)sqliteCommand.ExecuteScalar();
                if (table.Equals("IP_Addresses"))
                {
                    sqliteCommand.CommandText = Properties.Resources.MapIpToHardware;
                    sqliteCommand.Parameters.Add(new SQLiteParameter("IP_Address_ID", id));
                }
                else
                {
                    sqliteCommand.CommandText = Properties.Resources.MapMacToHardware;
                    sqliteCommand.Parameters.Add(new SQLiteParameter("MAC_Address_ID", id));
                }
                sqliteCommand.Parameters.Add(new SQLiteParameter("Hardware_ID", hardwarePrimaryKey));
                sqliteCommand.ExecuteNonQuery();
                sqliteCommand.Parameters.Clear();
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
                { sqliteCommand.Parameters.Add(new SQLiteParameter("Source_Name",ObtainCurrentNodeValue(xmlReader).Replace('_', ' '))); }
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
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("Source_Name", ObtainStigInfoSubNodeValue(xmlReader)));
                                        break;
                                    }
                                case "version":
                                    {
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("Source_Version", ObtainStigInfoSubNodeValue(xmlReader)));
                                        break;
                                    }
                                case "releaseinfo":
                                    {
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("Source_Release", ObtainStigInfoSubNodeValue(xmlReader)));
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
                            InsertVulnerabilitySource(sqliteCommand);
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

        private void InsertVulnerabilitySource(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = Properties.Resources.InsertVulnerabilitySource;
                foreach (SQLiteParameter parameter in sqliteCommand.Parameters)
                {
                    if (sqliteCommand.Parameters.IndexOf(parameter) == 0)
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(55, "@" + parameter.ParameterName); }
                    else
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(55, "@" + parameter.ParameterName + ", "); }

                }
                foreach (SQLiteParameter parameter in sqliteCommand.Parameters)
                {
                    if (sqliteCommand.Parameters.IndexOf(parameter) == 0)
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(45, parameter.ParameterName); }
                    else
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(45, parameter.ParameterName + ", "); }
                }
                sqliteCommand.ExecuteNonQuery();
                sqliteCommand.Parameters.Clear();
                sqliteCommand.CommandText = "SELECT last_insert_rowid();";
                lastVulnerabilitySourceId = int.Parse(sqliteCommand.ExecuteScalar().ToString());
            }
            catch (Exception exception)
            {
                log.Error("Unable to insert vulnerability source.");
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
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Unique_Vulnerability_Identifier", ObtainAttributeDataNodeValue(xmlReader)));
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
                            default:
                                { break; }
                        }
                    }
                    else if (xmlReader.IsStartElement() && xmlReader.Name.Equals("STATUS"))
                    {
                        InsertVulnerability(sqliteCommand);
                        if (ccis.Count > 0)
                        { MapVulnerbailityToCCI(sqliteCommand); }
                        ParseUniqueFindingData(sqliteCommand, xmlReader);
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to parse \"VULN\" node.");
                throw exception;
            }
        }

        private void InsertVulnerability(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = Properties.Resources.InsertVulnerability;
                foreach (SQLiteParameter parameter in sqliteCommand.Parameters)
                {
                    if (sqliteCommand.Parameters.IndexOf(parameter) == 0)
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(50, "@" + parameter.ParameterName); }
                    else
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(50, "@" + parameter.ParameterName + ", "); }

                }
                foreach (SQLiteParameter parameter in sqliteCommand.Parameters)
                {
                    if (sqliteCommand.Parameters.IndexOf(parameter) == 0)
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(40, parameter.ParameterName); }
                    else
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(40, parameter.ParameterName + ", "); }
                }
                sqliteCommand.ExecuteNonQuery();
                sqliteCommand.CommandText = "SELECT last_insert_rowid();";
                lastVulnerabilityId = int.Parse(sqliteCommand.ExecuteScalar().ToString());
                sqliteCommand.Parameters.Clear();
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to insert vulnerability.", sqliteCommand.Parameters["Unique_Vulnerability_Identifier"].Value.ToString()));
                throw exception;
            }
        }

        private void MapVulnerbailityToCCI(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = Properties.Resources.MapVulnerabilityToCci;
                foreach (string cci in ccis)
                {
                    sqliteCommand.Parameters.Add(new SQLiteParameter("Vulnerability_ID", lastVulnerabilityId));
                    sqliteCommand.Parameters.Add(new SQLiteParameter("CCI", cci));
                    sqliteCommand.ExecuteNonQuery();
                    sqliteCommand.Parameters.Clear();
                }
                ccis.Clear();
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to map vulnerability to CCI \"{0}\".", sqliteCommand.Parameters["cci"].Value.ToString()));
                log.Debug("Exception details: " + exception);
            }
        }

        private void ParseUniqueFindingData(SQLiteCommand sqliteCommand, XmlReader xmlReader)
        {
            try
            {
                xmlReader.Read();
                sqliteCommand.Parameters.Add(new SQLiteParameter("Status", xmlReader.Value));
                while (xmlReader.Read())
                {
                    if (xmlReader.IsStartElement())
                    {
                        switch (xmlReader.Name)
                        {
                            case "FINDING_DETAILS":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Finding_Details", ObtainCurrentNodeValue(xmlReader)));
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

                    }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to parse unique finding data.");
                throw exception;
            }
        }

        private void InsertUniqueFinding(SQLiteCommand sqliteCommand)
        {

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

        public string DdlTextReader(string ddlResourceFile)
        {
            string ddlText = string.Empty;
            using (Stream stream = assembly.GetManifestResourceStream(ddlResourceFile))
            {
                using (StreamReader streamReader = new StreamReader(stream))
                { ddlText = streamReader.ReadToEnd(); }
            }
            return ddlText;
        }

        public Object.File ObtainIdentifiers(Object.File file)
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

        private bool IdentifierRequired(string fieldName, Object.File file)
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
