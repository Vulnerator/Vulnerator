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
        DatabaseInterface databaseInterface = new DatabaseInterface();
        private string stigInfo = string.Empty;
        private string versionInfo = string.Empty;
        private string releaseInfo = string.Empty;
        private string techArea = string.Empty;
        private string webDbSite = string.Empty;
        private string webDbInstance = string.Empty;
        private string classification = string.Empty;
        private int hardwarePrimaryKey = 0;
        private int lastVulnerabilitySourceId = 0;
        private int lastVulnerabilityId = 0;
        private int groupPrimaryKey = 0;
        private int sourceFilePrimaryKey = 0;
        private bool deltaAnalysisRequired = false;
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
                        InsertSourceFile(sqliteCommand, file);
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
                if (!string.IsNullOrWhiteSpace(file.FileSystemName))
                { sqliteCommand.Parameters.Add(new SQLiteParameter("Group_Name", file.FileSystemName)); }
                else
                { sqliteCommand.Parameters.Add(new SQLiteParameter("Group_Name", "Unassigned")); }
                sqliteCommand.CommandText = Properties.Resources.SelectGroup;
                if (int.TryParse(Convert.ToString(sqliteCommand.ExecuteScalar()), out groupPrimaryKey))
                {
                    sqliteCommand.Parameters.Clear();
                    return;
                }
                sqliteCommand.CommandText = Properties.Resources.InsertGroup;
                sqliteCommand.ExecuteNonQuery();
                sqliteCommand.CommandText = "SELECT last_insert_rowid();";
                groupPrimaryKey = int.Parse(sqliteCommand.ExecuteScalar().ToString());
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
            try
            {
                sqliteCommand.Parameters.Add(new SQLiteParameter("Finding_Source_File_Name", file.FileName));
                sqliteCommand.CommandText = Properties.Resources.SelectUniqueFindingSourceFile;
                if (int.TryParse(Convert.ToString(sqliteCommand.ExecuteScalar()), out sourceFilePrimaryKey))
                {
                    sqliteCommand.Parameters.Clear();
                    return;
                }
                sqliteCommand.CommandText = Properties.Resources.InsertUniqueFindingSource;
                sqliteCommand.ExecuteNonQuery();
                sqliteCommand.Parameters.Clear();
                sqliteCommand.CommandText = "SELECT last_insert_rowid();";
                sourceFilePrimaryKey = int.Parse(sqliteCommand.ExecuteScalar().ToString());
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to insert unique finding source file \"{0}\".", file.FileName));
                throw exception;
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
                        InsertHardware(sqliteCommand);
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

        private void InsertHardware(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = Properties.Resources.SelectHardware;
                if (int.TryParse(Convert.ToString(sqliteCommand.ExecuteScalar()), out hardwarePrimaryKey))
                {
                    sqliteCommand.Parameters.Clear();
                    return;
                }
                sqliteCommand.Parameters.Add(new SQLiteParameter("Is_Virtual_Server", "False"));
                sqliteCommand.Parameters.Add(new SQLiteParameter("NIAP_Level", string.Empty));
                sqliteCommand.Parameters.Add(new SQLiteParameter("Manufacturer", string.Empty));
                sqliteCommand.Parameters.Add(new SQLiteParameter("ModelNumber", string.Empty));
                sqliteCommand.Parameters.Add(new SQLiteParameter("Is_IA_Enabled", string.Empty));
                sqliteCommand.Parameters.Add(new SQLiteParameter("SerialNumber", string.Empty));
                if (!sqliteCommand.Parameters.Contains("Role"))
                { sqliteCommand.Parameters.Add(new SQLiteParameter("Role", string.Empty)); }
                if (!sqliteCommand.Parameters.Contains("FQDN"))
                { sqliteCommand.Parameters.Add(new SQLiteParameter("FQDN", string.Empty)); }
                sqliteCommand.CommandText = Properties.Resources.InsertHardware;
                sqliteCommand.ExecuteNonQuery();
                sqliteCommand.CommandText = "SELECT last_insert_rowid();";
                hardwarePrimaryKey = int.Parse(sqliteCommand.ExecuteScalar().ToString());
                sqliteCommand.Parameters.Clear();
            }
            catch (Exception exception)
            {
                log.Error("Unable to insert hardware into database.");
                throw exception;
            }
        }

        private void ParseIpAndMacAddress(SQLiteCommand sqliteCommand, string parameter)
        {
            try
            {
                string[] regexArray = new string[]
                {
                    @"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$", //IPv4
                    @"(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9]))", //IPv6
                    @"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$" //MAC
                };
                foreach (string expression in regexArray)
                {
                    Regex regex = new Regex(expression);
                    foreach (Match match in regex.Matches(parameter))
                    {
                        switch (Array.IndexOf(regexArray, expression))
                        {
                            case 0:
                                {
                                    InsertAndMapIpMacAddress(sqliteCommand, match.ToString(), "IP_Addresses");
                                    break;
                                }
                            case 1:
                                {
                                    InsertAndMapIpMacAddress(sqliteCommand, match.ToString(), "IP_Addresses");
                                    break;
                                }
                            case 2:
                                {
                                    InsertAndMapIpMacAddress(sqliteCommand, match.ToString(), "MAC_Addresses");
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

        private void InsertAndMapIpMacAddress(SQLiteCommand sqliteCommand, string item, string table)
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
                sqliteCommand.CommandText = "SELECT last_insert_rowid();";
                int id = int.Parse(sqliteCommand.ExecuteScalar().ToString());
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
                {
                    sqliteCommand.Parameters.Add(new SQLiteParameter("Source_Name",ObtainCurrentNodeValue(xmlReader).Replace('_', ' ')));
                    sqliteCommand.Parameters.Add(new SQLiteParameter("Source_Version", string.Empty));
                    sqliteCommand.Parameters.Add(new SQLiteParameter("Source_Release", string.Empty));
                    lastVulnerabilitySourceId = databaseInterface.InsertVulnerabilitySource(sqliteCommand);
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
                            SQLiteCommand clonedSqliteCommand = (SQLiteCommand)sqliteCommand.Clone();
                            clonedSqliteCommand.CommandText = Properties.Resources.VerifyVulnerabilitySourceChange;
                            using (SQLiteDataReader sqliteDataReader = clonedSqliteCommand.ExecuteReader())
                            {
                                int commandVersion;
                                int commandRelease;
                                bool commandVersionPopulated = int.TryParse(sqliteCommand.Parameters["Source_Version"].Value.ToString(), out commandVersion);
                                bool commandReleasePopulated = int.TryParse(sqliteCommand.Parameters["Source_Release"].Value.ToString(), out commandRelease);
                                if (!sqliteDataReader.HasRows || !commandVersionPopulated || !commandReleasePopulated)
                                {
                                    lastVulnerabilitySourceId = databaseInterface.InsertVulnerabilitySource(sqliteCommand);
                                    return;
                                }
                                while (sqliteDataReader.Read())
                                {
                                    int readerVersion;
                                    int readerRelease;
                                    bool readerVersionPopulated = int.TryParse(sqliteDataReader["Source_Version"].ToString(), out readerVersion);
                                    bool readerReleasePopulated = int.TryParse(sqliteDataReader["Source_Release"].ToString(), out readerRelease);
                                    if (readerVersionPopulated && readerReleasePopulated && (commandVersion < readerVersion || commandRelease < readerRelease ))
                                    {
                                        lastVulnerabilitySourceId = int.Parse(sqliteDataReader["Vulnerability_Source_ID"].ToString());
                                        databaseInterface.UpdateVulnerabilitySource(sqliteCommand, lastVulnerabilitySourceId);
                                        sqliteCommand.Parameters.Clear();
                                        return;
                                    }
                                    else
                                    {
                                        sqliteCommand.Parameters.Clear();
                                        return;
                                    }
                                }
                            }
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
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Release", ruleRelease));
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
                        SQLiteCommand clonedSqliteCommand = (SQLiteCommand)sqliteCommand.Clone();
                        clonedSqliteCommand.CommandText = Properties.Resources.VerifyVulnerabilityChange;
                        if (sqliteCommand.Parameters.Contains("Release"))
                        {
                            clonedSqliteCommand.Parameters.Add(new SQLiteParameter("Vulnerability_Source_ID", lastVulnerabilitySourceId));
                            using (SQLiteDataReader sqliteDataReader = clonedSqliteCommand.ExecuteReader())
                            {
                                if (!sqliteDataReader.HasRows)
                                {
                                    lastVulnerabilityId = databaseInterface.InsertVulnerability(sqliteCommand, lastVulnerabilitySourceId);
                                    databaseInterface.MapVulnerabilityToCCI(sqliteCommand, ccis, lastVulnerabilityId);
                                }
                                while (sqliteDataReader.Read())
                                {
                                    if (int.Parse(sqliteDataReader["Release"].ToString()) < int.Parse(sqliteCommand.Parameters["Release"].Value.ToString()))
                                    {
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("Vulnerability_ID", sqliteDataReader["Vulnerability_ID"].ToString()));
                                        lastVulnerabilityId = databaseInterface.UpdateVulnerability(sqliteCommand);
                                        databaseInterface.MapVulnerabilityToCCI(sqliteCommand, ccis, lastVulnerabilityId);
                                        deltaAnalysisRequired = true;
                                    }
                                }
                            }
                        }
                        else
                        {
                            lastVulnerabilityId = databaseInterface.InsertVulnerability(sqliteCommand, lastVulnerabilitySourceId);
                            databaseInterface.MapVulnerabilityToCCI(sqliteCommand, ccis, lastVulnerabilityId);
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
                        InsertUniqueFinding(sqliteCommand);
                        ClearGlobals();
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

        private void InsertUniqueFinding(SQLiteCommand sqliteCommand)
        {

            try
            {
                sqliteCommand.Parameters.Add(new SQLiteParameter("Technology_Area", techArea));
                sqliteCommand.Parameters.Add(new SQLiteParameter("Web_DB_Site", webDbSite));
                sqliteCommand.Parameters.Add(new SQLiteParameter("Web_DB_Instance", webDbInstance));
                sqliteCommand.Parameters.Add(new SQLiteParameter("Last_Observed", DateTime.Now.ToLongDateString()));
                sqliteCommand.Parameters.Add(new SQLiteParameter("Finding_Source_File_ID", sourceFilePrimaryKey));
                sqliteCommand.Parameters.Add(new SQLiteParameter("Delta_Analysis_Required", deltaAnalysisRequired.ToString()));
                SQLiteCommand clonedCommand = (SQLiteCommand)sqliteCommand.Clone();
                clonedCommand.Parameters.Add(new SQLiteParameter("Hardware_ID", hardwarePrimaryKey));
                clonedCommand.Parameters.Add(new SQLiteParameter("Vulnerability_ID", lastVulnerabilityId));
                sqliteCommand.Parameters.Add(new SQLiteParameter("Approval_Status", "False"));
                clonedCommand.CommandText = Properties.Resources.SelectUniqueFinding;
                using (SQLiteDataReader sqliteDataReader = clonedCommand.ExecuteReader())
                {
                    while (sqliteDataReader.Read())
                    {
                        if (sqliteDataReader.HasRows)
                        {
                            sqliteCommand.Parameters.Add(new SQLiteParameter("Unique_Finding_ID", sqliteDataReader["Unique_Finding_ID"].ToString()));
                            sqliteCommand.CommandText = Properties.Resources.UpdateCklUniqueFinding;
                            sqliteCommand.ExecuteNonQuery();
                            sqliteCommand.Parameters.Clear();
                            return;
                        }
                    }
                }
                clonedCommand.CommandText = Properties.Resources.SelectFindingTypeId;
                clonedCommand.Parameters.Add(new SQLiteParameter("Finding_Type", "CKL"));
                using (SQLiteDataReader sqliteDataReader = clonedCommand.ExecuteReader())
                {
                    while (sqliteDataReader.Read())
                    {
                        if (sqliteDataReader.HasRows)
                        { sqliteCommand.Parameters.Add(new SQLiteParameter("Finding_Type_ID", sqliteDataReader["Finding_Type_ID"].ToString())); }
                    }
                }
                sqliteCommand.CommandText = Properties.Resources.InsertCklUniqueFinding;
                sqliteCommand.Parameters.Add(new SQLiteParameter("Hardware_ID", hardwarePrimaryKey));
                sqliteCommand.Parameters.Add(new SQLiteParameter("Vulnerability_ID", lastVulnerabilityId));
                sqliteCommand.Parameters.Add(new SQLiteParameter("First_Discovered", DateTime.Now.ToLongDateString()));
                sqliteCommand.Parameters.Add(new SQLiteParameter("Classification", classification));
                sqliteCommand.ExecuteNonQuery();
                sqliteCommand.Parameters.Clear();
            }
            catch (Exception exception)
            {
                log.Error("Unable to insert unique finding.");
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

        private void ClearGlobals()
        {
            stigInfo = string.Empty;
            versionInfo = string.Empty;
            releaseInfo = string.Empty;
            techArea = string.Empty;
            webDbSite = string.Empty;
            webDbInstance = string.Empty;
            classification = string.Empty;
            lastVulnerabilityId = 0;
            deltaAnalysisRequired = false;
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
