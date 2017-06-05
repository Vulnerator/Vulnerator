using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SQLite;
using System.IO;
using System.Linq;
using System.Reflection;
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
        private WorkingSystem workingSystem = new WorkingSystem();
        private string stigInfo = string.Empty;
        private string versionInfo = string.Empty;
        private string releaseInfo = string.Empty;
        private string groupName = string.Empty;
        private string fileNameWithoutPath = string.Empty;
        private int referencePrimaryKey = 0;
        private int hardwarePrimaryKey;
        private int vulnerabilityPrimaryKey;
        private string[] vulnerabilityTableColumns = new string[] { 
            "Unique_Vulnerability_Identifier", "STIG_V_ID", "Rule_Ver", "VulnerabilityFamilyOrClass", "Version", "Release", "Title", "Description", "Risk_Statement",
            "Fix_Text", "Published_Date", "Modified_Date", "Fix_Published_Date", "Raw_Risk", "Check_Content", "False_Positives", "False_Negatives", "Documentable",
            "Mitigations", "Potential_Impacts", "Third_Party_Tools", "Responsibility", "Severity_Override_Guidance" };
        private string[] uniqueFindingTableColumns = new string[] { "Tool_Generated_Output", "Comments", "Finding_Details", "Technical_Mitigation", "Proposed_Mitigation",
            "Predisposing_Conditions", "Impact", "Likelihood", "Severity", "Risk", "Residual_Risk", "First_Discovered", "Last_Observed", "Approval_Status",
            "Data_Entry_Date", "Data_Expiration_Date", "Delta_Analysis_Required", "Severity_Override", "Severity_Override_Justification", "Technology_Area", "Web_DB_Site",
            "Web_DB_Instance", "Classification" };
        private bool UserPrefersHost_Name { get { return bool.Parse(ConfigAlter.ReadSettingsFromDictionary("rbHostIdentifier")); } }
        private bool RevisionThreeSelected { get { return bool.Parse(ConfigAlter.ReadSettingsFromDictionary("revisionThreeRadioButton")); } }
        private bool RevisionFourSelected { get { return bool.Parse(ConfigAlter.ReadSettingsFromDictionary("revisionFourRadioButton")); } }
        private bool AppendixASelected { get { return bool.Parse(ConfigAlter.ReadSettingsFromDictionary("nistAppendixA_CheckBox")); } }
        private static readonly ILog log = LogManager.GetLogger(typeof(Logger));

        /// <summary>
        /// Reads *.ckl files exported from the DISA STIG Viewer and writes the results to the appropriate DataTables.
        /// </summary>
        /// <param name="fileName">Name of *.ckl file to be parsed.</param>
        /// <param name="mitigationsList">List of mitigation items for vulnerabilities to be read against.</param>
        /// <param name="systemName">Name of the system that the mitigations check will be run against.</param>
        /// <returns>string Value</returns>
        public string ReadCklFile(string fileName, string systemName)
        {
            try
            {
                if (fileName.IsFileInUse())
                {
                    log.Error(fileName + " is in use; please close any open instances and try again.");
                    return "Failed; File In Use";
                }
                fileNameWithoutPath = Path.GetFileName(fileName);
                groupName = systemName;
                if (DatabaseBuilder.sqliteConnection.State.ToString().Equals("Closed"))
                { DatabaseBuilder.sqliteConnection.Open(); }
                using (SQLiteTransaction sqliteTransaction = DatabaseBuilder.sqliteConnection.BeginTransaction())
                {
                    using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                    {
                        sqliteCommand.Parameters.Add(new SQLiteParameter("Finding_Type", "CKL"));
                        CreateAddGroupNameCommand(systemName, sqliteCommand);
                        CreateAddFileNameCommand(fileNameWithoutPath, sqliteCommand);
                        XmlReaderSettings xmlReaderSettings = GenerateXmlReaderSettings();
                        using (XmlReader xmlReader = XmlReader.Create(fileName, xmlReaderSettings))
                        {
                            while (xmlReader.Read())
                            {
                                if (xmlReader.IsStartElement())
                                {
                                    switch (xmlReader.Name)
                                    {
                                        case "ASSET":
                                            {
                                                workingSystem = ObtainSystemInformation(xmlReader);
                                                CreateAddAssetCommand(sqliteCommand);
                                                break;
                                            }
                                        case "STIG_INFO":
                                            {
                                                ObtainStigInfo(xmlReader);
                                                break;
                                            }
                                        case "VULN":
                                            {
                                                ParseVulnNode(xmlReader,sqliteCommand);
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
                log.Error("Unable to process CKL file.");
                log.Debug("Exception details:", exception);
                return "Failed; See Log";
            }
        }

        private void CreateAddGroupNameCommand(string groupName, SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = "INSERT INTO Groups VALUES (NULL, @GroupName, 0, NULL, NULL);";
                sqliteCommand.Parameters.Add(new SQLiteParameter("GroupName", groupName));
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                log.Error("Unable to insert GroupName into Groups.");
                throw exception;
            }
        }

        private void CreateAddFileNameCommand(string fileName, SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = "INSERT INTO SourceFiles VALUES (NULL, @FileName);";
                sqliteCommand.Parameters.Add(new SQLiteParameter("FileName", fileNameWithoutPath));
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                log.Error("Unable to insert new filename into Source_Files.");
                throw exception;
            }
        }

        private void CreateAddIpAddressCommand(SQLiteCommand sqliteCommand)
        {
            try
            {
                List<string> ipAddresses;
                sqliteCommand.Parameters.Add(new SQLiteParameter("Hardware_ID", hardwarePrimaryKey));
                if (workingSystem.IpAddress.Contains("'"))
                {
                    ipAddresses = workingSystem.IpAddress.Split('\'').ToList();
                    foreach (string ip in ipAddresses)
                    {
                        sqliteCommand.Parameters.Add(new SQLiteParameter("IpAddress", ip));
                        InsertHardwareIpAddresses(sqliteCommand);
                    }
                }
                else
                {
                    sqliteCommand.Parameters.Add(new SQLiteParameter("IpAddress", workingSystem.IpAddress));
                    InsertHardwareIpAddresses(sqliteCommand);
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to process IP Address(es).");
                throw exception;
            }
        }

        private void InsertHardwareIpAddresses(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = "INSERT INTO IpAddresses VALUES (NULL, IpAddress);";
                sqliteCommand.ExecuteNonQuery();
                sqliteCommand.CommandText = "SELECT last_insert_rowid();";
                int ipId = int.Parse(sqliteCommand.ExecuteScalar().ToString());
                sqliteCommand.Parameters.Add(new SQLiteParameter("IP_Address_ID", ipId));
                sqliteCommand.CommandText = "INSERT INTO HardwareIpAddresses VALUES (@Hardware_ID, @IP_Address_ID);";
                sqliteCommand.ExecuteNonQuery();
                sqliteCommand.Parameters.Remove("IP_Address_ID");
            }
            catch (Exception exception)
            {
                log.Error("Unable to insert IP Address(es) into IpAddresses and / or HardwareIpAddresses.");
                throw exception;
            }
        }

        private void CreateAddAssetCommand(SQLiteCommand sqliteCommand)
        {
            try
            {
                if (!string.IsNullOrWhiteSpace(workingSystem.HostName))
                { sqliteCommand.Parameters.Add(new SQLiteParameter("Host_Name", workingSystem.HostName)); }
                else
                { sqliteCommand.Parameters.Add(new SQLiteParameter("Host_Name", "Host Name Not Provided")); }
                sqliteCommand.Parameters.Add(new SQLiteParameter("FQDN", string.Empty));
                sqliteCommand.Parameters.Add(new SQLiteParameter("Is_Virtual_Server", "False"));
                sqliteCommand.Parameters.Add(new SQLiteParameter("NIAP_Level", string.Empty));
                sqliteCommand.Parameters.Add(new SQLiteParameter("Manufacturer", string.Empty));
                sqliteCommand.Parameters.Add(new SQLiteParameter("ModelNumber", string.Empty));
                sqliteCommand.Parameters.Add(new SQLiteParameter("Is_IA_Enabled", "False"));
                sqliteCommand.Parameters.Add(new SQLiteParameter("SerialNumber", string.Empty));
                sqliteCommand.Parameters.Add(new SQLiteParameter("Role", workingSystem.Role));
                sqliteCommand.Parameters.Add(new SQLiteParameter("LifecycleStatus", string.Empty));
                sqliteCommand.CommandText = Properties.Resources.InsertHardware;
                sqliteCommand.ExecuteNonQuery();
                sqliteCommand.CommandText = "SELECT last_insert_rowid();";
                hardwarePrimaryKey = int.Parse(sqliteCommand.ExecuteScalar().ToString());
            }
            catch (Exception exception)
            {
                log.Error("Unable to insert new system into Hardware.");
                throw exception;
            }
        }

        private void CreateAddSourceCommand(SQLiteCommand sqliteCommand)
        {
            try
            {
                bool sourceExists = false;
                sqliteCommand.CommandText = "SELECT * FROM VulnerabilitySources WHERE Source_Name = @Source AND Source_Version = @Version AND Source_Release = @Release;";
                using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
                {
                    if (sqliteDataReader.HasRows)
                    { sourceExists = true; }
                }
                if (!sourceExists)
                {
                    sqliteCommand.CommandText = "INSERT INTO VulnerabilitySources VALUES (NULL, @Source, @Version, @Release);";
                    sqliteCommand.ExecuteNonQuery();
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to insert new source into VulnerabilitySources.");
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

        private WorkingSystem ObtainSystemInformation(XmlReader xmlReader)
        {
            try
            {
                WorkingSystem workingsystem = new WorkingSystem();

                while (xmlReader.Read())
                {
                    if (xmlReader.IsStartElement())
                    {
                        switch (xmlReader.Name)
                        {
                            case "HOST_NAME":
                                {
                                    workingsystem.HostName = ObtainCurrentNodeValue(xmlReader);
                                    break;
                                }
                            case "HOST_IP":
                                {
                                    workingsystem.IpAddress = ObtainCurrentNodeValue(xmlReader);
                                    break;
                                }
                            case "ROLE":
                                {
                                    workingsystem.Role = ObtainCurrentNodeValue(xmlReader);
                                    break;
                                }
                            case "ASSET_TYPE":
                                {
                                    workingsystem.AssetType = ObtainCurrentNodeValue(xmlReader);
                                    break;
                                }
                            case "HOST_FQDN":
                                {
                                    workingsystem.FQDN = ObtainCurrentNodeValue(xmlReader);
                                    break;
                                }
                            case "TECH_AREA":
                                {
                                    workingsystem.TechArea = ObtainCurrentNodeValue(xmlReader);
                                    break;
                                }
                            case "WEB_DB_SITE":
                                {
                                    workingsystem.Site = ObtainCurrentNodeValue(xmlReader);
                                    break;
                                }
                            case "WEB_DB_INSTANCE":
                                {
                                    workingsystem.Instance = ObtainCurrentNodeValue(xmlReader);
                                    break;
                                }
                            default:
                                { break; }
                        }
                    }
                    else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("ASSET"))
                    { break; }
                }

                return workingsystem;
            }
            catch (Exception exception)
            {
                log.Error("Unable to obtain host system information.");
                throw exception;
            }
        }

        private void ObtainStigInfo(XmlReader xmlReader)
        {
            try
            {
                xmlReader.Read();
                if (xmlReader.Name.Equals("STIG_TITLE"))
                {
                    stigInfo = ObtainCurrentNodeValue(xmlReader).Replace('_', ' ');
                    if (!stigInfo.Contains("STIG"))
                    { stigInfo = stigInfo + " STIG"; }
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
                                        stigInfo = ObtainStigInfoSubNodeValue(xmlReader);
                                        if (!stigInfo.Contains ("STIG") || !stigInfo.Contains("Security Technical Implementation Benchmark"))
                                        { stigInfo = stigInfo + " STIG"; }
                                        break;
                                    }
                                case "version":
                                    {
                                        versionInfo = ObtainStigInfoSubNodeValue(xmlReader);
                                        break;
                                    }
                                case "releaseinfo":
                                    {
                                        releaseInfo = ObtainStigInfoSubNodeValue(xmlReader);
                                        break;
                                    }
                                default:
                                    { break; }
                            }
                        }
                        else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("STIG_INFO"))
                        { break; }
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to obtain STIG information.");
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
                        stigInfoValue = xmlReader.Value;
                        if (stigInfoPortion.Equals("version"))
                        {
                            if (!string.IsNullOrWhiteSpace(stigInfoValue))
                            { stigInfoValue = "V" + stigInfoValue; }
                            else
                            { stigInfoValue = "V?"; }
                        }
                        if (stigInfoPortion.Equals("releaseinfo"))
                        {
                            if (!string.IsNullOrWhiteSpace(stigInfoValue))
                            { stigInfoValue = "R" + stigInfoValue.Split(' ')[1].Split(' ')[0].Trim(); }
                            else
                            { stigInfoValue = "R?"; }
                        }
                        return stigInfoValue;
                    }
                    else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("SI_DATA"))
                    {
                        if (string.IsNullOrWhiteSpace(stigInfoValue))
                        {
                            switch (stigInfoPortion)
                            {
                                case "version":
                                    { return "V?"; }
                                case "releaseinfo":
                                    { return "R?"; }
                                default:
                                    { return string.Empty; }
                            }
                        }
                        return stigInfoValue;
                    }
                    else
                    { continue; }
                }
                return "Read too far!";
            }
            catch (Exception exception)
            {
                log.Error("Unable to obtain the value from the STIG Info sub-node");
                throw exception;
            }
        }

        private void ParseVulnNode(XmlReader xmlReader, SQLiteCommand sqliteCommand)
        {
            try
            {
                while (xmlReader.Read())
                {
                    ParseStigDataNodes(xmlReader, sqliteCommand);
                    ParseRemainingVulnSubNodes(xmlReader, sqliteCommand);
                    CreateAddSourceCommand(sqliteCommand);
                    sqliteCommand.CommandText = SetInitialSqliteCommandText("Vulnerability");
                    sqliteCommand.CommandText = InsertParametersIntoSqliteCommandText(sqliteCommand, "Vulnerability");
                    sqliteCommand.ExecuteNonQuery();
                    SetStandardParameters(sqliteCommand);
                    sqliteCommand.CommandText = SetInitialSqliteCommandText("UniqueFinding");
                    sqliteCommand.CommandText = InsertParametersIntoSqliteCommandText(sqliteCommand, "UniqueFinding");
                    sqliteCommand.ExecuteNonQuery();
                    return;
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to parse Vuln node.");
                throw exception;
            }
        }

        private void ParseStigDataNodes(XmlReader xmlReader, SQLiteCommand sqliteCommand)
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
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("STIG_V_ID", ObtainAttributeDataNodeValue(xmlReader)));
                                    break;
                                }
                            case "Severity":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Impact", ConvertSeverityToImpact(ObtainAttributeDataNodeValue(xmlReader))));
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Raw_Risk",
                                        ConvertImpactToRawRisk(sqliteCommand.Parameters["Impact"].Value.ToString())));
                                    break;
                                }
                            case "Rule_ID":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Unique_Vulnerability_Identifier", ObtainAttributeDataNodeValue(xmlReader)));
                                    break;
                                }
                            case "Rule_Ver":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Rule_Ver", ObtainAttributeDataNodeValue(xmlReader)));
                                    break;
                                }
                            case "Rule_Title":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Title", ObtainAttributeDataNodeValue(xmlReader)));
                                    break;
                                }
                            case "Vuln_Discuss":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Description", ObtainAttributeDataNodeValue(xmlReader)));
                                    break;
                                }
                            case "IA_Controls":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("IaControl", ObtainAttributeDataNodeValue(xmlReader)));
                                    break;
                                }
                            case "Fix_Text":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Fix_Text", ObtainAttributeDataNodeValue(xmlReader)));
                                    break;
                                }
                            case "CCI_REF":
                                {
                                    
                                    break;
                                }
                            case "STIGRef":
                                {
                                    if (string.IsNullOrWhiteSpace(stigInfo))
                                    {
                                        stigInfo = ObtainAttributeDataNodeValue(xmlReader);
                                        if (stigInfo.Contains("Release") && string.IsNullOrWhiteSpace(releaseInfo))
                                        { releaseInfo = stigInfo.Split(new string[] { "Release:" }, StringSplitOptions.None)[1].Split(' ')[0].Trim(); }
                                        if (stigInfo.Contains("Benchmark"))
                                        { stigInfo = stigInfo.Split(new string[] { "::" }, StringSplitOptions.None)[0].Trim(); }
                                    }
                                    if (string.IsNullOrWhiteSpace(versionInfo))
                                    { versionInfo = "V?"; }
                                    if (string.IsNullOrWhiteSpace(releaseInfo))
                                    { releaseInfo = "R?"; }
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Source", stigInfo));
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Version", versionInfo));
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Release", releaseInfo));
                                    break;
                                }
                            case "Check_Content":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Check_Content", ObtainAttributeDataNodeValue(xmlReader)));
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
                                    if (bool.Parse(ObtainAttributeDataNodeValue(xmlReader)))
                                    { sqliteCommand.Parameters.Add(new SQLiteParameter("Documentable", 1)); }
                                    else
                                    { sqliteCommand.Parameters.Add(new SQLiteParameter("Documentable", 0)); }
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
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Responsibility", ObtainAttributeDataNodeValue(xmlReader)));
                                    break;
                                }
                            case "Severity_Override_Guidance":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Severity_Override_Guidance", ObtainAttributeDataNodeValue(xmlReader)));
                                    break;
                                }
                            case "Check_Content_Ref":
                                {
                                    InsertReference(sqliteCommand, ObtainAttributeDataNodeValue(xmlReader));
                                    break;
                                }
                            case "Classification":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Classification", ObtainAttributeDataNodeValue(xmlReader)));
                                    break;
                                }
                            default:
                                { break; }
                        }
                    }
                    else if (xmlReader.IsStartElement() && xmlReader.Name.Equals("STATUS"))
                    { return; }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to parse STIG data node.");
                throw exception;
            }
        }

        private void InsertReference(SQLiteCommand sqlitecommand, string reference)
        {
            try
            {
                sqlitecommand.Parameters.Add(new SQLiteParameter("Reference", reference));
                sqlitecommand.Parameters.Add(new SQLiteParameter("ReferenceType", "STIG"));
                sqlitecommand.CommandText = "INSERT INTO VulnerabilityReferences VALUES (NULL, @Reference, @ReferenceType);";
                sqlitecommand.ExecuteNonQuery();
                sqlitecommand.CommandText = "SELECT last_insert_rowid()";
                referencePrimaryKey = int.Parse(sqlitecommand.ExecuteScalar().ToString());
            }
            catch (Exception exception)
            {
                log.Error("Unable to insert new STIG Check_Content_Reference value.");
                throw exception;
            }
        }

        private void ParseRemainingVulnSubNodes(XmlReader xmlReader, SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.Parameters.Add(new SQLiteParameter("Status", MakeStatusUseable(ObtainCurrentNodeValue(xmlReader))));
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
                            case "SEVERITY_OVERRIDE_JUSTIFICATION":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Comments", ObtainCurrentNodeValue(xmlReader)));
                                    break;
                                }
                            default:
                                { break; }
                        }
                    }
                    else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("VULN"))
                    { return; }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to parse Vuln sub-node.");
                throw exception;
            }
        }

        private void SetStandardParameters(SQLiteCommand sqliteCommand)
        {
            sqliteCommand.Parameters.Add(new SQLiteParameter("Approval_Status", "False"));
            sqliteCommand.Parameters.Add(new SQLiteParameter("Delta_Analysis_Required", "False"));
            sqliteCommand.Parameters.Add(new SQLiteParameter("First_Discovered", DateTime.Now.ToString()));
            sqliteCommand.Parameters.Add(new SQLiteParameter("Last_Observed", DateTime.Now.ToString()));
        }

        private string SetInitialSqliteCommandText(string tableName)
        {
            try
            {
                switch (tableName)
                {
                    case "Vulnerability":
                        {
                            return "INSERT INTO Vulnerabilities () VALUES ();";
                        }
                    case "UniqueFinding":
                        {
                            return "INSERT INTO UniqueFindings (Finding_Type_ID, Source_ID, Status_ID, " +
                                "Source_File_ID, Vulnerability_ID, Hardware_ID) VALUES (" +
                                "(SELECT Finding_Type_ID FROM FindingTypes WHERE Finding_Type = @Finding_Type), " +
                                "(SELECT Source_ID FROM VulnerabilitySources WHERE Source_Name = @Source AND Source_Version = @Version AND Source_Release = @Release), " +
                                "(SELECT Status_ID FROM FindingStatuses WHERE Status = @Status), " +
                                "(SELECT Source_File_ID FROM SourceFiles WHERE Source_File_Name = @FileName), " +
                                "(SELECT Vulnerability_ID FROM Vulnerabilities WHERE Unique_Vulnerability_Identifier = @Unique_Vulnerability_Identifier), " +
                                "(SELECT Hardware_ID FROM Hardware WHERE Host_Name = @Host_Name));";
                        }
                    default:
                        { return string.Empty; }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to set initial SQLite command text.");
                throw exception;
            }
        }

        private string InsertParametersIntoSqliteCommandText(SQLiteCommand sqliteCommand, string tableName)
        {
            try
            {
                switch (tableName)
                {
                    case "Vulnerability":
                        {
                            foreach (SQLiteParameter sqliteParameter in sqliteCommand.Parameters)
                            {
                                if (Array.IndexOf(vulnerabilityTableColumns, sqliteParameter.ParameterName) >= 0)
                                { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(39, "@" + sqliteParameter.ParameterName + ", "); }
                            }
                            foreach (SQLiteParameter sqliteParameter in sqliteCommand.Parameters)
                            {
                                if (Array.IndexOf(vulnerabilityTableColumns, sqliteParameter.ParameterName) >= 0)
                                { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(29, sqliteParameter.ParameterName + ", "); }
                            }
                            break;
                        }
                    case "UniqueFinding":
                        {
                            foreach (SQLiteParameter sqliteParameter in sqliteCommand.Parameters)
                            {
                                if (Array.IndexOf(uniqueFindingTableColumns, sqliteParameter.ParameterName) >= 0)
                                { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(122, "@" + sqliteParameter.ParameterName + ", "); }
                            }
                            foreach (SQLiteParameter sqliteParameter in sqliteCommand.Parameters)
                            {
                                if (Array.IndexOf(uniqueFindingTableColumns, sqliteParameter.ParameterName) >= 0)
                                { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(28, sqliteParameter.ParameterName + ", "); }
                            }
                            break;
                        }
                    default:
                        { break; }
                }

                return sqliteCommand.CommandText.Replace(", )", ")");
            }
            catch (Exception exception)
            {
                log.Error("Unable to insert parameters into SQLite command text.");
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
                log.Error("Unable to obtain Attribute Data node value.");
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

        private string ConvertImpactToRawRisk(string severity)
        {
            try
            {
                switch (severity)
                {
                    case "High":
                        { return "I"; }
                    case "Medium":
                        { return "II"; }
                    case "Low":
                        { return "III"; }
                    case "Unknown":
                        { return "Unknown"; }
                    default:
                        { return "Unknown"; }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to convert impact to raw risk.");
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

        public Model.Object.File ObtainIdentifiers(Model.Object.File file)
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
                log.Error("Unable to verify host name exists.");
                log.Debug("Exception details:", exception);
                return file;
            }
        }

        private bool IdentifierRequired(string fieldName, Model.Object.File file)
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
