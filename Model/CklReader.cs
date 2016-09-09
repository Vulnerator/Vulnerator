using System;
using System.Collections.ObjectModel;
using System.Data;
using System.Data.SQLite;
using System.IO;
using System.Linq;
using log4net;
using System.Text.RegularExpressions;
using System.Xml;
using Vulnerator.Model;
using Vulnerator.ViewModel;

namespace Vulnerator
{
    /// <summary>
    /// Class housing all items required to parse DISA STIG *.ckl scan files.
    /// </summary>
    public class CklReader
    {
        private static DataTable joinedCciDatatable = CreateCciDataTable();
        private WorkingSystem workingSystem = new WorkingSystem();
        private string stigInfo = string.Empty;
        string versionInfo = string.Empty;
        string releaseInfo = string.Empty;
        private string groupName = string.Empty;
        private string fileNameWithoutPath = string.Empty;
        private string[] vulnerabilityTableColumns = new string[] { 
            "VulnId", "VulnTitle", "Description", "RiskStatement", "IaControl", "NistControl", "CPEs", "CrossReferences", 
            "IavmNumber", "FixText", "PluginPublishedDate", "PluginModifiedDate", "PatchPublishedDate", "Age", "RawRisk", "Impact", "RuleId" };
        private string[] uniqueFindingTableColumns = new string[] { "Comments", "FindingDetails", "PluginOutput", "LastObserved" };
        private bool UserPrefersHostName { get { return bool.Parse(ConfigAlter.ReadSettingsFromDictionary("rbHostIdentifier")); } }
        private static readonly ILog log = LogManager.GetLogger(typeof(Logger));

        /// <summary>
        /// Reads *.ckl files exported from the DISA STIG Viewer and writes the results to the appropriate DataTables.
        /// </summary>
        /// <param name="fileName">Name of *.ckl file to be parsed.</param>
        /// <param name="mitigationsList">List of mitigation items for vulnerabilities to be read against.</param>
        /// <param name="systemName">Name of the system that the mitigations check will be run against.</param>
        /// <returns>string Value</returns>
        public string ReadCklFile(string fileName, ObservableCollection<MitigationItem> mitigationsList, string systemName)
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
                using (SQLiteTransaction sqliteTransaction = FindingsDatabaseActions.sqliteConnection.BeginTransaction())
                {
                    using (SQLiteCommand sqliteCommand = FindingsDatabaseActions.sqliteConnection.CreateCommand())
                    {
                        sqliteCommand.Parameters.Add(new SQLiteParameter("FindingType", "CKL"));
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
                sqliteCommand.CommandText = "INSERT INTO Groups VALUES (NULL, @GroupName);";
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
                sqliteCommand.CommandText = "INSERT INTO FileNames VALUES (NULL, @FileName);";
                sqliteCommand.Parameters.Add(new SQLiteParameter("FileName", fileNameWithoutPath));
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                log.Error("Unable to insert new filename into FileNames.");
                throw exception;
            }
        }

        private void CreateAddAssetCommand(SQLiteCommand sqliteCommand)
        {
            try
            {
                if (!string.IsNullOrWhiteSpace(workingSystem.IpAddress))
                { sqliteCommand.Parameters.Add(new SQLiteParameter("IpAddress", workingSystem.IpAddress)); }
                else
                { sqliteCommand.Parameters.Add(new SQLiteParameter("IpAddress", "IP Not Provided")); }

                if (!string.IsNullOrWhiteSpace(workingSystem.HostName))
                { sqliteCommand.Parameters.Add(new SQLiteParameter("HostName", workingSystem.HostName)); }
                else
                { sqliteCommand.Parameters.Add(new SQLiteParameter("HostName", "Host Name Not Provided")); }

                if (UserPrefersHostName)
                { sqliteCommand.Parameters.Add(new SQLiteParameter("AssetIdToReport", sqliteCommand.Parameters["HostName"].Value)); }
                else
                { sqliteCommand.Parameters.Add(new SQLiteParameter("AssetIdToReport", sqliteCommand.Parameters["IpAddress"].Value)); }

                sqliteCommand.CommandText = "INSERT INTO Assets (AssetIdToReport, HostName, IpAddress, GroupIndex) VALUES " +
                    "(@AssetIdToReport, @HostName, @IpAddress, " +
                    "(SELECT GroupIndex FROM Groups WHERE GroupName = @GroupName));";
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                log.Error("Unable to insert new asset into Assets.");
                throw exception;
            }
        }

        private void CreateAddSourceCommand(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = "INSERT INTO VulnerabilitySources VALUES (NULL, @Source, @Version, @Release);";
                sqliteCommand.ExecuteNonQuery();
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
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("VulnId", ObtainAttributeDataNodeValue(xmlReader)));
                                    break;
                                }
                            case "Severity":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Impact", ConvertSeverityToImpact(ObtainAttributeDataNodeValue(xmlReader))));
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("RawRisk",
                                        ConvertImpactToRawRisk(sqliteCommand.Parameters["Impact"].Value.ToString())));
                                    break;
                                }
                            case "Rule_ID":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("RuleId", ObtainAttributeDataNodeValue(xmlReader)));
                                    break;
                                }
                            case "Rule_Title":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("VulnTitle", ObtainAttributeDataNodeValue(xmlReader)));
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
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("FixText", ObtainAttributeDataNodeValue(xmlReader)));
                                    break;
                                }
                            case "CCI_REF":
                                {
                                    string cciRef = string.Empty;
                                    string cciRefData = ObtainAttributeDataNodeValue(xmlReader);
                                    foreach (DataRow cciControlDataRow in joinedCciDatatable.AsEnumerable().Where(
                                        x => x["CciRef"].Equals(cciRefData)))
                                    { cciRef = cciRef + cciControlDataRow["CciControl"] + Environment.NewLine; }
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("NistControl", cciRef));
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("CciNumber", cciRefData));
                                    break;
                                }
                            case "STIGRef":
                                {
                                    if (!string.IsNullOrWhiteSpace(stigInfo))
                                    {
                                        stigInfo = ObtainAttributeDataNodeValue(xmlReader);
                                        if (stigInfo.Contains("Release") && string.IsNullOrWhiteSpace(releaseInfo))
                                        { releaseInfo = stigInfo.Split(new string[] { "Release:" }, StringSplitOptions.None)[1].Split(' ')[0].Trim(); }
                                        if (stigInfo.Contains("Benchmark"))
                                        { stigInfo = stigInfo.Split(new string[] { "::" }, StringSplitOptions.None)[0].Trim(); }
                                    }
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Source", stigInfo));
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Version", versionInfo));
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Release", releaseInfo));
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
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("FindingDetails", ObtainCurrentNodeValue(xmlReader)));
                                    break;
                                }
                            case "COMMENTS":
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

        private string SetInitialSqliteCommandText(string tableName)
        {
            try
            {
                switch (tableName)
                {
                    case "Vulnerability":
                        {
                            return "INSERT INTO Vulnerability () VALUES ();";
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
                                { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(37, "@" + sqliteParameter.ParameterName + ", "); }
                            }
                            foreach (SQLiteParameter sqliteParameter in sqliteCommand.Parameters)
                            {
                                if (Array.IndexOf(vulnerabilityTableColumns, sqliteParameter.ParameterName) >= 0)
                                { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(27, sqliteParameter.ParameterName + ", "); }
                            }
                            break;
                        }
                    case "UniqueFinding":
                        {
                            foreach (SQLiteParameter sqliteParameter in sqliteCommand.Parameters)
                            {
                                if (Array.IndexOf(uniqueFindingTableColumns, sqliteParameter.ParameterName) >= 0)
                                { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(126, "@" + sqliteParameter.ParameterName + ", "); }
                            }
                            foreach (SQLiteParameter sqliteParameter in sqliteCommand.Parameters)
                            {
                                if (Array.IndexOf(uniqueFindingTableColumns, sqliteParameter.ParameterName) >= 0)
                                { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(27, sqliteParameter.ParameterName + ", "); }
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
                return xmlReader.Value;
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
                return xmlReader.Value;
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
                log.Error("Unable to create CCI DataTable.");
                log.Debug("Exception details:", exception);
                throw;
            }
        }
    }
}
