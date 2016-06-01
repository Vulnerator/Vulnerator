using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Data;
using System.Data.SQLite;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Xml;
using System.Xml.Linq;
using Vulnerator.ViewModel;

namespace Vulnerator.Model
{
    /// <summary>
    /// Class housing all items required to parse ACAS *.nessus scan files.
    /// </summary>
    public class AcasNessusReader
    {
        private string dateTimeFormat = "ddd MMM d HH:mm:ss yyyy";
        private string[] vulnerabilityTableColumns = new string[] { 
            "VulnId", "VulnTitle", "Description", "RiskStatement", "IaControl", "CciReference", "CPEs", "CrossReferences", 
            "IavmNumber", "FixText", "PluginPublishedDate", "PluginModifiedDate", "PatchPublishedDate", "Age", "RawRisk", "Impact", "RuleId" };
        private string[] uniqueFindingTableColumns = new string[] { "Comments", "FindingDetails", "PluginOutput", "LastObserved" };

        /// <summary>
        /// Reads *.nessus files exported from within ACAS and writes the results to the appropriate DataTables.
        /// </summary>
        /// <param name="fileName">Name of *.nessus file to be parsed.</param>
        /// <param name="mitigationsList">List of mitigation items for vulnerabilities to be read against.</param>
        /// <param name="systemName">Name of the system that the mitigations check will be run against.</param>
        /// <returns>String Value</returns>
        public string ReadAcasNessusFile(string fileName, ObservableCollection<MitigationItem> mitigationsList, string systemName)
        {
            try
            {                
                if (fileName.IsFileInUse())
                {
                    WriteLog.DiagnosticsInformation(fileName, "File is in use; please close any open instances and try again.", string.Empty);
                    return "Failed; File In Use";
                }

                ParseNessusWithXmlReader(systemName, fileName);

                return "Processed";
            }
            catch (Exception exception)
            {
                WriteLog.LogWriter(exception, fileName);
                return "Failed; See Log";
            }
        }

        private void ParseNessusWithXmlReader(string systemName, string fileName)
        {
            using (SQLiteTransaction sqliteTransaction = FindingsDatabaseActions.sqliteConnection.BeginTransaction())
            {
                CreateAddFileNameCommand(fileName);
                CreateAddGroupNameCommand(systemName);
                CreateAddSourceCommand();
                XmlReaderSettings xmlReaderSettings = GenerateXmlReaderSettings();
                using (XmlReader xmlReader = XmlReader.Create(fileName, xmlReaderSettings))
                {
                    WorkingSystem workingSystem = new WorkingSystem();
                    while (xmlReader.Read())
                    {
                        if (xmlReader.IsStartElement() && xmlReader.Name == "HostProperties")
                        {
                            workingSystem = new WorkingSystem();
                            workingSystem = ParseHostInformation(xmlReader, workingSystem);
                            CreateAddAssetCommand(workingSystem, systemName);
                        }
                        else if (xmlReader.IsStartElement() && xmlReader.Name == "ReportItem")
                        {
                            using (SQLiteCommand sqliteCommand = FindingsDatabaseActions.sqliteConnection.CreateCommand())
                            {
                                ParseVulnerabilityInformation(xmlReader, sqliteCommand, workingSystem);
                                if (sqliteCommand.Parameters["VulnId"].Value.Equals("19506") || 
                                    sqliteCommand.Parameters["VulnId"].Value.Equals("21745") || 
                                    sqliteCommand.Parameters["VulnId"].Value.Equals("26917"))
                                { SetCredentialedStatusFallback(sqliteCommand); }
                                sqliteCommand.Parameters.Add(new SQLiteParameter("FileName", Path.GetFileName(fileName)));
                                sqliteCommand.Parameters.Add(new SQLiteParameter("GroupName", systemName));
                                sqliteCommand.CommandText = SetInitialSqliteCommandText("Vulnerability");
                                sqliteCommand.CommandText = InsertParametersIntoSqliteCommandText(sqliteCommand, "Vulnerability");
                                sqliteCommand.ExecuteNonQuery();
                                sqliteCommand.CommandText = SetInitialSqliteCommandText("UniqueFinding");
                                sqliteCommand.CommandText = InsertParametersIntoSqliteCommandText(sqliteCommand, "UniqueFinding");
                                sqliteCommand.ExecuteNonQuery();
                            }
                        }
                    }
                }
                sqliteTransaction.Commit();
            }
        }

        private void CreateAddFileNameCommand(string fileName)
        {
            using (SQLiteCommand sqliteCommand = FindingsDatabaseActions.sqliteConnection.CreateCommand())
            {
                sqliteCommand.CommandText = "INSERT INTO FileNames VALUES (NULL, @FileName);";
                sqliteCommand.Parameters.Add(new SQLiteParameter("FileName", Path.GetFileName(fileName)));
                sqliteCommand.ExecuteNonQuery();
            }
        }

        private void CreateAddGroupNameCommand(string groupName)
        {
            using (SQLiteCommand sqliteCommand = FindingsDatabaseActions.sqliteConnection.CreateCommand())
            {
                sqliteCommand.CommandText = "INSERT INTO Groups VALUES (NULL, @GroupName);";
                sqliteCommand.Parameters.Add(new SQLiteParameter("GroupName", groupName));
                sqliteCommand.ExecuteNonQuery();
            }
        }

        private void CreateAddSourceCommand()
        {
            using (SQLiteCommand sqliteCommand = FindingsDatabaseActions.sqliteConnection.CreateCommand())
            {
                sqliteCommand.CommandText = "INSERT INTO VulnerabilitySources VALUES (NULL, 'Assured Compliance Assessment Solution (ACAS)');";
                sqliteCommand.ExecuteNonQuery();
            }
        }

        private XmlReaderSettings GenerateXmlReaderSettings()
        {
            XmlReaderSettings xmlReaderSettings = new XmlReaderSettings();
            xmlReaderSettings.IgnoreWhitespace = true;
            xmlReaderSettings.IgnoreComments = true;
            xmlReaderSettings.ValidationType = ValidationType.Schema;
            xmlReaderSettings.ValidationFlags = System.Xml.Schema.XmlSchemaValidationFlags.ProcessInlineSchema;
            xmlReaderSettings.ValidationFlags = System.Xml.Schema.XmlSchemaValidationFlags.ProcessSchemaLocation;
            return xmlReaderSettings;
        }

        private WorkingSystem ParseHostInformation(XmlReader xmlReader, WorkingSystem workingSystem)
        {
            while (xmlReader.Read())
            {
                if (xmlReader.IsStartElement() && xmlReader.Name.Equals("tag"))
                {
                    switch (xmlReader.GetAttribute("name"))
                    {
                        case "HOST_END":
                            {
                                xmlReader.Read();
                                DateTime scanEndTime;
                                if (DateTime.TryParseExact(xmlReader.Value.Replace("  ", " "), dateTimeFormat, System.Globalization.CultureInfo.InvariantCulture, 
                                    System.Globalization.DateTimeStyles.None, out scanEndTime))
                                { workingSystem.SetEndTime(scanEndTime); }
                                break;
                            }
                        case "Credentialed_Scan":
                            {
                                xmlReader.Read();
                                workingSystem.SetCredentialedScan(xmlReader.Value);
                                break;
                            }
                        case "host-fqdn":
                            {
                                xmlReader.Read();
                                workingSystem.SetHostName(xmlReader.Value);
                                break;
                            }
                        case "operating-system":
                            {
                                xmlReader.Read();
                                workingSystem.SetOperatingSystem(xmlReader.Value);
                                break;
                            }
                        case "host-ip":
                            {
                                xmlReader.Read();
                                workingSystem.SetIpAddress(xmlReader.Value);
                                break;
                            }
                        case "HOST_START":
                            {
                                xmlReader.Read();
                                DateTime scanStartTime;
                                if (DateTime.TryParseExact(xmlReader.Value.Replace("  ", " "), dateTimeFormat, null, System.Globalization.DateTimeStyles.None, out scanStartTime))
                                { workingSystem.SetStartTime(scanStartTime); }
                                break;
                            }
                        default:
                            { break; }
                    }
                }
                else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("HostProperties"))
                { break; }
            }
            return workingSystem;
        }

        private SQLiteCommand ParseVulnerabilityInformation(XmlReader xmlReader, SQLiteCommand sqliteCommand, WorkingSystem workingSystem)
        {
            sqliteCommand.Parameters.Add(new SQLiteParameter("VulnId", xmlReader.GetAttribute("pluginID")));
            sqliteCommand.Parameters.Add(new SQLiteParameter("RuleId", xmlReader.GetAttribute("pluginID")));
            sqliteCommand.Parameters.Add(new SQLiteParameter("VulnTitle", xmlReader.GetAttribute("pluginName")));
            sqliteCommand.Parameters.Add(new SQLiteParameter("LastObserved", workingSystem.StartTime.ToLongDateString()));
            sqliteCommand.Parameters.Add(new SQLiteParameter("Status", "Ongoing"));
            sqliteCommand.Parameters.Add(new SQLiteParameter("FindingType", "ACAS"));
            sqliteCommand.Parameters.Add(new SQLiteParameter("Source", "Assured Compliance Assessment Solution (ACAS)"));
            if (!String.IsNullOrWhiteSpace(workingSystem.HostName))
            { sqliteCommand.Parameters.Add(new SQLiteParameter("AssetIdToReport", workingSystem.HostName)); }
            else
            { sqliteCommand.Parameters.Add(new SQLiteParameter("AssetIdToReport", workingSystem.IpAddress)); }

            while (xmlReader.Read())
            {
                if (xmlReader.IsStartElement())
                {
                    switch (xmlReader.Name)
                    {
                        case "description":
                            {
                                xmlReader.Read();
                                sqliteCommand.Parameters.Add(new SQLiteParameter("Description", xmlReader.Value));
                                break;
                            }
                        case "plugin_publication_date":
                            {
                                xmlReader.Read();
                                sqliteCommand.Parameters.Add(new SQLiteParameter("PluginPublishedDate", 
                                    DateTime.Parse(xmlReader.Value).ToLongDateString()));
                                sqliteCommand.Parameters.Add(new SQLiteParameter("Age", 
                                    (DateTime.Now - DateTime.Parse(xmlReader.Value)).Days.ToString()));
                                break;
                            }
                        case "plugin_modification_date":
                            {
                                xmlReader.Read();
                                sqliteCommand.Parameters.Add(new SQLiteParameter("PluginModifiedDate", 
                                    DateTime.Parse(xmlReader.Value).ToLongDateString()));
                                break;
                            }
                        case "patch_publication_date":
                            {
                                xmlReader.Read();
                                sqliteCommand.Parameters.Add(new SQLiteParameter("PatchPublishedDate",
                                    DateTime.Parse(xmlReader.Value).ToLongDateString()));
                                break;
                            }
                        case "risk_factor":
                            {
                                xmlReader.Read();
                                if (xmlReader.Value.Equals("None"))
                                { sqliteCommand.Parameters.Add(new SQLiteParameter("Impact", "Informational")); }
                                else
                                { sqliteCommand.Parameters.Add(new SQLiteParameter("Impact", xmlReader.Value)); }
                                break;
                            }
                        case "solution":
                            {
                                xmlReader.Read();
                                if (xmlReader.Value.Equals("n/a"))
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("FixText", 
                                        "Informational finding - no solution provided."));
                                }
                                else
                                { sqliteCommand.Parameters.Add(new SQLiteParameter("FixText", xmlReader.Value)); }
                                break;
                            }
                        case "synopsis":
                            {
                                xmlReader.Read();
                                sqliteCommand.Parameters.Add(new SQLiteParameter("RiskStatement", xmlReader.Value));
                                break;
                            }
                        case "plugin_output":
                            {
                                xmlReader.Read();
                                sqliteCommand.Parameters.Add(new SQLiteParameter("PluginOutput", xmlReader.Value));
                                break;
                            }
                        case "stig_severity":
                            {
                                xmlReader.Read();
                                sqliteCommand.Parameters.Add(new SQLiteParameter("RawRisk", xmlReader.Value));
                                break;
                            }
                        case "xref":
                            {
                                xmlReader.Read();
                                if (!sqliteCommand.Parameters.Contains("CrossReferences"))
                                { sqliteCommand.Parameters.Add(new SQLiteParameter("CrossReferences", xmlReader.Value)); }
                                else
                                { sqliteCommand.Parameters["CrossReferences"].Value = 
                                    sqliteCommand.Parameters["CrossReferences"].Value + Environment.NewLine + xmlReader.Value; 
                                }
                                if (xmlReader.Value.Contains("IAV"))
                                { sqliteCommand.Parameters.Add(new SQLiteParameter("IavmNumber", xmlReader.Value)); }
                                break;
                            }
                        case "cve":
                            {
                                xmlReader.Read();
                                if (!sqliteCommand.Parameters.Contains("CrossReferences"))
                                { sqliteCommand.Parameters.Add(new SQLiteParameter("CrossReferences", xmlReader.Value)); }
                                else
                                {
                                    sqliteCommand.Parameters["CrossReferences"].Value =
                                      sqliteCommand.Parameters["CrossReferences"].Value + Environment.NewLine + xmlReader.Value;
                                }
                                break;
                            }

                        case "cpe":
                            {
                                xmlReader.Read();
                                if (!sqliteCommand.Parameters.Contains("CPEs"))
                                { sqliteCommand.Parameters.Add(new SQLiteParameter("CPEs", xmlReader.Value)); }
                                else
                                {
                                    sqliteCommand.Parameters["CPEs"].Value =
                                      sqliteCommand.Parameters["CPEs"].Value + Environment.NewLine + xmlReader.Value;
                                }
                                break;
                            }
                        default:
                            { break; }
                    }
                }
                else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name == "ReportItem")
                { break; }
            }
            return sqliteCommand;
        }
        
        private void CreateAddAssetCommand(WorkingSystem workingSystem, string systemName)
        {
            using (SQLiteCommand sqliteCommand = FindingsDatabaseActions.sqliteConnection.CreateCommand())
            {
                sqliteCommand.Parameters.Add(new SQLiteParameter("IpAddress", workingSystem.IpAddress));
                sqliteCommand.Parameters.Add(new SQLiteParameter("IsCredentialed", workingSystem.CredentialedScan));
                sqliteCommand.Parameters.Add(new SQLiteParameter("AssetIdToReport", workingSystem.IpAddress));
                if (!String.IsNullOrWhiteSpace(workingSystem.HostName))
                {
                    sqliteCommand.Parameters.Add(new SQLiteParameter("HostName", workingSystem.HostName));
                    sqliteCommand.Parameters.Add(new SQLiteParameter("AssetIdToReport", workingSystem.HostName));
                }
                else
                { sqliteCommand.Parameters.Add(new SQLiteParameter("AssetIdToReport", workingSystem.IpAddress)); }
                if (!String.IsNullOrWhiteSpace(workingSystem.OperatingSystem))
                { sqliteCommand.Parameters.Add(new SQLiteParameter("OperatingSystem", workingSystem.OperatingSystem)); }
                sqliteCommand.CommandText = "INSERT INTO Assets (, GroupIndex) VALUES (, " +
                    "(SELECT GroupIndex FROM Groups WHERE GroupName = @GroupName));";
                for (int i = 0; i < sqliteCommand.Parameters.Count; i++)
                {
                    if (sqliteCommand.Parameters[i].ParameterName.Equals("GroupName"))
                    { continue; }
                    if (i == 0)
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(42, "@" + sqliteCommand.Parameters[i].ParameterName); }
                    else
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(42, "@" + sqliteCommand.Parameters[i].ParameterName + ", "); }
                }
                for (int i = 0; i < sqliteCommand.Parameters.Count; i++)
                {
                    if (sqliteCommand.Parameters[i].ParameterName.Equals("GroupName"))
                    { continue; }
                    if (i == 0)
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(20, sqliteCommand.Parameters[i].ParameterName); }
                    else
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(20, sqliteCommand.Parameters[i].ParameterName + ", "); }
                }
                sqliteCommand.Parameters.Add(new SQLiteParameter("GroupName", systemName));
                sqliteCommand.ExecuteNonQuery();
            }
        }

        private string SetInitialSqliteCommandText(string tableName)
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

        private string InsertParametersIntoSqliteCommandText(SQLiteCommand sqliteCommand, string tableName)
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

        private void SetCredentialedStatusFallback(SQLiteCommand sqliteCommand)
        {
            switch (sqliteCommand.Parameters["VulnId"].Value.ToString())
            {
                case "19506":
                    {
                        sqliteCommand.CommandText = "SELECT IsCredentialed FROM Assets WHERE AssetIdToReport = @AssetIdToReport;";
                        using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
                        {
                            while (sqliteDataReader.Read())
                            {
                                if (!string.IsNullOrWhiteSpace(sqliteDataReader[0].ToString()))
                                { return; }
                            }
                        }
                        if (sqliteCommand.Parameters["PluginOutput"].ToString().Contains("Credentialed checks : no"))
                        {
                            sqliteCommand.CommandText = "UPDATE Assets SET IsCredentialed = 'No' WHERE AssetIdToReport = @AssetIdToReport;";
                            sqliteCommand.ExecuteNonQuery();
                        }
                        else
                        {
                            sqliteCommand.CommandText = "UPDATE Assets SET IsCredentialed = 'Yes' WHERE AssetIdToReport = @AssetIdToReport;";
                            sqliteCommand.ExecuteNonQuery();
                        }
                        break;
                    }
                case "21745":
                    {
                        sqliteCommand.CommandText = "UPDATE Assets SET IsCredentialed = 'No', Found21745 = 'True' WHERE AssetIdToReport = @AssetIdToReport;";
                        sqliteCommand.ExecuteNonQuery();
                        break;
                    }
                case "26917":
                    {
                        sqliteCommand.CommandText = "UPDATE Assets SET IsCredentialed = 'No', Found26917 = 'True' WHERE AssetIdToReport = @AssetIdToReport;";
                        sqliteCommand.ExecuteNonQuery();
                        break;
                    }
                default:
                    { break; }
            }
        }
    }
}
