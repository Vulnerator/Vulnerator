using CsvHelper;
using log4net;
using System;
using System.Collections.ObjectModel;
using System.Data.SQLite;
using System.IO;
using System.Linq;
using Vulnerator.Model.DataAccess;
using Vulnerator.Model.ModelHelper;
using Vulnerator.Model.Object;

namespace Vulnerator.Model.BusinessLogic
{
    /// <summary>
    /// Class housing all items required to parse ACAS *.csv scan files.
    /// </summary>
    class AcasCsvReader
    {
        private string[] iavaDelimiter = { "IAVA #" };
        private string[] iavbDelimiter = { "IAVB #" };
        private string[] iavtDelimiter = { "IAVT #" };
        private string[] timezoneDelimiter = { " UTC" };
        private string dateTimeFormat = "MMM d, yyyy hh:mm:ss";
        private string vulneratorDatabaseConnection = @"Data Source = " + ConfigAlter.ReadSettingsFromDictionary("tbMitDbLocation");
        private bool UserPrefersHostName { get { return bool.Parse(ConfigAlter.ReadSettingsFromDictionary("rbHostIdentifier")); } }
        private static readonly ILog log = LogManager.GetLogger(typeof(Logger));

        /// <summary>
        /// Reads *.csv files exported from within ACAS and writes the results to the appropriate DataTables.
        /// </summary>
        /// <param name="fileName">Name of *.csv file to be parsed.</param>
        /// <param name="mitigationsList">List of mitigation items for vulnerabilities to be read against.</param>
        /// <param name="systemName">Name of the system that the mitigations check will be run against.</param>
        /// <returns>string Value</returns>
        public string ReadAcasCsvFile(string fileName, ObservableCollection<MitigationItem> mitigationsList, string systemName)
        {
            try
            {
                if (fileName.IsFileInUse())
                {
                    log.Error(fileName + " is in use; please close any open instances and try again.");
                    return "Failed; File In Use";
                }

                using (SQLiteTransaction sqliteTransaction = FindingsDatabaseActions.sqliteConnection.BeginTransaction())
                {
                    CreateAddSourceCommand();
                    CreateAddGroupCommand(systemName);
                    string fileNameWithoutExtension = Path.GetFileName(fileName);
                    CreateAddFileNameCommand(fileNameWithoutExtension);
                    using (TextReader textReader = System.IO.File.OpenText(fileName))
                    {
                        var csvReader = new CsvReader(textReader);
                        csvReader.Configuration.HasHeaderRecord = true;

                        while (csvReader.Read())
                        {
                            if (csvReader.Row == 1)
                            {
                                string missingHeader = CheckForCsvHeaders(csvReader);
                                if (!string.IsNullOrWhiteSpace(missingHeader))
                                {
                                    log.Error("CSV File is missing the \"" + missingHeader + "\" column; please generate a " +
                                        "new CSV file utilizing the ACAS report template that was packaged with the application.");
                                    return "Failed; See Log";
                                }
                                csvReader.Read();
                            }
                            CreateAddAssetCommand(csvReader, systemName);
                            CreateAddVulnerabilityCommand(csvReader);
                            CreateAddUniqueFindingCommand(csvReader, systemName, fileNameWithoutExtension);
                        }
                    }
                    sqliteTransaction.Commit();
                }
                return "Processed";
            }
            catch (Exception exception)
            {
                log.Error("Unable to process CSV file.");
                log.Debug("Exception details:", exception);
                return "Failed; See Log";
            }
        }

        private string CheckForCsvHeaders(CsvReader csvReader)
        {
            try
            {
                string[] headersToVerify = { "Plugin", "Plugin Name", "IP Address", "DNS Name", "Synopsis", "Description", "NetBIOS Name",
                                           "Solution", "Risk Factor", "STIG Severity", "Cross References", "Last Observed", "Plugin Modification Date" };
                log.Info("Verifying CSV headers.");
                csvReader.ReadHeader();
                foreach (string headerName in headersToVerify)
                {
                    if (!csvReader.FieldHeaders.Contains(headerName))
                    { return headerName; }
                }

                return string.Empty;
            }
            catch (Exception exception)
            {
                log.Error("CSV header checking has failed.");
                throw exception;
            }
        }

        private void CreateAddGroupCommand(string groupName)
        {
            try
            {
                using (SQLiteCommand sqliteCommand = FindingsDatabaseActions.sqliteConnection.CreateCommand())
                {
                    sqliteCommand.Parameters.Add(new SQLiteParameter("GroupName", groupName));
                    sqliteCommand.CommandText = "INSERT INTO Groups (GroupName) VALUES (@GroupName);";
                    sqliteCommand.ExecuteNonQuery();
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to insert a new GroupName into Groups.");
                throw exception;
            }
        }

        private void CreateAddFileNameCommand(string fileName)
        {
            try
            {
                using (SQLiteCommand sqliteCommand = FindingsDatabaseActions.sqliteConnection.CreateCommand())
                {
                    sqliteCommand.Parameters.Add(new SQLiteParameter("FileName", fileName));
                    sqliteCommand.CommandText = "INSERT INTO FileNames (FileName) VALUES (@FileName);";
                    sqliteCommand.ExecuteNonQuery();
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to insert a new FileName into FileNames.");
                throw exception;
            }
        }

        private void CreateAddSourceCommand()
        {
            try
            {
                using (SQLiteCommand sqliteCommand = FindingsDatabaseActions.sqliteConnection.CreateCommand())
                {
                    sqliteCommand.Parameters.Add(new SQLiteParameter("Source", "Assured Compliance Assessment Solution (ACAS) Nessus Scanner"));
                    sqliteCommand.CommandText = "INSERT INTO VulnerabilitySources VALUES (NULL, @Source, '?', '?');";
                    sqliteCommand.ExecuteNonQuery();
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to insert a new Source into VulnerabilitySources.");
                throw exception;
            }
        }

        private void CreateAddAssetCommand(CsvReader csvReader, string groupName)
        {
            using (SQLiteCommand sqliteCommand = FindingsDatabaseActions.sqliteConnection.CreateCommand())
            {
                try
                {
                    sqliteCommand.Parameters.Add(new SQLiteParameter("IpAddress", csvReader.GetField("IP Address")));
                    if (!string.IsNullOrWhiteSpace(csvReader.GetField("DNS Name")))
                    {
                        sqliteCommand.Parameters.Add(new SQLiteParameter("HostName", csvReader.GetField("DNS Name")));
                        if (UserPrefersHostName)
                        { sqliteCommand.Parameters.Add(new SQLiteParameter("AssetIdToReport", csvReader.GetField("DNS Name"))); }
                        else
                        { sqliteCommand.Parameters.Add(new SQLiteParameter("AssetIdToReport", csvReader.GetField("IP Address"))); }
                    }
                    else if (!string.IsNullOrWhiteSpace(csvReader.GetField("NetBIOS Name")))
                    {
                        sqliteCommand.Parameters.Add(new SQLiteParameter("HostName", csvReader.GetField("NetBIOS Name")));
                        if (UserPrefersHostName)
                        { sqliteCommand.Parameters.Add(new SQLiteParameter("AssetIdToReport", csvReader.GetField("NetBIOS Name"))); }
                        else
                        { sqliteCommand.Parameters.Add(new SQLiteParameter("AssetIdToReport", csvReader.GetField("IP Address"))); }
                    }
                    else
                    { sqliteCommand.Parameters.Add(new SQLiteParameter("AssetIdToReport", csvReader.GetField("IP Address"))); }
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
                    sqliteCommand.Parameters.Add(new SQLiteParameter("GroupName", groupName));
                    sqliteCommand.ExecuteNonQuery();
                }
                catch (Exception exception)
                {
                    log.Error("Unable to insert new asset into Assets.");
                    throw exception;
                }
            }
        }

        private void CreateAddVulnerabilityCommand(CsvReader csvReader)
        {
            try
            {
                using (SQLiteCommand sqliteCommand = FindingsDatabaseActions.sqliteConnection.CreateCommand())
                {
                    if (csvReader.GetField("Plugin").Equals("21745") || csvReader.GetField("Plugin").Equals("26917"))
                    { SetCredentialedStatus(csvReader); }
                    sqliteCommand.Parameters.Add(new SQLiteParameter("VulnId", csvReader.GetField("Plugin")));
                    sqliteCommand.Parameters.Add(new SQLiteParameter("RuleId", csvReader.GetField("Plugin")));
                    sqliteCommand.Parameters.Add(new SQLiteParameter("VulnTitle", csvReader.GetField("Plugin Name")));
                    sqliteCommand.Parameters.Add(new SQLiteParameter("RiskStatement", csvReader.GetField("Synopsis")));
                    sqliteCommand.Parameters.Add(new SQLiteParameter("Description", csvReader.GetField("Description")));
                    if (csvReader.GetField("Solution").IndexOf("n/a") == 0)
                    { sqliteCommand.Parameters.Add(new SQLiteParameter("FixText", "Informational finding - no solution available")); }
                    else
                    { sqliteCommand.Parameters.Add(new SQLiteParameter("FixText", csvReader.GetField("Solution"))); }
                    if (csvReader.GetField("Risk Factor").Equals("None"))
                    { sqliteCommand.Parameters.Add(new SQLiteParameter("Impact", "Informational")); }
                    else
                    { sqliteCommand.Parameters.Add(new SQLiteParameter("Impact", csvReader.GetField("Risk Factor"))); }
                    if (!string.IsNullOrWhiteSpace(csvReader.GetField("STIG Severity")))
                    { sqliteCommand.Parameters.Add(new SQLiteParameter("RawRisk", csvReader.GetField("STIG Severity"))); }
                    sqliteCommand.Parameters.Add(new SQLiteParameter(
                        "CrossReferences", csvReader.GetField("Cross References").Replace(",", Environment.NewLine).Replace(" #", ":")));
                    if (csvReader.GetField("Cross References").Contains("IAV"))
                    { sqliteCommand.Parameters.Add(new SQLiteParameter("IavmNumber", ObtainIavmNumber(csvReader.GetField("Cross References")))); }
                    sqliteCommand.Parameters.Add(new SQLiteParameter("PluginModifiedDate", csvReader.GetField("Plugin Modification Date")));
                    sqliteCommand.CommandText = "INSERT INTO Vulnerability () VALUES ();";
                    for (int i = 0; i < sqliteCommand.Parameters.Count; i++)
                    {
                        if (i == 0)
                        { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(37, "@" + sqliteCommand.Parameters[i].ParameterName); }
                        else
                        { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(37, "@" + sqliteCommand.Parameters[i].ParameterName + ", "); }
                    }
                    for (int i = 0; i < sqliteCommand.Parameters.Count; i++)
                    {
                        if (i == 0)
                        { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(27, sqliteCommand.Parameters[i].ParameterName); }
                        else
                        { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(27, sqliteCommand.Parameters[i].ParameterName + ", "); }
                    }
                    sqliteCommand.ExecuteNonQuery();
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to insert new vulnerability into Vulnerabilities.");
                throw exception;
            }
        }

        private void CreateAddUniqueFindingCommand(CsvReader csvReader, string groupName, string fileName)
        {
            try
            {
                using (SQLiteCommand sqliteCommand = FindingsDatabaseActions.sqliteConnection.CreateCommand())
                {
                    sqliteCommand.Parameters.Add(new SQLiteParameter("LastObserved", csvReader.GetField("Last Observed")));
                    sqliteCommand.CommandText = "INSERT INTO UniqueFinding (FindingTypeIndex, SourceIndex, StatusIndex, " +
                        "FileNameIndex, VulnerabilityIndex, AssetIndex) VALUES (" +
                        "(SELECT FindingTypeIndex FROM FindingTypes WHERE FindingType = 'ACAS'), " +
                        "(SELECT SourceIndex FROM VulnerabilitySources WHERE Source = 'Assured Compliance Assessment Solution (ACAS) Nessus Scanner' AND Version = '?' AND Release = '?'), " +
                        "(SELECT StatusIndex FROM FindingStatuses WHERE Status = 'Ongoing'), " +
                        "(SELECT FileNameIndex FROM FileNames WHERE FileName = @FileName), " +
                        "(SELECT VulnerabilityIndex FROM Vulnerability WHERE RuleId = @RuleId), " +
                        "(SELECT AssetIndex FROM Assets WHERE AssetIdToReport = @AssetIdToReport));";
                    foreach (SQLiteParameter sqliteParameter in sqliteCommand.Parameters)
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(126, "@" + sqliteParameter.ParameterName + ", "); }
                    foreach (SQLiteParameter sqliteParameter in sqliteCommand.Parameters)
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(27, sqliteParameter.ParameterName + ", "); }
                    sqliteCommand.Parameters.Add(new SQLiteParameter("GroupName", groupName));
                    sqliteCommand.Parameters.Add(new SQLiteParameter("FileName", fileName));
                    sqliteCommand.Parameters.Add(new SQLiteParameter("RuleId", csvReader.GetField("Plugin")));
                    if (UserPrefersHostName)
                    {
                        if (!string.IsNullOrWhiteSpace(csvReader.GetField("DNS Name")))
                        { sqliteCommand.Parameters.Add(new SQLiteParameter("AssetIdToReport", csvReader.GetField("DNS Name"))); }
                        else if (!string.IsNullOrWhiteSpace(csvReader.GetField("NetBIOS Name")))
                        { sqliteCommand.Parameters.Add(new SQLiteParameter("AssetIdToReport", csvReader.GetField("NetBIOS Name"))); }
                        else
                        { sqliteCommand.Parameters.Add(new SQLiteParameter("AssetIdToReport", csvReader.GetField("IP Address"))); }
                    }
                    else
                    { sqliteCommand.Parameters.Add(new SQLiteParameter("AssetIdToReport", csvReader.GetField("IP Address"))); }
                    sqliteCommand.ExecuteNonQuery();
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to insert new unique finding into UniqueFinding.");
                throw exception;
            }
        }

        private string ObtainIavmNumber(string crossReferencesField)
        {
            try
            {
                string iavmNumber = string.Empty;

                if (crossReferencesField.Contains(string.Concat(iavaDelimiter)))
                { iavmNumber = crossReferencesField.Split(iavaDelimiter, StringSplitOptions.None)[1].Trim(); }
                else if (crossReferencesField.Contains(string.Concat(iavbDelimiter)))
                { iavmNumber = crossReferencesField.Split(iavbDelimiter, StringSplitOptions.None)[1].Trim(); }
                else if (crossReferencesField.Contains(string.Concat(iavtDelimiter)))
                { iavmNumber = crossReferencesField.Split(iavtDelimiter, StringSplitOptions.None)[1].Trim(); }

                return iavmNumber;
            }
            catch (Exception exception)
            {
                log.Error("Unable to obtain IAVM Number.");
                throw exception;
            }
        }

        private DateTime ParseDateInformation(string stringToParse)
        {
            try
            {
                string temporaryDateTime = stringToParse.Split(timezoneDelimiter, StringSplitOptions.None)[0];
                DateTime parsedDateTime;
                if (DateTime.TryParseExact(temporaryDateTime, dateTimeFormat, System.Globalization.CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.None, out parsedDateTime))
                { return parsedDateTime; }
                else
                { return DateTime.Now; }
            }
            catch (Exception exception)
            {
                log.Error("Unable to parse date information.");
                throw exception;
            }
        }

        private string ExtractOperatingSystem(string pluginText)
        {
            try
            {
                string operatingSystem = pluginText.Split(':')[1].Trim();
                operatingSystem = operatingSystem.Split(new string[] { "Confidence" }, StringSplitOptions.None)[0].Trim();
                return operatingSystem;
            }
            catch (Exception exception)
            {
                log.Error("Unable to extract operating system.");
                throw exception;
            }
        }

        private void SetCredentialedStatus(CsvReader csvReader)
        {
            try
            {
                using (SQLiteCommand sqliteCommand = FindingsDatabaseActions.sqliteConnection.CreateCommand())
                {
                    sqliteCommand.Parameters.Add(new SQLiteParameter("IpAddress", csvReader.GetField("IP Address")));
                    switch (csvReader.GetField("Plugin"))
                    {
                        case "21745":
                            {
                                sqliteCommand.CommandText = "UPDATE Assets SET IsCredentialed = 'No', Found21745 = 'True' WHERE IpAddress = @IpAddress;";
                                sqliteCommand.ExecuteNonQuery();
                                break;
                            }
                        case "26917":
                            {
                                sqliteCommand.CommandText = "UPDATE Assets SET IsCredentialed = 'No', Found26917 = 'True' WHERE IpAddress = @IpAddress;";
                                sqliteCommand.ExecuteNonQuery();
                                break;
                            }
                        default:
                            { break; }
                    }
                    sqliteCommand.ExecuteNonQuery();
                }
            }
            catch (Exception excption)
            {
                log.Error("Unable to set credentialed status.");
                throw excption;
            }     
        }
    }
}
