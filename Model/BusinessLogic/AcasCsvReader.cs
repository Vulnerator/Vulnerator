using CsvHelper;
using log4net;
using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using Vulnerator.Helper;
using Vulnerator.Model.DataAccess;
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
        private string acasVersion = string.Empty;
        private string acasRelease = string.Empty;
        private string[] persistentParameters = new string[] { "Name", "FindingSourceFileName", "SourceName" };
        List<VulnerabilityReference> references = new List<VulnerabilityReference>();
        private DatabaseInterface databaseInterface = new DatabaseInterface();

        /// <summary>
        /// Reads *.csv files exported from within ACAS and writes the results to the appropriate DataTables.
        /// </summary>
        /// <param name="fileName">Name of *.csv file to be parsed.</param>
        /// <param name="mitigationsList">List of mitigation items for vulnerabilities to be read against.</param>
        /// <param name="systemName">Name of the system that the mitigations check will be run against.</param>
        /// <returns>string Value</returns>
        public string ReadAcasCsvFile(Object.File file)
        {
            try
            {
                if (file.FilePath.IsFileInUse())
                {
                    LogWriter.LogError($"'{file.FileName}' is in use; please close any open instances and try again.");
                    return "Failed; File In Use";
                }

                if (!DatabaseBuilder.sqliteConnection.State.Equals("Open"))
                { DatabaseBuilder.sqliteConnection.Open(); }
                using (SQLiteTransaction sqliteTransaction = DatabaseBuilder.sqliteConnection.BeginTransaction())
                {
                    using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                    {
                        databaseInterface.InsertParameterPlaceholders(sqliteCommand);
                        databaseInterface.InsertParsedFileSource(sqliteCommand, file);
                        sqliteCommand.Parameters["FindingType"].Value = "ACAS";
                        sqliteCommand.Parameters["Name"].Value = "All";
                        using (TextReader textReader = System.IO.File.OpenText(file.FilePath))
                        {
                            var csvReader = new CsvReader(textReader);
                            csvReader.Configuration.HasHeaderRecord = true;

                            while (csvReader.Read())
                            {
                                if (csvReader.Context.Row == 1)
                                {
                                    string missingHeader = CheckForCsvHeaders(csvReader);
                                    if (!string.IsNullOrWhiteSpace(missingHeader))
                                    {
                                        LogWriter.LogError($"CSV File is missing the '{missingHeader}' column; please generate a " +
                                            "new CSV file utilizing the ACAS report template that was packaged with the application.");
                                        return "Failed; See Log";
                                    }
                                    csvReader.Read();
                                }
                                sqliteCommand.Parameters["UniqueVulnerabilityIdentifier"].Value = csvReader.GetField("Plugin");
                                sqliteCommand.Parameters["VulnerabilityTitle"].Value = csvReader.GetField("Plugin Name");
                                sqliteCommand.Parameters["ScanIP"].Value = csvReader.GetField("IP Address");
                                sqliteCommand.Parameters["DiscoveredHostName"].Value = csvReader.GetField("DNS Name");
                                sqliteCommand.Parameters["DisplayedHostName"].Value = csvReader.GetField("DNS Name");
                                sqliteCommand.Parameters["NetBIOS"].Value = csvReader.GetField("NetBIOS Name");
                                sqliteCommand.Parameters["RiskStatement"].Value = csvReader.GetField("Synopsis");
                                sqliteCommand.Parameters["VulnerabilityDescription"].Value = csvReader.GetField("Description");
                                sqliteCommand.Parameters["FixText"].Value = csvReader.GetField("Solution");
                                sqliteCommand.Parameters["RawRisk"].Value = ConvertRiskFactorToRawRisk(csvReader.GetField("Risk Factor"));
                                sqliteCommand.Parameters["RawRisk"].Value = csvReader.GetField("STIG Severity");
                                string crossReferences = csvReader.GetField("Cross References");
                                if (!string.IsNullOrWhiteSpace(crossReferences))
                                {
                                    if (crossReferences.Contains(","))
                                    {
                                        foreach (string reference in crossReferences.Split(','))
                                        { references.Add(SanitizeCrossReferences(reference)); }
                                    }
                                    else
                                    { references.Add(SanitizeCrossReferences(crossReferences)); }
                                }
                                sqliteCommand.Parameters["LastObserved"].Value = DateTime.Parse(csvReader.GetField("Last Observed")).ToShortDateString();
                                sqliteCommand.Parameters["ModifiedDate"].Value = csvReader.GetField("Plugin Modification Date");
                                sqliteCommand.Parameters["CVSS_TemporalScore"].Value = csvReader.GetField("CVSS Temporal Score");
                                sqliteCommand.Parameters["CVSS_BaseScore"].Value = csvReader.GetField("CVSS Base Score");
                                if (!string.IsNullOrWhiteSpace(csvReader.GetField("CVSS Temporal Score")))
                                {
                                    sqliteCommand.Parameters["CVSS_BaseVector"].Value = csvReader.GetField("CVSS Vector")
                                        .Split(new string[] { "/E:" }, StringSplitOptions.None)[0];
                                    sqliteCommand.Parameters["CVSS_TemporalVector"].Value = csvReader.GetField("CVSS Vector");
                                }
                                else
                                { sqliteCommand.Parameters["CVSS_BaseVector"].Value = csvReader.GetField("CVSS Vector"); }
                                sqliteCommand.Parameters["ToolGeneratedOutput"].Value = csvReader.GetField("Plugin Text")
                                    .Replace("Plugin Output: ", string.Empty);
                                if (sqliteCommand.Parameters["UniqueVulnerabilityIdentifier"].Value.ToString().Equals("19506"))
                                { SetSourceInformation(sqliteCommand); }
                                sqliteCommand.Parameters["Protocol"].Value = csvReader.GetField("Protocol");
                                sqliteCommand.Parameters["Port"].Value = csvReader.GetField("Port");
                                sqliteCommand.Parameters["VulnerabilityFamilyOrClass"].Value = csvReader.GetField("Family");
                                sqliteCommand.Parameters["FirstDiscovered"].Value = DateTime.Parse(csvReader.GetField("First Discovered")).ToShortDateString();
                                sqliteCommand.Parameters["PublishedDate"].Value = DateTime.Parse(csvReader.GetField("Plugin Publication Date")).ToShortDateString();
                                sqliteCommand.Parameters["FixPublishedDate"].Value = DateTime.Parse(csvReader.GetField("Patch Publication Date")).ToShortDateString();
                                sqliteCommand.Parameters["VulnerabilityVersion"].Value = csvReader.GetField("Version");
                                ParsePluginRevision(sqliteCommand);
                                sqliteCommand.Parameters["MAC_Address"].Value = csvReader.GetField("MAC Address");
                                PrepareVulnerabilitySource(sqliteCommand);
                                databaseInterface.InsertHardware(sqliteCommand);
                                databaseInterface.InsertVulnerability(sqliteCommand);
                                if (Properties.Settings.Default.CaptureAcasPortInformation)
                                { databaseInterface.InsertAndMapPort(sqliteCommand); }
                                databaseInterface.InsertAndMapIpAddress(sqliteCommand);
                                databaseInterface.InsertAndMapMacAddress(sqliteCommand);
                                if (Properties.Settings.Default.CaptureAcasEnumeratedSoftware)
                                {
                                    switch (sqliteCommand.Parameters["UniqueVulnerabilityIdentifier"].Value.ToString())
                                    {
                                        case "20811":
                                            {
                                                ParseWindowsSoftware(sqliteCommand);
                                                break;
                                            }
                                        case "22869":
                                            {
                                                ParseUnixSoftware(sqliteCommand, "22869");
                                                break;
                                            }
                                        case "29217":
                                            {
                                                ParseUnixSoftware(sqliteCommand, "29217");
                                                break;
                                            }
                                        default:
                                            { break; }
                                    }
                                }
                                if (Properties.Settings.Default.CaptureAcasReferenceInformation)
                                {
                                    foreach (VulnerabilityReference reference in references)
                                    {
                                        sqliteCommand.Parameters["Reference"].Value = reference.Reference;
                                        sqliteCommand.Parameters["ReferenceType"].Value = reference.ReferenceType;
                                        databaseInterface.InsertAndMapVulnerabilityReferences(sqliteCommand);
                                    }
                                }
                                PrepareUniqueFinding(sqliteCommand);
                                foreach (SQLiteParameter parameter in sqliteCommand.Parameters)
                                {
                                    if (!persistentParameters.Contains(parameter.ParameterName))
                                    { parameter.Value = string.Empty; }
                                }
                                references.Clear();
                            }
                        }
                    }
                    sqliteTransaction.Commit();
                }
                return "Processed";
            }
            catch (Exception exception)
            {
                string error = $"Unable to process ACAS CSV file '{file.FileName}'";
                LogWriter.LogErrorWithDebug(error, exception);
                return "Failed; See Log";
            }
            finally
            { DatabaseBuilder.sqliteConnection.Close(); }
        }

        private VulnerabilityReference SanitizeCrossReferences(string unsanitizedCrossReference)
        {
            try
            {
                string referenceType = unsanitizedCrossReference.Split('#')[0].Trim();
                string reference = unsanitizedCrossReference.Split('#')[1].Trim();
                return new VulnerabilityReference(reference, referenceType);
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to sanitize cross reference '{unsanitizedCrossReference}'");
                throw exception;
            }
        }

        private void PrepareUniqueFinding(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.Parameters["Status"].Value = "Ongoing";
                sqliteCommand.Parameters["UniqueFinding_ID"].Value = DBNull.Value;
                sqliteCommand.Parameters["Approval_Status"].Value = "Not Approved";
                sqliteCommand.Parameters["DeltaAnalysisRequired"].Value = "False";
                sqliteCommand.Parameters["FindingType"].Value = "ACAS";
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

        private string CheckForCsvHeaders(CsvReader csvReader)
        {
            try
            {
                string[] headersToVerify = new string[]
                {
                    "Plugin", "Plugin Name", "IP Address", "DNS Name", "NetBIOS Name", "Synopsis", "Description", "Solution", "Risk Factor", "STIG Severity",
                    "Cross References", "Last Observed", "Plugin Modification Date", "CVSS Temporal Score", "CVSS Base Score", "CVSS Vector", "Plugin Text",
                    "Protocol", "Port", "Family", "First Discovered", "Vuln Publication Date", "Patch Publication Date", "Version"
                };
                LogWriter.LogStatusUpdate("Verifying CSV headers.");
                csvReader.ReadHeader();
                foreach (string headerName in headersToVerify)
                {
                    if (!csvReader.Context.HeaderRecord.Contains(headerName))
                    { return headerName; }
                }

                return string.Empty;
            }
            catch (Exception exception)
            {
                LogWriter.LogError("CSV header checking has failed.");
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
                LogWriter.LogError($"Unable to parse date information from '{stringToParse}'.");
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
                LogWriter.LogError($"Unable to extract operating system from '{pluginText}'.");
                throw exception;
            }
        }

        private void ParseWindowsSoftware(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.Parameters["Is_OS_Or_Firmware"].Value = "False";
                string[] regexArray = new string[]
                {
                    Properties.Resources.RegexAcasWindowsSoftwareName,
                    Properties.Resources.RegexAcasWindowsSoftwareVersion,
                    Properties.Resources.RegexAcasSoftwareInstallDate
                };
                string rawOutput = sqliteCommand.Parameters["ToolGeneratedOutput"].Value.ToString();
                using (StringReader stringReader = new StringReader(rawOutput))
                {
                    string line;
                    int i = 0;
                    while ((line = stringReader.ReadLine()) != null)
                    {
                        if (i < 2)
                        {
                            i++;
                            continue;
                        }
                        foreach (string expression in regexArray)
                        {
                            Regex regex = new Regex(expression);
                            switch (Array.IndexOf(regexArray, expression))
                            {
                                case 0:
                                    {
                                        string name = SanitizeWindowsSoftwareName(regex.Match(line), "20811");
                                        sqliteCommand.Parameters["DiscoveredSoftwareName"].Value = name;
                                        sqliteCommand.Parameters["DisplayedSoftwareName"].Value = name;
                                        break;
                                    }
                                case 1:
                                    {
                                        sqliteCommand.Parameters["SoftwareVersion"].Value = regex.Match(line).Value.Trim();
                                        break;
                                    }
                                case 2:
                                    {
                                        sqliteCommand.Parameters["InstallDate"].Value = regex.Match(line).Value.Trim();
                                        break;
                                    }
                                default:
                                    { break; }
                            }
                        }
                        if (!string.IsNullOrWhiteSpace(sqliteCommand.Parameters["DiscoveredSoftwareName"].Value.ToString()))
                        {
                            sqliteCommand.Parameters["DADMS_ID"].Value = DBNull.Value;
                            sqliteCommand.Parameters["ReportInAccreditationGlobal"].Value = "False";
                            sqliteCommand.Parameters["ApprovedForBaselineGlobal"].Value = "False";
                            databaseInterface.InsertSoftware(sqliteCommand);
                            databaseInterface.MapHardwareToSoftware(sqliteCommand);
                        }
                        string[] parametersToClear = new string[] { "DiscoveredSoftwareName", "DisplayedSoftwareName", "SoftwareVersion", "InstallDate" };
                        foreach (string parameter in parametersToClear)
                        { sqliteCommand.Parameters[parameter].Value = string.Empty; }
                    }
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError(
                    $"Unable to parse Windows software (Plugin 20811) for '{sqliteCommand.Parameters["ScanIP"].Value.ToString()}'.");
                throw exception;
            }
        }

        private void ParseUnixSoftware(SQLiteCommand sqliteCommand, string pluginId)
        {
            try
            {
                string[] regexArray;
                sqliteCommand.Parameters["Is_OS_Or_Firmware"].Value = "False";
                if (pluginId.Equals("22869"))
                {
                    regexArray = new string[]
                    {
                        Properties.Resources.RegexAcasLinuxSoftwareName,
                        Properties.Resources.RegexAcasLinuxSoftwareVersion
                    };
                }
                else
                {
                    regexArray = new string[]
                    {
                        Properties.Resources.RegexAcasSolarisSoftwareName,
                        Properties.Resources.RegexAcasSolarisSoftwareVersion
                    };
                }

                string rawOutput = sqliteCommand.Parameters["ToolGeneratedOutput"].Value.ToString();
                using (StringReader stringReader = new StringReader(rawOutput))
                {
                    string line;
                    int i = 0;
                    while ((line = stringReader.ReadLine()) != null)
                    {
                        if (pluginId.Equals("22869") && line.Contains("Solaris"))
                        { return; }
                        if (i < 2)
                        {
                            i++;
                            continue;
                        }
                        line = line.Trim();
                        foreach (string expression in regexArray)
                        {
                            Regex regex = new Regex(expression);
                            switch (Array.IndexOf(regexArray, expression))
                            {
                                case 0:
                                    {
                                        string name = regex.Match(line).Value.Trim();
                                        sqliteCommand.Parameters["DiscoveredSoftwareName"].Value = name;
                                        sqliteCommand.Parameters["DisplayedSoftwareName"].Value = name;
                                        break;
                                    }
                                case 1:
                                    {
                                        sqliteCommand.Parameters["SoftwareVersion"].Value = regex.Match(line).Value.Trim();
                                        break;
                                    }
                                default:
                                    { break; }
                            }
                        }
                        if (!string.IsNullOrWhiteSpace(sqliteCommand.Parameters["DiscoveredSoftwareName"].Value.ToString()))
                        {
                            sqliteCommand.Parameters["DADMS_ID"].Value = DBNull.Value;
                            sqliteCommand.Parameters["ReportInAccreditationGlobal"].Value = "False";
                            sqliteCommand.Parameters["ApprovedForBaselineGlobal"].Value = "False";
                            databaseInterface.InsertSoftware(sqliteCommand);
                            databaseInterface.MapHardwareToSoftware(sqliteCommand);
                        }
                        string[] parametersToClear = new string[] { "DiscoveredSoftwareName", "DisplayedSoftwareName", "SoftwareVersion", "InstallDate" };
                        foreach (string parameter in parametersToClear)
                        { sqliteCommand.Parameters[parameter].Value = string.Empty; }
                    }
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError(
                    $"Unable to parse SSH software (Plugin 22869/29217) for '{sqliteCommand.Parameters["ScanIP"].Value.ToString()}'.");
                throw exception;
            }
        }

        private string SanitizeWindowsSoftwareName(Match match, string pluginId)
        {
            try
            {
                string name = match.Value.Trim();
                if (name.StartsWith("{") || name.StartsWith("KB") || string.IsNullOrWhiteSpace(name))
                { return string.Empty; }
                string[] ignoredSoftwareArray = new string[] { "Security Update", "Update for", "Hotfix for", "Language Pack" };
                foreach (string ignorable in ignoredSoftwareArray)
                {
                    if (name.Contains(ignorable))
                    { return string.Empty; }
                }
                return name;
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to obtain the software name for plugin \"{pluginId}\".");
                throw exception;
            }
        }

        private string ConvertRiskFactorToRawRisk(string riskFactor)
        {
            try
            {
                switch (riskFactor)
                {
                    case "None":
                        { return "IV"; }
                    case "Low":
                        { return "III"; }
                    case "Medium":
                        { return "II"; }
                    case "High":
                        { return "I"; }
                    case "Critical":
                        { return "I"; }
                    default:
                        { return "Unknown"; }
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to convert '{riskFactor}' to a standardized raw risk.");
                throw exception;
            }
        }

        private void SetSourceInformation(SQLiteCommand sqliteCommand)
        {
            try
            {
                StringReader stringReader = new StringReader(sqliteCommand.Parameters["ToolGeneratedOutput"].Value.ToString());
                string line = string.Empty;
                while (line != null)
                {
                    if (string.IsNullOrWhiteSpace(line))
                    {
                        line = stringReader.ReadLine();
                        continue;
                    }
                    if (line.StartsWith("Nessus version"))
                    { acasVersion = line.Split(':')[1].Split('(')[0].Trim(); }
                    else if (line.StartsWith("Plugin feed version"))
                    {
                        acasRelease = line.Split(':')[1].Trim();
                        line = null;
                    }
                    if (line != null)
                    { line = stringReader.ReadLine(); }
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to set ACAS Nessus source file information.");
                throw exception;
            }
        }

        private void PrepareVulnerabilitySource(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.Parameters.Add(new SQLiteParameter("SourceName", "Tenable Nessus Scanner"));
                sqliteCommand.Parameters.Add(new SQLiteParameter("SourceSecondaryIdentifier", "Assured Compliance Assessment Solution (ACAS)"));
                if (!string.IsNullOrWhiteSpace(acasVersion))
                { sqliteCommand.Parameters.Add(new SQLiteParameter("SourceVersion", acasVersion)); }
                else
                { sqliteCommand.Parameters.Add(new SQLiteParameter("SourceVersion", "Version Unknown")); }
                if (!string.IsNullOrWhiteSpace(acasRelease))
                { sqliteCommand.Parameters.Add(new SQLiteParameter("SourceRelease", acasRelease)); }
                else
                { sqliteCommand.Parameters.Add(new SQLiteParameter("SourceRelease", "Release Unknown")); }
                databaseInterface.InsertVulnerabilitySource(sqliteCommand);
                if (!sqliteCommand.Parameters["SourceVersion"].Value.ToString().Equals("Version Unknown"))
                { databaseInterface.UpdateVulnerabilitySource(sqliteCommand); }
            }
            catch (Exception exception)
            {
                LogWriter.LogError(
                    $"Unable to insert source '{sqliteCommand.Parameters["SourceName"].Value.ToString()} {sqliteCommand.Parameters["SourceVersion"].Value.ToString()} {sqliteCommand.Parameters["SourceRelease"].Value.ToString()}'.");
                throw exception;
            }
        }

        private void ParsePluginRevision(SQLiteCommand sqliteCommand)
        {
            try
            {
                string pluginVersion = sqliteCommand.Parameters["VulnerabilityVersion"].Value.ToString();
                pluginVersion = pluginVersion.Replace("$", string.Empty);
                if (pluginVersion.Contains(":"))
                { pluginVersion = pluginVersion.Split(':')[1]; }
                pluginVersion = pluginVersion.Trim();
                sqliteCommand.Parameters["VulnerabilityVersion"].Value = pluginVersion;
            }
            catch (Exception exception)
            {
                LogWriter.LogError(
                    $"Unable to parse the version information for plugin '{sqliteCommand.Parameters["VulnerabilityVersion"].Value.ToString()}'.");
                throw exception;
            }
        }
    }
}
