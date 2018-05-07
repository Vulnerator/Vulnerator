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
        private string vulneratorDatabaseConnection = @"Data Source = " + ConfigAlter.ReadSettingsFromDictionary("tbMitDbLocation");
        private bool UserPrefersHostName { get { return bool.Parse(ConfigAlter.ReadSettingsFromDictionary("rbHostIdentifier")); } }
        private static readonly ILog log = LogManager.GetLogger(typeof(Logger));
        private string[] persistentParameters = new string[] { "Group_Name", "Finding_Source_File_Name", "Source_Name" };
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
                    log.Error(file.FileName + " is in use; please close any open instances and try again.");
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
                        sqliteCommand.Parameters["Finding_Type"].Value = "ACAS";
                        sqliteCommand.Parameters["Group_Name"].Value = "All";
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
                                        log.Error("CSV File is missing the \"" + missingHeader + "\" column; please generate a " +
                                            "new CSV file utilizing the ACAS report template that was packaged with the application.");
                                        return "Failed; See Log";
                                    }
                                    csvReader.Read();
                                }
                                sqliteCommand.Parameters["Unique_Vulnerability_Identifier"].Value = csvReader.GetField("Plugin");
                                sqliteCommand.Parameters["Vulnerability_Title"].Value = csvReader.GetField("Plugin Name");
                                sqliteCommand.Parameters["Scan_IP"].Value = csvReader.GetField("IP Address");
                                sqliteCommand.Parameters["Host_Name"].Value = csvReader.GetField("DNS Name");
                                sqliteCommand.Parameters["Displayed_Host_Name"].Value = csvReader.GetField("DNS Name");
                                sqliteCommand.Parameters["NetBIOS"].Value = csvReader.GetField("NetBIOS Name");
                                sqliteCommand.Parameters["Risk_Statement"].Value = csvReader.GetField("Synopsis");
                                sqliteCommand.Parameters["Vulnerability_Description"].Value = csvReader.GetField("Description");
                                sqliteCommand.Parameters["Fix_Text"].Value = csvReader.GetField("Solution");
                                sqliteCommand.Parameters["Raw_Risk"].Value = ConvertRiskFactorToRawRisk(csvReader.GetField("Risk Factor"));
                                sqliteCommand.Parameters["Raw_Risk"].Value = csvReader.GetField("STIG Severity");
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
                                sqliteCommand.Parameters["Last_Observed"].Value = DateTime.Parse(csvReader.GetField("Last Observed")).ToShortDateString();
                                sqliteCommand.Parameters["Modified_Date"].Value = csvReader.GetField("Plugin Modification Date");
                                sqliteCommand.Parameters["CVSS_Temporal_Score"].Value = csvReader.GetField("CVSS Temporal Score");
                                sqliteCommand.Parameters["CVSS_Base_Score"].Value = csvReader.GetField("CVSS Base Score");
                                if (!string.IsNullOrWhiteSpace(csvReader.GetField("CVSS Temporal Score")))
                                {
                                    sqliteCommand.Parameters["CVSS_Base_Vector"].Value = csvReader.GetField("CVSS Vector")
                                        .Split( new string[] { "/E:" }, StringSplitOptions.None)[0];
                                    sqliteCommand.Parameters["CVSS_Temporal_Vector"].Value = csvReader.GetField("CVSS Vector");
                                }
                                else
                                { sqliteCommand.Parameters["CVSS_Base_Vector"].Value = csvReader.GetField("CVSS Vector"); }
                                sqliteCommand.Parameters["Tool_Generated_Output"].Value = csvReader.GetField("Plugin Text")
                                    .Replace("Plugin Output: ", string.Empty);
                                if (sqliteCommand.Parameters["Unique_Vulnerability_Identifier"].Value.ToString().Equals("19506"))
                                { SetSourceInformation(sqliteCommand); }
                                sqliteCommand.Parameters["Protocol"].Value = csvReader.GetField("Protocol");
                                sqliteCommand.Parameters["Port"].Value = csvReader.GetField("Port");
                                sqliteCommand.Parameters["VulnerabilityFamilyOrClass"].Value = csvReader.GetField("Family");
                                sqliteCommand.Parameters["First_Discovered"].Value = DateTime.Parse(csvReader.GetField("First Discovered")).ToShortDateString();
                                sqliteCommand.Parameters["Published_Date"].Value = DateTime.Parse(csvReader.GetField("Plugin Publication Date")).ToShortDateString();
                                sqliteCommand.Parameters["Fix_Published_Date"].Value = DateTime.Parse(csvReader.GetField("Patch Publication Date")).ToShortDateString();
                                sqliteCommand.Parameters["Vulnerability_Version"].Value = csvReader.GetField("Version");
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
                                    switch (sqliteCommand.Parameters["Unique_Vulnerability_Identifier"].Value.ToString())
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
                                        sqliteCommand.Parameters["Reference_Type"].Value = reference.ReferenceType;
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
                log.Error("Unable to process CSV file.");
                log.Debug("Exception details:", exception);
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
                log.Error(string.Format("Unable to santize cross reference \"{0}\"", unsanitizedCrossReference));
                throw exception;
            }
        }

        private void PrepareUniqueFinding(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.Parameters["Status"].Value = "Ongoing";
                sqliteCommand.Parameters["Unique_Finding_ID"].Value = DBNull.Value;
                sqliteCommand.Parameters["Approval_Status"].Value = "Not Approved";
                sqliteCommand.Parameters["Delta_Analysis_Required"].Value = "False";
                sqliteCommand.Parameters["Finding_Type"].Value = "ACAS";
                databaseInterface.UpdateUniqueFinding(sqliteCommand);
                databaseInterface.InsertUniqueFinding(sqliteCommand);
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to create a uniqueFinding record for plugin \"{0}\".",
                    sqliteCommand.Parameters["Unique_Vulnerability_Identifier"].Value.ToString()));
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
                log.Info("Verifying CSV headers.");
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
                log.Error("CSV header checking has failed.");
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
                string rawOutput = sqliteCommand.Parameters["Tool_Generated_Output"].Value.ToString();
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
                                        sqliteCommand.Parameters["Discovered_Software_Name"].Value = name;
                                        sqliteCommand.Parameters["Displayed_Software_Name"].Value = name;
                                        break;
                                    }
                                case 1:
                                    {
                                        sqliteCommand.Parameters["Software_Version"].Value = regex.Match(line).Value.Trim();
                                        break;
                                    }
                                case 2:
                                    {
                                        sqliteCommand.Parameters["Install_Date"].Value = regex.Match(line).Value.Trim();
                                        break;
                                    }
                                default:
                                    { break; }
                            }
                        }
                        if (!string.IsNullOrWhiteSpace(sqliteCommand.Parameters["Discovered_Software_Name"].Value.ToString()))
                        {
                            sqliteCommand.Parameters["DADMS_ID"].Value = DBNull.Value;
                            sqliteCommand.Parameters["ReportInAccreditation_Global"].Value = "False";
                            sqliteCommand.Parameters["ApprovedForBaseline_Global"].Value = "False";
                            databaseInterface.InsertSoftware(sqliteCommand);
                            databaseInterface.MapHardwareToSoftware(sqliteCommand);
                        }
                        string[] parametersToClear = new string[] { "Discovered_Software_Name", "Displayed_Software_Name", "Software_Version", "Install_Date" };
                        foreach (string parameter in parametersToClear)
                        { sqliteCommand.Parameters[parameter].Value = string.Empty; }
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to parse Windows software (Plugin 20811) for \"{0}\".",
                    sqliteCommand.Parameters["Scan_IP"].Value.ToString()));
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

                string rawOutput = sqliteCommand.Parameters["Tool_Generated_Output"].Value.ToString();
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
                                        sqliteCommand.Parameters["Discovered_Software_Name"].Value = name;
                                        sqliteCommand.Parameters["Displayed_Software_Name"].Value = name;
                                        break;
                                    }
                                case 1:
                                    {
                                        sqliteCommand.Parameters["Software_Version"].Value = regex.Match(line).Value.Trim();
                                        break;
                                    }
                                default:
                                    { break; }
                            }
                        }
                        if (!string.IsNullOrWhiteSpace(sqliteCommand.Parameters["Discovered_Software_Name"].Value.ToString()))
                        {
                            sqliteCommand.Parameters["DADMS_ID"].Value = DBNull.Value;
                            sqliteCommand.Parameters["ReportInAccreditation_Global"].Value = "False";
                            sqliteCommand.Parameters["ApprovedForBaseline_Global"].Value = "False";
                            databaseInterface.InsertSoftware(sqliteCommand);
                            databaseInterface.MapHardwareToSoftware(sqliteCommand);
                        }
                        string[] parametersToClear = new string[] { "Discovered_Software_Name", "Displayed_Software_Name", "Software_Version", "Install_Date" };
                        foreach (string parameter in parametersToClear)
                        { sqliteCommand.Parameters[parameter].Value = string.Empty; }
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to parse SSH software (Plugin 22869/29217) for \"{0}\".",
                    sqliteCommand.Parameters["Scan_IP"].Value.ToString()));
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
                log.Error(string.Format("Unable to obtain the software name for plugin \"{0}\"."));
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
                log.Error(string.Format("Unable to convert \"{0}\" to a standardized raw risk.", riskFactor));
                throw exception;
            }
        }

        private void SetSourceInformation(SQLiteCommand sqliteCommand)
        {
            try
            {
                StringReader stringReader = new StringReader(sqliteCommand.Parameters["Tool_Generated_Output"].Value.ToString());
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
                log.Error("Unable to set ACAS Nessus File source information.");
                throw exception;
            }
        }

        private void PrepareVulnerabilitySource(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.Parameters.Add(new SQLiteParameter("Source_Name", "Tenable Nessus Scanner"));
                sqliteCommand.Parameters.Add(new SQLiteParameter("Source_Secondary_Identifier", "Assured Compliance Assessment Solution (ACAS)"));
                if (!string.IsNullOrWhiteSpace(acasVersion))
                { sqliteCommand.Parameters.Add(new SQLiteParameter("Source_Version", acasVersion)); }
                else
                { sqliteCommand.Parameters.Add(new SQLiteParameter("Source_Version", "Version Unknown")); }
                if (!string.IsNullOrWhiteSpace(acasRelease))
                { sqliteCommand.Parameters.Add(new SQLiteParameter("Source_Release", acasRelease)); }
                else
                { sqliteCommand.Parameters.Add(new SQLiteParameter("Source_Release", "Release Unknown")); }
                databaseInterface.InsertVulnerabilitySource(sqliteCommand);
                if (!sqliteCommand.Parameters["Source_Version"].Value.ToString().Equals("Version Unknown"))
                { databaseInterface.UpdateVulnerabilitySource(sqliteCommand); }
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to insert source \"{0} {1} {2}\".",
                    sqliteCommand.Parameters["Source_Name"].Value.ToString(),
                    sqliteCommand.Parameters["Source_Version"].Value.ToString(),
                    sqliteCommand.Parameters["Source_Release"].Value.ToString()));
                throw exception;
            }
        }

        private void ParsePluginRevision(SQLiteCommand sqliteCommand)
        {
            try
            {
                string pluginVersion = sqliteCommand.Parameters["Vulnerability_Version"].Value.ToString();
                pluginVersion = pluginVersion.Replace("$", string.Empty);
                if (pluginVersion.Contains(":"))
                { pluginVersion = pluginVersion.Split(':')[1]; }
                pluginVersion = pluginVersion.Trim();
                sqliteCommand.Parameters["Vulnerability_Version"].Value = pluginVersion;
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to parse the version information for plugin \"{0}\".",
                    sqliteCommand.Parameters["Vulnerability_Version"].Value.ToString()));
                throw exception;
            }
        }
    }
}
