using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Data.SQLite;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text.RegularExpressions;
using log4net;
using System.Xml;
using Vulnerator.Helper;
using Vulnerator.Model.DataAccess;
using Vulnerator.Model.Object;
namespace Vulnerator.Model.BusinessLogic
{
    /// <summary>
    /// Class housing all items required to parse ACAS *.nessus scan files.
    /// </summary>
    public class AcasNessusReader
    {
        private Assembly assembly = Assembly.GetExecutingAssembly();
        DatabaseInterface databaseInterface = new DatabaseInterface();
        private string groupName = string.Empty;
        private string fileName = string.Empty;
        private string ipAddress = string.Empty;
        private string acasVersion = string.Empty;
        private string acasRelease = string.Empty;
        private DateTime firstDiscovered = DateTime.Now.Date;
        private DateTime lastObserved = DateTime.Now.Date;
        private string dateTimeFormat = "ddd MMM d HH:mm:ss yyyy";
        private bool found21745 = false;
        private bool found26917 = false;
        List<VulnerabilityReference> references = new List<VulnerabilityReference>();
        private string[] persistentParameters = new string[]
        {
            "Name", "FindingSourceFileName", "SourceName", "ScanIP", "DiscoveredHostName", "FindingType", "FQDN", "NetBIOS"
        };

        /// <summary>
        /// Reads *.nessus files exported from within ACAS and writes the results to the appropriate DataTables.
        /// </summary>
        /// <param name="file">File Object to be parsed</param>
        /// <returns>string Value</returns>
        public string ReadAcasNessusFile(Object.File file)
        {
            try
            {
                if (file.FilePath.IsFileInUse())
                {
                    LogWriter.LogError($"'{file.FileName}' is in use; please close any open instances and try again.");
                    return "Failed; File In Use";
                }

                fileName = file.FileName;
                ParseNessusWithXmlReader(file);

                return "Processed";
            }
            catch (Exception exception)
            {
                string error = $"Unable to process ACAS Nessus file '{file.FileName}'";
                LogWriter.LogErrorWithDebug(error, exception);
                return "Failed; See Log";
            }
        }

        private void ParseNessusWithXmlReader(Object.File file)
        {
            try
            {
                if (DatabaseBuilder.sqliteConnection.State.ToString().Equals("Closed"))
                { DatabaseBuilder.sqliteConnection.Open(); }
                using (SQLiteTransaction sqliteTransaction = DatabaseBuilder.sqliteConnection.BeginTransaction())
                {
                    using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                    {
                        databaseInterface.InsertParameterPlaceholders(sqliteCommand);
                        sqliteCommand.Parameters["FindingType"].Value = "ACAS";
                        sqliteCommand.Parameters["Name"].Value = "All";
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
                                        case "ReportHost":
                                            {
                                                ParseHostData(sqliteCommand, xmlReader);
                                                break;
                                            }
                                        case "ReportItem":
                                            {
                                                ParseVulnerability(sqliteCommand, xmlReader);
                                                break;
                                            }
                                        default:
                                            { break; }
                                    }
                                }
                                else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("ReportHost"))
                                {
                                    sqliteCommand.Parameters["Found21745"].Value = found21745;
                                    sqliteCommand.Parameters["Found26917"].Value = found26917;
                                    databaseInterface.SetCredentialedScanStatus(sqliteCommand);
                                    found21745 = found26917 = false;
                                }
                            }
                        }
                    }
                    sqliteTransaction.Commit();
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to parse ACAS Nessus file with XmlReader.");
                throw exception;
            }
            finally
            { DatabaseBuilder.sqliteConnection.Close(); }
        }

        private void ParseHostData(SQLiteCommand sqliteCommand, XmlReader xmlReader)
        {
            string hostIp = xmlReader.GetAttribute("name");
            try
            {
                while (xmlReader.Read())
                {
                    if (xmlReader.IsStartElement())
                    {
                        switch (xmlReader.GetAttribute("name"))
                        {
                            case "hostname":
                                {
                                    sqliteCommand.Parameters["DiscoveredHostName"].Value = xmlReader.ObtainCurrentNodeValue(true);
                                    sqliteCommand.Parameters["DisplayedHostName"].Value = sqliteCommand.Parameters["DiscoveredHostName"].Value;
                                    break;
                                }
                            case "operating-system":
                                {
                                    string operatingSystem = xmlReader.ObtainCurrentNodeValue(true);
                                    sqliteCommand.Parameters["DiscoveredSoftwareName"].Value = operatingSystem;
                                    sqliteCommand.Parameters["DisplayedSoftwareName"].Value = operatingSystem;
                                    sqliteCommand.Parameters["OS"].Value = operatingSystem;
                                    sqliteCommand.Parameters["Is_OS_Or_Firmware"].Value = "True";
                                    break;
                                }
                            case "host-fqdn":
                                {
                                    sqliteCommand.Parameters["FQDN"].Value = xmlReader.ObtainCurrentNodeValue(true);
                                    break;
                                }
                            case "host-ip":
                                {
                                    ipAddress = xmlReader.ObtainCurrentNodeValue(true);
                                    sqliteCommand.Parameters["IP_Address"].Value = ipAddress;
                                    sqliteCommand.Parameters["ScanIP"].Value = ipAddress;
                                    break;
                                }
                            case "mac-address":
                                {
                                    sqliteCommand.Parameters["MAC_Address"].Value = xmlReader.ObtainCurrentNodeValue(true);
                                    break;
                                }
                            case "netbios-name":
                                {
                                    sqliteCommand.Parameters["NetBIOS"].Value = xmlReader.ObtainCurrentNodeValue(true);
                                    break;
                                }
                            case "HOST_END":
                                {
                                    DateTime scanEndTime;
                                    if (DateTime.TryParseExact(xmlReader.ObtainCurrentNodeValue(true).Replace("  ", " "), dateTimeFormat, System.Globalization.CultureInfo.InvariantCulture,
                                        System.Globalization.DateTimeStyles.None, out scanEndTime))
                                    { firstDiscovered = lastObserved = scanEndTime.Date; }
                                    break;
                                }
                            default:
                                { break; }
                        }
                    }
                    else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("HostProperties"))
                    {
                        databaseInterface.InsertHardware(sqliteCommand);
                        databaseInterface.InsertAndMapIpAddress(sqliteCommand);
                        databaseInterface.MapHardwareToGroup(sqliteCommand);
                        if (!string.IsNullOrWhiteSpace(sqliteCommand.Parameters["MAC_Address"].Value.ToString()))
                        {
                            string macAddress = sqliteCommand.Parameters["MAC_Address"].Value.ToString();
                            Regex regex = new Regex(Properties.Resources.RegexMAC);
                            foreach (Match match in regex.Matches(macAddress))
                            {
                                sqliteCommand.Parameters["MAC_Address"].Value = match.ToString();
                                databaseInterface.InsertAndMapMacAddress(sqliteCommand);
                            }
                        }
                        if (!string.IsNullOrWhiteSpace(sqliteCommand.Parameters["DiscoveredSoftwareName"].Value.ToString()))
                        {
                            databaseInterface.InsertSoftware(sqliteCommand);
                            databaseInterface.MapHardwareToSoftware(sqliteCommand);
                            sqliteCommand.Parameters["DiscoveredSoftwareName"].Value = string.Empty;
                        }
                        return;
                    }
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to parse host '{hostIp}'.");
                throw exception;
            }
        }

        private void ParseVulnerability(SQLiteCommand sqliteCommand, XmlReader xmlReader)
        {
            string pluginId = xmlReader.GetAttribute("pluginID");
            try
            {
                sqliteCommand.Parameters["LastObserved"].Value = lastObserved;
                sqliteCommand.Parameters["SourceVersion"].Value = string.Empty;
                sqliteCommand.Parameters["SourceRelease"].Value = string.Empty;
                sqliteCommand.Parameters["Port"].Value = xmlReader.GetAttribute("port");
                sqliteCommand.Parameters["Protocol"].Value = xmlReader.GetAttribute("protocol");
                sqliteCommand.Parameters["DiscoveredService"].Value = sqliteCommand.Parameters["DisplayService"].Value = xmlReader.GetAttribute("svc_name");
                sqliteCommand.Parameters["UniqueVulnerabilityIdentifier"].Value = pluginId;
                sqliteCommand.Parameters["VulnerabilityTitle"].Value = xmlReader.GetAttribute("pluginName");
                sqliteCommand.Parameters["VulnerabilityFamilyOrClass"].Value = xmlReader.GetAttribute("pluginFamily");
                if (sqliteCommand.Parameters["UniqueVulnerabilityIdentifier"].Value.ToString().Equals("21745"))
                { found21745 = true; }
                if (sqliteCommand.Parameters["UniqueVulnerabilityIdentifier"].Value.ToString().Equals("26917"))
                { found26917 = true; }
                while (xmlReader.Read())
                {
                    if (xmlReader.IsStartElement())
                    {
                        switch (xmlReader.Name)
                        {
                            case "description":
                                {
                                    sqliteCommand.Parameters["VulnerabilityDescription"].Value = xmlReader.ObtainCurrentNodeValue(true);
                                    break;
                                }
                            case "plugin_modification_date":
                                {
                                    sqliteCommand.Parameters["ModifiedDate"].Value = xmlReader.ObtainCurrentNodeValue(true);
                                    break;
                                }
                            case "plugin_publication_date":
                                {
                                    sqliteCommand.Parameters["PublishedDate"].Value = xmlReader.ObtainCurrentNodeValue(true);
                                    break;
                                }
                            case "patch_publication_date":
                                {
                                    sqliteCommand.Parameters["FixPublishedDate"].Value = xmlReader.ObtainCurrentNodeValue(true);
                                    break;
                                }
                            case "risk_factor":
                                {
                                    xmlReader.Read();
                                    if (string.IsNullOrWhiteSpace(sqliteCommand.Parameters["RawRisk"].Value.ToString()))
                                    { sqliteCommand.Parameters["RawRisk"].Value = ConvertRiskFactorToRawRisk(xmlReader.Value); }
                                    break;
                                }
                            case "solution":
                                {
                                    sqliteCommand.Parameters["FixText"].Value = xmlReader.ObtainCurrentNodeValue(true);
                                    break;
                                }
                            case "synopsis":
                                {
                                    sqliteCommand.Parameters["RiskStatement"].Value = xmlReader.ObtainCurrentNodeValue(true);
                                    break;
                                }
                            case "plugin_output":
                                {
                                    sqliteCommand.Parameters["ToolGeneratedOutput"].Value = xmlReader.ObtainCurrentNodeValue(true);
                                    if (pluginId == "19506")
                                    { SetSourceInformation(sqliteCommand); }
                                    break;
                                }
                            case "stig_severity":
                                {
                                    sqliteCommand.Parameters["RawRisk"].Value = xmlReader.ObtainCurrentNodeValue(true);
                                    break;
                                }
                            case "xref":
                                {
                                    string reference = xmlReader.ObtainCurrentNodeValue(true);
                                    string referenceType = reference.Split(':')[0].Trim();
                                    reference = reference.Split(':')[1].Trim();
                                    references.Add(new VulnerabilityReference(reference, referenceType));
                                    break;
                                }
                            case "cve":
                                {
                                    references.Add(new VulnerabilityReference(xmlReader.ObtainCurrentNodeValue(true), "CVE"));
                                    break;
                                }
                            case "cpe":
                                {
                                    references.Add(new VulnerabilityReference(xmlReader.ObtainCurrentNodeValue(true), "CPE"));
                                    break;
                                }
                            case "bid":
                                {
                                    references.Add(new VulnerabilityReference(xmlReader.ObtainCurrentNodeValue(true), "BID"));
                                    break;
                                }
                            case "cvss_base_score":
                                {
                                    sqliteCommand.Parameters["CVSS_BaseScore"].Value = xmlReader.ObtainCurrentNodeValue(true);
                                    break;
                                }
                            case "cvss_temporal_score":
                                {
                                    sqliteCommand.Parameters["CVSS_TemporalScore"].Value = xmlReader.ObtainCurrentNodeValue(true);
                                    break;
                                }
                            case "cvss_vector":
                                {
                                    sqliteCommand.Parameters["CVSS_BaseVector"].Value = xmlReader.ObtainCurrentNodeValue(true);
                                    break;
                                }
                            case "cvss_temporal_vector":
                                {
                                    sqliteCommand.Parameters["CVSS_TemporalVector"].Value = xmlReader.ObtainCurrentNodeValue(true);
                                    break;
                                }
                            case "script_version":
                                {
                                    sqliteCommand.Parameters["VulnerabilityVersion"].Value = xmlReader.ObtainCurrentNodeValue(true);
                                    ParsePluginRevision(sqliteCommand);
                                    break;
                                }
                            default:
                                { break; }
                        }
                    }
                    else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("ReportItem"))
                    {
                        sqliteCommand.Parameters["ScanIP"].Value = ipAddress;
                        PrepareVulnerabilitySource(sqliteCommand);
                        databaseInterface.UpdateVulnerability(sqliteCommand);
                        databaseInterface.InsertVulnerability(sqliteCommand);
                        databaseInterface.MapVulnerabilityToSource(sqliteCommand);
                        if (Properties.Settings.Default.CaptureAcasPortInformation)
                        { databaseInterface.InsertAndMapPort(sqliteCommand); }
                        PrepareUniqueFinding(sqliteCommand);
                        if (Properties.Settings.Default.CaptureAcasReferenceInformation)
                        {
                            foreach (VulnerabilityReference reference in references)
                            {
                                sqliteCommand.Parameters["Reference"].Value = reference.Reference;
                                sqliteCommand.Parameters["ReferenceType"].Value = reference.ReferenceType;
                                databaseInterface.InsertAndMapVulnerabilityReferences(sqliteCommand);
                            }
                        }
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
                        foreach (SQLiteParameter parameter in sqliteCommand.Parameters)
                        {
                            if (!persistentParameters.Contains(parameter.ParameterName))
                            { parameter.Value = string.Empty; }
                        }
                        references.Clear();
                        return;
                    }
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to parse plugin '{pluginId}'.");
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
                string rawOutput = sqliteCommand.Parameters["ToolGeneratedOutput"].Value.ToString();
                string[] regexArray;
                sqliteCommand.Parameters["Is_OS_Or_Firmware"].Value = "False";
                if (pluginId.Equals("22869"))
                {
                    if (rawOutput.Contains("Debian"))
                    {
                        regexArray = new string[]
                        {
                            Properties.Resources.RegexAcasDebianSoftwareName,
                            Properties.Resources.RegexAcasDebianSoftwareVersion
                        };
                    }
                    else
                    {
                        regexArray = new string[]
                        {
                            Properties.Resources.RegexAcasLinuxSoftwareName,
                            Properties.Resources.RegexAcasLinuxSoftwareVersion
                        };
                    }
                }
                else
                {
                    regexArray = new string[]
                    {
                        Properties.Resources.RegexAcasSolarisSoftwareName,
                        Properties.Resources.RegexAcasSolarisSoftwareVersion
                    };
                }
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
                LogWriter.LogError($"Unable to obtain the software name for plugin '{pluginId}'.");
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

        private void PrepareVulnerabilitySource(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.Parameters["SourceName"].Value = "Tenable Nessus Scanner";
                sqliteCommand.Parameters["SourceSecondaryIdentifier"].Value = "Assured Compliance Assessment Solution (ACAS)";
                if (!string.IsNullOrWhiteSpace(acasVersion))
                { sqliteCommand.Parameters["SourceVersion"].Value = acasVersion; }
                else
                { sqliteCommand.Parameters["SourceVersion"].Value = "Version Unknown"; }
                if (!string.IsNullOrWhiteSpace(acasRelease))
                { sqliteCommand.Parameters["SourceRelease"].Value = acasRelease; }
                else
                { sqliteCommand.Parameters["SourceRelease"].Value = "Release Unknown"; }
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

        private void PrepareUniqueFinding(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.Parameters["Status"].Value = "Ongoing";
                sqliteCommand.Parameters["UniqueFinding_ID"].Value = DBNull.Value;
                sqliteCommand.Parameters["FirstDiscovered"].Value = firstDiscovered;
                sqliteCommand.Parameters["Approval_Status"].Value = "Not Approved";
                sqliteCommand.Parameters["DeltaAnalysisRequired"].Value = "False";
                sqliteCommand.Parameters["FindingSourceFileName"].Value = fileName;
                databaseInterface.InsertUniqueFinding(sqliteCommand);
            }
            catch (Exception exception)
            {
                LogWriter.LogError(
                    $"Unable to create a uniqueFinding record for plugin '{sqliteCommand.Parameters["UniqueVulnerabilityIdentifier"].Value}'.");
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
                LogWriter.LogError("Unable to obtain currently accessed node value.");
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
                LogWriter.LogError("Unable to generate XmlReaderSettings.");
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
                LogWriter.LogError("Unable to set ACAS Nessus File source information.");
                throw exception;
            }
        }
    }
}
