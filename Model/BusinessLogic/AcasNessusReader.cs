using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
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

namespace Vulnerator.Model.BusinessLogic
{
    /// <summary>
    /// Class housing all items required to parse ACAS *.nessus scan files.
    /// </summary>
    public class AcasNessusReader
    {
        private Assembly assembly = Assembly.GetExecutingAssembly();
        DatabaseInterface databaseInterface = new DatabaseInterface();
        private int hardwarePrimaryKey = 0;
        private int softwarePrimaryKey = 0;
        private int lastVulnerabilitySourceId = 0;
        private int lastVulnerabilityId = 0;
        private int groupPrimaryKey = 0;
        private int sourceFilePrimaryKey = 0;
        private int findingTypeId = 0;
        private int ipId = 0;
        private int macId = 0;
        private string acasVersion = string.Empty;
        private string acasRelease = string.Empty;
        private string firstDiscovered = DateTime.Now.ToShortDateString();
        private string lastObserved = DateTime.Now.ToShortDateString();
        private string dateTimeFormat = "ddd MMM d HH:mm:ss yyyy";
        private static readonly ILog log = LogManager.GetLogger(typeof(Logger));
        private List<string> cves = new List<string>();
        private List<string> cpes = new List<string>();
        private List<string> xrefs = new List<string>();
        

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
                    log.Error(file.FileName + " is in use; please close any open instances and try again.");
                    return "Failed; File In Use";
                }

                ParseNessusWithXmlReader(file);

                return "Processed";
            }
            catch (Exception exception)
            {
                log.Error("Unable to process Nessus file.");
                log.Debug("Exception details:", exception);
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
                        InsertParameterPlaceholders(sqliteCommand);
                        InsertGroup(sqliteCommand, file);
                        InsertSourceFile(sqliteCommand, file);
                        XmlReaderSettings xmlReaderSettings = GenerateXmlReaderSettings();
                        using (XmlReader xmlReader = XmlReader.Create(file.FilePath, xmlReaderSettings))
                        {
                            WorkingSystem workingSystem = new WorkingSystem();
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
                                { ClearGlobals(); }
                            }
                        }
                    }
                    sqliteTransaction.Commit();
                    DatabaseBuilder.sqliteConnection.Close();
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to parse nessus file with XmlReader.");
                throw exception;
            }
        }

        private void SelectFindingType(SQLiteCommand sqliteCommand)
        { 
            try
            {
                sqliteCommand.CommandText = Properties.Resources.SelectFindingTypeId;
                sqliteCommand.Parameters.Add(new SQLiteParameter("Finding_Type", "ACAS"));
                using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
                {
                    while (sqliteDataReader.Read())
                    {
                        if (sqliteDataReader.HasRows)
                        { findingTypeId = int.Parse(sqliteDataReader["Finding_Type_ID"].ToString()); }
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to retrieve Finding Type ID for \"ACAS\"."));
                throw exception;
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
                sqliteCommand.CommandText = Properties.Resources.InsertGroup;
                sqliteCommand.ExecuteNonQuery();
                sqliteCommand.CommandText = Properties.Resources.SelectGroup;
                groupPrimaryKey = int.Parse(sqliteCommand.ExecuteScalar().ToString());
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
                sqliteCommand.CommandText = Properties.Resources.InsertUniqueFindingSource;
                sqliteCommand.ExecuteNonQuery();
                sqliteCommand.CommandText = Properties.Resources.SelectUniqueFindingSourceFile;
                sourceFilePrimaryKey = int.Parse(sqliteCommand.ExecuteScalar().ToString());
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to insert unique finding source file \"{0}\".", file.FileName));
                throw exception;
            }
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
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Host_Name", ObtainCurrentNodeValue(xmlReader)));
                                    break;
                                }
                            case "operating-system":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Discovered_Software_Name", ObtainCurrentNodeValue(xmlReader)));
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Displayed_Software_Name", ObtainCurrentNodeValue(xmlReader)));
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Is_OS_Or_Firmware", "True"));
                                    break;
                                }
                            case "host-fqdn":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("FQDN", ObtainCurrentNodeValue(xmlReader)));
                                    break;
                                }
                            case "host-ip":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("IP_Address", ObtainCurrentNodeValue(xmlReader)));
                                    break;
                                }
                            case "mac-address":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("MAC_Address", ObtainCurrentNodeValue(xmlReader)));
                                    break;
                                }
                            case "netbios-name":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("NetBIOS", ObtainCurrentNodeValue(xmlReader)));
                                    break;
                                }
                            case "HOST_END":
                                {
                                    DateTime scanEndTime;
                                    if (DateTime.TryParseExact(ObtainCurrentNodeValue(xmlReader).Replace("  ", " "), dateTimeFormat, System.Globalization.CultureInfo.InvariantCulture,
                                        System.Globalization.DateTimeStyles.None, out scanEndTime))
                                    { firstDiscovered = lastObserved = scanEndTime.ToShortDateString(); }
                                    break;
                                }
                            default:
                                { break; }
                        }
                    }
                    else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("HostProperties"))
                    {
                        InsertIpAddress(sqliteCommand);
                        InsertHardware(sqliteCommand);
                        MapIpAddress(sqliteCommand);
                        if (!string.IsNullOrWhiteSpace(sqliteCommand.Parameters["MAC_Address"].Value.ToString()))
                        { InsertAndMapMacAddress(sqliteCommand); }
                        if (sqliteCommand.Parameters.Contains("Discovered_Software_Name"))
                        {
                            InsertSoftware(sqliteCommand);
                            MapHardwareToSoftware(sqliteCommand);
                        }
                        return;
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to parse host \"{0}\".", hostIp));
                throw exception;
            }
        }

        private void InsertHardware(SQLiteCommand sqliteCommand)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(sqliteCommand.Parameters["Host_Name"].Value.ToString()))
                {
                    if (Properties.Settings.Default.HostNameFallbackFqdn)
                    {
                        if (!string.IsNullOrWhiteSpace(sqliteCommand.Parameters["FQDN"].Value.ToString()))
                        { sqliteCommand.Parameters["Host_Name"].Value = sqliteCommand.Parameters["FQDN"].Value; }
                        else
                        { sqliteCommand.Parameters["Host_Name"].Value = sqliteCommand.Parameters["NetBIOS"].Value; }
                    }
                    else
                    {
                        if (!string.IsNullOrWhiteSpace(sqliteCommand.Parameters["NetBIOS"].Value.ToString()))
                        { sqliteCommand.Parameters["Host_Name"].Value = sqliteCommand.Parameters["NetBIOS"].Value; }
                        else
                        { sqliteCommand.Parameters["Host_Name"].Value = sqliteCommand.Parameters["FQDN"].Value; }
                    }
                }
                sqliteCommand.Parameters.Add(new SQLiteParameter("Is_Virtual_Server", "False"));
                sqliteCommand.CommandText = Properties.Resources.InsertHardware;
                sqliteCommand.ExecuteNonQuery();
                sqliteCommand.CommandText = Properties.Resources.SelectHardware;
                hardwarePrimaryKey = int.Parse(sqliteCommand.ExecuteScalar().ToString());
                sqliteCommand.Parameters.Add(new SQLiteParameter("Hardware_ID", hardwarePrimaryKey));
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to insert host \"{0}\".", sqliteCommand.Parameters["IP_Address"].Value.ToString()));
                throw exception;
            }
        }

        private void InsertSoftware(SQLiteCommand sqliteCommand)
        { 
            try
            {
                sqliteCommand.CommandText = Properties.Resources.InsertSoftware;
                sqliteCommand.ExecuteNonQuery();
                sqliteCommand.CommandText = Properties.Resources.SelectSoftware;
                softwarePrimaryKey = int.Parse(sqliteCommand.ExecuteScalar().ToString());
                sqliteCommand.Parameters.Add(new SQLiteParameter("Software_ID", softwarePrimaryKey));
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to insert software \"{0}\" into table.", sqliteCommand.Parameters["Discovered_Software_Name"].Value.ToString()));
                throw exception;
            }
        }

        private void MapHardwareToSoftware(SQLiteCommand sqliteCommand)
        { 
            try
            {
                sqliteCommand.CommandText = Properties.Resources.MapHardwareToSoftware;
                sqliteCommand.Parameters.Add(new SQLiteParameter("ReportInAccreditation", "False"));
                sqliteCommand.Parameters.Add(new SQLiteParameter("ApprovedForBaseline", "False"));
                sqliteCommand.Parameters.Add(new SQLiteParameter("BaselineApprover", DBNull.Value));
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to map software \"{0}\" to \"{1}\".",
                    sqliteCommand.Parameters["Discovered_Software_Name"].Value.ToString(),
                    sqliteCommand.Parameters["Host_Name"].Value.ToString()));
                throw exception;
            }
        }

        private void InsertIpAddress(SQLiteCommand sqliteCommand)
        { 
            try
            {
                sqliteCommand.CommandText = Properties.Resources.InsertIpAddress;
                sqliteCommand.ExecuteNonQuery();
                sqliteCommand.CommandText = Properties.Resources.SelectIpAddress;
                ipId = int.Parse(sqliteCommand.ExecuteScalar().ToString());
                sqliteCommand.Parameters.Add(new SQLiteParameter("IP_Address_ID", ipId));
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to insert IP Address \"{0}\"."));
                log.Debug("Exception details:", exception);
                throw exception;
            }
        }

        private void MapIpAddress(SQLiteCommand sqliteCommand)
        { 
            try
            {
                sqliteCommand.CommandText = Properties.Resources.MapIpToHardware;
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to map IP Address \"{0}\" to host \"{1}\"."));
                throw exception;
            }
        }

        private void InsertAndMapMacAddress(SQLiteCommand sqliteCommand)
        { 
            try
            {
                string macAddress = sqliteCommand.Parameters["MAC_Address"].Value.ToString();
                Regex regex = new Regex(Properties.Resources.RegexMAC);
                foreach (Match match in regex.Matches(macAddress))
                {
                    sqliteCommand.Parameters["MAC_Address"].Value = match.ToString();
                    sqliteCommand.CommandText = Properties.Resources.InsertMacAddress;
                    sqliteCommand.ExecuteNonQuery();
                    sqliteCommand.CommandText = Properties.Resources.SelectMacAddress;
                    int macId = int.Parse(sqliteCommand.ExecuteScalar().ToString());
                    sqliteCommand.CommandText = Properties.Resources.MapMacToHardware;
                    sqliteCommand.Parameters.Add(new SQLiteParameter("MAC_Address_ID", macId));
                    sqliteCommand.ExecuteNonQuery();
                }
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to insert / map MAC Address \"{0}\" belonging to host \"{1}\"."));
                throw exception;
            }
        }

        private void ParseVulnerability(SQLiteCommand sqliteCommand, XmlReader xmlReader)
        {
            string pluginId = xmlReader.GetAttribute("pluginID");
            try
            {
                sqliteCommand.Parameters.Add(new SQLiteParameter("Last_Observed", lastObserved));
                sqliteCommand.Parameters.Add(new SQLiteParameter("Source_Version", string.Empty));
                sqliteCommand.Parameters.Add(new SQLiteParameter("Source_Release", string.Empty));
                sqliteCommand.Parameters.Add(new SQLiteParameter("Port", xmlReader.GetAttribute("port")));
                sqliteCommand.Parameters.Add(new SQLiteParameter("Protocol", xmlReader.GetAttribute("protocol")));
                sqliteCommand.Parameters.Add(new SQLiteParameter("Service", xmlReader.GetAttribute("svc_name")));
                sqliteCommand.Parameters.Add(new SQLiteParameter("Unique_Vulnerability_Identifier", pluginId));
                sqliteCommand.Parameters.Add(new SQLiteParameter("Vulnerability_Title", xmlReader.GetAttribute("pluginName")));
                sqliteCommand.Parameters.Add(new SQLiteParameter("VulnerabilityFamilyOrClass", xmlReader.GetAttribute("pluginFamily")));
                while (xmlReader.Read())
                {
                    if (xmlReader.IsStartElement())
                    {
                        switch (xmlReader.Name)
                        {
                            case "description":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Description", ObtainCurrentNodeValue(xmlReader)));
                                    break;
                                }
                            case "plugin_modification_date":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Modified_Date", ObtainCurrentNodeValue(xmlReader)));
                                    break;
                                }
                            case "plugin_publication_date":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Published_Date", ObtainCurrentNodeValue(xmlReader)));
                                    break;
                                }
                            case "patch_publication_date":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Fix_Published_Date", ObtainCurrentNodeValue(xmlReader)));
                                    break;
                                }
                            case "risk_factor":
                                {
                                    xmlReader.Read();
                                    if (string.IsNullOrWhiteSpace(sqliteCommand.Parameters["Raw_Risk"].Value.ToString()))
                                    { sqliteCommand.Parameters.Add(new SQLiteParameter("Raw_Risk", ConvertRiskFactorToRawRisk(xmlReader.Value))); }
                                    break;
                                }
                            case "solution":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Fix_Text", ObtainCurrentNodeValue(xmlReader)));
                                    break;
                                }
                            case "synopsis":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Risk_Statement", ObtainCurrentNodeValue(xmlReader)));
                                    break;
                                }
                            case "plugin_output":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Tool_Generated_Output", ObtainCurrentNodeValue(xmlReader)));
                                    switch (pluginId)
                                    {
                                        case "19506":
                                            {
                                                SetSourceInformation(sqliteCommand);
                                                break;
                                            }
                                        default:
                                            { break; }
                                    }
                                    break;
                                }
                            case "stig_severity":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Raw_Risk", ObtainCurrentNodeValue(xmlReader)));
                                    break;
                                }
                            case "xref":
                                {
                                    xrefs.Add(ObtainCurrentNodeValue(xmlReader));
                                    break;
                                }
                            case "cve":
                                {
                                    cves.Add(ObtainCurrentNodeValue(xmlReader));
                                    break;
                                }
                            case "cpe":
                                {
                                    cpes.Add(ObtainCurrentNodeValue(xmlReader));
                                    break;
                                }
                            case "bid":
                                {
                                    xrefs.Add(string.Format("BID:{0}", ObtainCurrentNodeValue(xmlReader)));
                                    break;
                                }
                            case "cvss_base_score":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("CVSS_Base_Score", ObtainCurrentNodeValue(xmlReader)));
                                    break;
                                }
                            case "cvss_temporal_score":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("CVSS_Temporal_Score", ObtainCurrentNodeValue(xmlReader)));
                                    break;
                                }
                            case "cvss_vector":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("CVSS_Base_Vector", ObtainCurrentNodeValue(xmlReader)));
                                    break;
                                }
                            case "cvss_temporal_vector":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("CVSS_Temporal_Vector", ObtainCurrentNodeValue(xmlReader)));
                                    break;
                                }
                            default:
                                { break; }
                        }
                    }
                    else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("ReportItem"))
                    {
                        sqliteCommand.Parameters.Add(new SQLiteParameter("Hardware_ID", hardwarePrimaryKey));
                        InsertVulnerabilitySource(sqliteCommand);
                        InsertVulnerability(sqliteCommand);
                        MapVulnerabilityToSource(sqliteCommand);
                        if (Properties.Settings.Default.CaptureAcasPortInformation)
                        { InsertAndMapPort(sqliteCommand); }
                        InsertUniqueFinding(sqliteCommand);
                        if (Properties.Settings.Default.CaptureAcasReferenceInformation)
                        {
                            InsertAndMapReferences(sqliteCommand, cpes, "CPE");
                            InsertAndMapReferences(sqliteCommand, cves, "CVE");
                            InsertAndMapReferences(sqliteCommand, xrefs, "Multi");
                        }
                        ClearGlobals();
                        foreach (SQLiteParameter parameter in sqliteCommand.Parameters)
                        { parameter.Value = string.Empty; }
                        return;
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to parse plugin \"{0}\".", pluginId));
                throw exception;
            }
        }

        private void InsertVulnerabilitySource(SQLiteCommand sqliteCommand)
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
                sqliteCommand.CommandText = Properties.Resources.SelectAcasVulnerabilitySource;
                using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
                {
                    if (sqliteDataReader.HasRows)
                    {
                        while (sqliteDataReader.Read())
                        {
                            lastVulnerabilitySourceId = int.Parse(sqliteDataReader["Vulnerability_Source_ID"].ToString());
                            return;
                        }
                    }
                }
                sqliteCommand.Parameters.Add(new SQLiteParameter("Vulnerability_Source_ID", DBNull.Value));
                sqliteCommand.CommandText = Properties.Resources.InsertVulnerabilitySource;
                sqliteCommand.ExecuteNonQuery();
                sqliteCommand.CommandText = Properties.Resources.SelectVulnerabilitySource;
                lastVulnerabilitySourceId = int.Parse(sqliteCommand.ExecuteScalar().ToString());
                sqliteCommand.Parameters.Add(new SQLiteParameter("Vulnerability_Source_ID", lastVulnerabilitySourceId));
                MapUnknownVulnerabilitySources(sqliteCommand);
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

        private void MapUnknownVulnerabilitySources(SQLiteCommand sqliteCommand)
        {
            try
            {
                SQLiteCommand clonedCommand = (SQLiteCommand)sqliteCommand.Clone();
                clonedCommand.CommandText = "SELECT Vulnerability_Source_ID FROM VulnerabilitySources WHERE Source_Version = 'Version Unknown'";
                using (SQLiteDataReader sqliteDataReader = clonedCommand.ExecuteReader())
                {
                    if (sqliteDataReader.HasRows)
                    {
                        while (sqliteDataReader.Read())
                        {
                            int unknownSourceId = int.Parse(sqliteDataReader["Vulnerability_Source_ID"].ToString());
                            sqliteCommand.Parameters.Add(new SQLiteParameter("Old_Source", unknownSourceId));
                            sqliteCommand.CommandText = "UPDATE Vulnerabilities_VulnerabilitySources SET Vulnerability_Source_ID = @Vulnerability_Source_ID WHERE @Vulnerability_Source_ID = @Old_Source;";
                            sqliteCommand.ExecuteNonQuery();
                            sqliteCommand.CommandText = "DELETE FROM VulnerabilitySources WHERE @Vulnerability_Source_ID = @Old_Source;";
                            sqliteCommand.ExecuteNonQuery();
                            sqliteCommand.Parameters.Remove(sqliteCommand.Parameters["Old_Source"]);
                        }
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to re-map unknown ACAS Release / Version information."));
                throw exception;
            }
        }

        private void InsertVulnerability(SQLiteCommand sqliteCommand)
        { 
            try
            {
                SQLiteCommand clonedCommand = (SQLiteCommand)sqliteCommand.Clone();
                clonedCommand.CommandText = Properties.Resources.SelectVulnerability;
                using (SQLiteDataReader sqliteDataReader = clonedCommand.ExecuteReader())
                {
                    if (sqliteDataReader.HasRows)
                    {
                        while (sqliteDataReader.Read())
                        {
                            lastVulnerabilityId = int.Parse(sqliteDataReader["Vulnerability_ID"].ToString());
                            sqliteCommand.Parameters.Add(new SQLiteParameter("Vulnerability_ID", lastVulnerabilityId));
                            sqliteCommand.CommandText = Properties.Resources.UpdateVulnerability;
                            sqliteCommand.ExecuteNonQuery();
                            return;
                        }
                    }
                    sqliteCommand.CommandText = Properties.Resources.InsertVulnerability;
                    sqliteCommand.ExecuteNonQuery();
                    sqliteCommand.CommandText = Properties.Resources.SelectVulnerability;
                    lastVulnerabilityId = int.Parse(sqliteCommand.ExecuteScalar().ToString());
                }
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to insert plugin \"{0}\" into Vulnerabilities.", sqliteCommand.Parameters["Unique_Vulnerability_Identifier"].Value.ToString()));
                throw exception;
            }
        }

        private void MapVulnerabilityToSource(SQLiteCommand sqliteCommand)
        { 
            try
            {
                sqliteCommand.Parameters.Add(new SQLiteParameter("Vulnerability_ID", lastVulnerabilityId));
                sqliteCommand.Parameters.Add(new SQLiteParameter("Vulnerability_Source_ID", lastVulnerabilitySourceId));
                sqliteCommand.CommandText = Properties.Resources.MapVulnerabilityToSource;
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to map vulnerability back to a source."));
                throw exception;
            }
        }

        private void InsertAndMapPort(SQLiteCommand sqliteCommand)
        {
            try
            {
                int ppsId = 0;
                SQLiteCommand clonedCommand = (SQLiteCommand)sqliteCommand.Clone();
                clonedCommand.CommandText = Properties.Resources.SelectPort;
                using (SQLiteDataReader sqliteDataReader = clonedCommand.ExecuteReader())
                {
                    if (!sqliteDataReader.HasRows)
                    {
                        sqliteCommand.CommandText = Properties.Resources.InsertPort;
                        sqliteCommand.ExecuteNonQuery();
                        sqliteCommand.CommandText = Properties.Resources.SelectPort;
                        ppsId = int.Parse(sqliteCommand.ExecuteScalar().ToString());
                    }
                    else
                    {
                        while (sqliteDataReader.Read())
                        { ppsId = int.Parse(sqliteDataReader["PPS_ID"].ToString()); }
                    }
                }
                sqliteCommand.Parameters.Add(new SQLiteParameter("Hardware_ID", hardwarePrimaryKey));
                sqliteCommand.Parameters.Add(new SQLiteParameter("PPS_ID", ppsId));
                sqliteCommand.CommandText = Properties.Resources.MapPortToHardware;
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to insert or map port \"{0} {1}\".", 
                    sqliteCommand.Parameters["Protocol"].Value.ToString(),
                    sqliteCommand.Parameters["Port"].Value.ToString()));
                throw exception;
            }
        }

        private void InsertUniqueFinding(SQLiteCommand sqliteCommand)
        { 
            try
            {
                SQLiteCommand clonedCommand = (SQLiteCommand)sqliteCommand.Clone();
                clonedCommand.CommandText = Properties.Resources.SelectUniqueFinding;
                clonedCommand.Parameters.Add(new SQLiteParameter("Vulnerability_ID", lastVulnerabilityId));
                sqliteCommand.Parameters.Add(new SQLiteParameter("Status", "Ongoing"));
                using (SQLiteDataReader sqliteDataReader = clonedCommand.ExecuteReader())
                {
                    if (sqliteDataReader.HasRows)
                    {
                        sqliteCommand.CommandText = Properties.Resources.UpdateAcasUniqueFinding;
                        while (sqliteDataReader.Read())
                        { sqliteCommand.Parameters.Add(new SQLiteParameter("Unique_Finding_ID", sqliteDataReader["Unique_Finding_ID"])); }
                        if (sqliteCommand.Parameters.Contains("Tool_Generated_Output"))
                        { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(74, ", Tool_Generated_Output = @Tool_Generated_Output"); }
                        sqliteCommand.ExecuteNonQuery();
                        return;
                    }
                }
                sqliteCommand.Parameters.Add(new SQLiteParameter("Finding_Type_ID", findingTypeId));
                sqliteCommand.CommandText = Properties.Resources.InsertUniqueFinding;
                sqliteCommand.Parameters.Add(new SQLiteParameter("Unique_Finding_ID", DBNull.Value));
                sqliteCommand.Parameters.Add(new SQLiteParameter("First_Discovered", firstDiscovered));
                sqliteCommand.Parameters.Add(new SQLiteParameter("Approval_Status", "Not Approved"));
                sqliteCommand.Parameters.Add(new SQLiteParameter("Delta_Analysis_Required", "False"));
                sqliteCommand.Parameters.Add(new SQLiteParameter("Finding_Source_File_ID", sourceFilePrimaryKey));
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to create a UniqueFinding record for plugin \"{0}\".",
                    sqliteCommand.Parameters["Unique_Vulnerability_Identifier"].Value.ToString()));
                throw exception;
            }
        }

        private void InsertAndMapReferences(SQLiteCommand sqliteCommand, List<string> references, string referenceType)
        { 
            try
            {
                sqliteCommand.Parameters.Add(new SQLiteParameter("Vulnerability_ID", lastVulnerabilityId));
                foreach (string reference in references)
                {
                    sqliteCommand.CommandText = Properties.Resources.InsertVulnerabilityReference;
                    if (!referenceType.Equals("CVE") && !referenceType.Equals("CPE"))
                    {
                        referenceType = reference.Split(':')[0];
                        sqliteCommand.Parameters.Add(new SQLiteParameter("Reference", reference.Split(':')[1]));
                    }
                    else
                    { sqliteCommand.Parameters.Add(new SQLiteParameter("Reference", reference)); }
                    sqliteCommand.Parameters.Add(new SQLiteParameter("Reference_Type", referenceType));
                    sqliteCommand.ExecuteNonQuery();
                    sqliteCommand.CommandText = Properties.Resources.SelectVulnerabilityReference;
                    int referenceId = int.Parse(sqliteCommand.ExecuteScalar().ToString());
                    sqliteCommand.Parameters.Add(new SQLiteParameter("Reference_ID", referenceId));
                    sqliteCommand.CommandText = Properties.Resources.MapReferenceToVulnerability;
                    sqliteCommand.ExecuteNonQuery();
                }
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to insert / map reference."));
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

        private void ClearGlobals()
        {
            hardwarePrimaryKey = softwarePrimaryKey = lastVulnerabilityId = 0;
            cves.Clear();
            cpes.Clear();
            xrefs.Clear();
            firstDiscovered = lastObserved = DateTime.Now.ToShortDateString();
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
                    "Is_IA_Enabled", "SerialNumber", "Role", "Lifecycle_Status_ID",
                    // IP_Addresses Table
                    "IP_Address_ID", "IP_Address",
                    // MAC_Addresses Table
                    "MAC_Address_ID", "MAC_Address",
                    // PPS Table
                    "PPS_ID", "Port", "Protocol",
                    // Software Table
                    "Software_ID", "Discovered_Software_Name", "Displayed_Software_Name", "Software_Acronym", "Software_Version",
                    "Function", "Install_Date", "DADMS_ID", "DADMS_Disposition", "DADMS_LDA", "Has_Custom_Code", "IaOrIa_Enabled",
                    "Is_OS_Or_Firmware", "FAM_Accepted", "Externally_Authorized", "ReportInAccreditation_Global",
                    "ApprovedForBaseline_Global", "BaselineApprover_Global", "Instance",
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
                    "Source_Description", "Source_Version", "Source_Release"
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
