using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Data.SQLite;
using System.IO;
using System.Reflection;
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
        private static readonly ILog log = LogManager.GetLogger(typeof(Logger));

        /// <summary>
        /// Reads *.nessus files exported from within ACAS and writes the results to the appropriate DataTables.
        /// </summary>
        /// <param name="fileName">Name of *.nessus file to be parsed.</param>
        /// <param name="mitigationsList">List of mitigation items for vulnerabilities to be read against.</param>
        /// <param name="systemName">Name of the system that the mitigations check will be run against.</param>
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
                using (SQLiteTransaction sqliteTransaction = FindingsDatabaseActions.sqliteConnection.BeginTransaction())
                {
                    using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                    {
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
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to parse nessus file with XmlReader.");
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

        private void ParseHostData(SQLiteCommand sqliteCommand, XmlReader xmlReader)
        {
            string hostIp = xmlReader.GetAttribute("name");
            sqliteCommand.Parameters.Add(new SQLiteParameter("IP_Address", hostIp));
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
                            default:
                                { break; }
                        }
                    }
                    else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("HostProperties"))
                    {
                        InsertHardware(sqliteCommand);
                        sqliteCommand.Parameters.Add(new SQLiteParameter("Hardware_ID", hardwarePrimaryKey));
                        InsertAndMapMacAndIp(sqliteCommand);
                        if (sqliteCommand.Parameters.Contains("Discovered_Software_Name"))
                        {
                            InsertSoftware(sqliteCommand);
                            MapHardwareToSoftware(sqliteCommand);
                        }
                        sqliteCommand.Parameters.Clear();
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
                if (!sqliteCommand.Parameters.Contains("NetBIOS"))
                { sqliteCommand.Parameters.Add(new SQLiteParameter("NetBIOS", "Undefined")); }
                if (!sqliteCommand.Parameters.Contains("Host_Name"))
                { sqliteCommand.Parameters.Add(new SQLiteParameter("Host_Name", "Undefined")); }
                if (!sqliteCommand.Parameters.Contains("FQDN"))
                { sqliteCommand.Parameters.Add(new SQLiteParameter("FQDN", "Undefined")); }
                sqliteCommand.Parameters.Add(new SQLiteParameter("Is_Virtual_Server", "False"));
                sqliteCommand.Parameters.Add(new SQLiteParameter("NIAP_Level", string.Empty));
                sqliteCommand.Parameters.Add(new SQLiteParameter("Manufacturer", string.Empty));
                sqliteCommand.Parameters.Add(new SQLiteParameter("ModelNumber", string.Empty));
                sqliteCommand.Parameters.Add(new SQLiteParameter("Is_IA_Enabled", string.Empty));
                sqliteCommand.Parameters.Add(new SQLiteParameter("SerialNumber", string.Empty));
                sqliteCommand.Parameters.Add(new SQLiteParameter("Role", string.Empty));
                sqliteCommand.CommandText = Properties.Resources.InsertHardware;
                sqliteCommand.ExecuteNonQuery();
                sqliteCommand.CommandText = Properties.Resources.SelectHardware;
                hardwarePrimaryKey = int.Parse(sqliteCommand.ExecuteScalar().ToString());
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
                sqliteCommand.CommandText = Properties.Resources.InsertAcasDiscoveredSoftware;
                sqliteCommand.ExecuteNonQuery();
                sqliteCommand.CommandText = Properties.Resources.SelectSoftware;
                softwarePrimaryKey = int.Parse(sqliteCommand.ExecuteScalar().ToString());
            }
            catch (Exception exception)
            {
                log.Error(string.Format(""));
                throw exception;
            }
        }

        private void MapHardwareToSoftware(SQLiteCommand sqliteCommand)
        { 
            try
            {
                sqliteCommand.CommandText = Properties.Resources.MapHardwareToSoftware;
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                log.Error(string.Format(""));
                log.Debug("Exception details:", exception);
                throw exception;
            }
        }

        private void InsertAndMapMacAndIp(SQLiteCommand sqliteCommand)
        { 
            try
            {
                sqliteCommand.CommandText = Properties.Resources.InsertIpAddress;
                sqliteCommand.ExecuteNonQuery();
                sqliteCommand.CommandText = "SELECT last_insert_rowid();";
                int ipId = int.Parse(sqliteCommand.ExecuteScalar().ToString());
                sqliteCommand.CommandText = Properties.Resources.MapIpToHardware;
                sqliteCommand.Parameters.Add(new SQLiteParameter("IP_Address_ID", ipId));
                sqliteCommand.ExecuteNonQuery();
                sqliteCommand.CommandText = Properties.Resources.InsertMacAddress;
                sqliteCommand.ExecuteNonQuery();
                sqliteCommand.CommandText = "SELECT last_insert_rowid();";
                int macId = int.Parse(sqliteCommand.ExecuteScalar().ToString());
                sqliteCommand.CommandText = Properties.Resources.MapIpToHardware;
                sqliteCommand.Parameters.Add(new SQLiteParameter("MAC_Address_ID", macId));
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                log.Error(string.Format(""));
                log.Debug("Exception details:", exception);
                throw exception;
            }
        }

        private void ParseVulnerability(SQLiteCommand sqliteCommand, XmlReader xmlReader)
        {
            int ppsId = 0;
            string pluginId = xmlReader.GetAttribute("pluginID");
            try
            {
                sqliteCommand.Parameters.Add(new SQLiteParameter("Port", xmlReader.GetAttribute("port")));
                sqliteCommand.Parameters.Add(new SQLiteParameter("Protocol", xmlReader.GetAttribute("protocol")));
                sqliteCommand.Parameters.Add(new SQLiteParameter("Service", xmlReader.GetAttribute("svc_name")));
                sqliteCommand.Parameters.Add(new SQLiteParameter("Unique_Vulnerability_ID", pluginId));
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
                                    break;
                                }
                            case "plugin_modification_date":
                                {
                                    break;
                                }
                            case "plugin_publication_date":
                                {
                                    break;
                                }
                            case "risk_factor":
                                {
                                    break;
                                }
                            case "solution":
                                {
                                    break;
                                }
                            case "synopsis":
                                {
                                    break;
                                }
                            case "plugin_output":
                                {
                                    break;
                                }
                            case "stig_severity":
                                {
                                    break;
                                }
                            case "xref":
                                {
                                    break;
                                }
                            case "cve":
                                {
                                    break;
                                }
                            case "cpe":
                                {
                                    break;
                                }
                            case "cvss_base_score":
                                {
                                    break;
                                }
                            case "cvss_temporal_score":
                                {
                                    break;
                                }
                            case "cvss_vector":
                                {
                                    break;
                                }
                            case "cvss_temporal_vector":
                                {
                                    break;
                                }
                            default:
                                { break; }
                        }
                    }
                    else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("ReportItem"))
                    { }
                }
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to parse plugin \"{0}\".", pluginId));
                throw exception;
            }
        }

        private void InsertAndMapPort(SQLiteCommand sqliteCommand)
        { 
            try
            {

            }
            catch (Exception exception)
            {
                log.Error(string.Format(""));
                throw exception;
            }
        }

        private void InsertVulnerability(SQLiteCommand sqliteCommand)
        { 
            try
            {

            }
            catch (Exception exception)
            {
                log.Error(string.Format(""));
                throw exception;
            }
        }

        private void InsertUniqueFingding(SQLiteCommand sqliteCommand)
        { 
            try
            {

            }
            catch (Exception exception)
            {
                log.Error(string.Format(""));
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
            hardwarePrimaryKey = 0;
            softwarePrimaryKey = 0;
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
    }
}
