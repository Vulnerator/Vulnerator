using log4net;
using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.Linq;
using System.Text.RegularExpressions;
using System.Xml;
using Vulnerator.Helper;
using Vulnerator.Model.DataAccess;
using Vulnerator.Model.Object;

namespace Vulnerator.Model.BusinessLogic
{
    public class AnsibleReader
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(Logger));
        DatabaseInterface databaseInterface = new DatabaseInterface();
        private string[] persistentParameters = new string[] {
            "Group_Name", "Finding_Source_File_Name", "Source_Name", "Source_Version", "Source_Release", "Scan_IP", "Host_Name", "Finding_Type"
        };
        List<string> ccis = new List<string>();


        public string ReadAnsibleFile(File file)
        { 
            try
            {
                if (file.FilePath.IsFileInUse())
                {
                    log.Error(file.FileName + " is in use; please close any open instances and try again.");
                    return "Failed; File In Use";
                }

                if (!DatabaseBuilder.sqliteConnection.State.ToString().Equals("Open"))
                { DatabaseBuilder.sqliteConnection.Open(); }
                using (SQLiteTransaction sqliteTransaction = DatabaseBuilder.sqliteConnection.BeginTransaction())
                {
                    using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                    {
                        databaseInterface.InsertParameterPlaceholders(sqliteCommand);
                        sqliteCommand.Parameters["Finding_Type"].Value = "CKL";
                        databaseInterface.InsertGroup(sqliteCommand, file);
                        databaseInterface.InsertParsedFileSource(sqliteCommand, file);
                        using (XmlReader xmlReader = XmlReader.Create(file.FilePath, GenerateXmlReaderSettings()))
                        {
                            while (xmlReader.Read())
                            {
                                if (xmlReader.IsStartElement())
                                {
                                    switch (xmlReader.Name)
                                    {
                                        case "ansible":
                                            {
                                                ParseHostData(sqliteCommand, xmlReader);
                                                break;
                                            }
                                        case "stig":
                                            {
                                                ParseSourceData(sqliteCommand, xmlReader);
                                                break;
                                            }
                                        case "finding":
                                            {
                                                ParseFindingData(sqliteCommand, xmlReader);
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
                log.Error("Unable to process Ansible file.");
                log.Debug("Exception details:", exception);
                return "Failed; See Log";
            }
            finally
            { DatabaseBuilder.sqliteConnection.Close(); }
        }

        private void ParseHostData(SQLiteCommand sqliteCommand, XmlReader xmlReader)
        {

            try
            {
                sqliteCommand.Parameters["Host_Name"].Value = xmlReader.GetAttribute("hostname");
                sqliteCommand.Parameters["Displayed_Host_Name"].Value = xmlReader.GetAttribute("hostname");
                string ipAddress = xmlReader.GetAttribute("ip_address");
                string macAddress = xmlReader.GetAttribute("mac_address");
                databaseInterface.InsertHardware(sqliteCommand);
                databaseInterface.MapHardwareToGroup(sqliteCommand);
                ParseIpAndMacAddress(sqliteCommand, ipAddress);
                ParseIpAndMacAddress(sqliteCommand, macAddress);
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to insert Hardware \"{0}\".", sqliteCommand.Parameters["Host_Name"].Value.ToString()));
                throw exception;
            }
        }

        private void ParseIpAndMacAddress(SQLiteCommand sqliteCommand, string parameter)
        {
            try
            {
                string[] regexArray = new string[] { Properties.Resources.RegexIPv4, Properties.Resources.RegexIPv6, Properties.Resources.RegexMAC };
                foreach (string expression in regexArray)
                {
                    Regex regex = new Regex(expression);
                    foreach (Match match in regex.Matches(parameter))
                    {
                        switch (Array.IndexOf(regexArray, expression))
                        {
                            case 0:
                                {
                                    PrepareIpAndMacAddress(sqliteCommand, match.ToString(), "IP_Addresses");
                                    break;
                                }
                            case 1:
                                {
                                    PrepareIpAndMacAddress(sqliteCommand, match.ToString(), "IP_Addresses");
                                    break;
                                }
                            case 2:
                                {
                                    string mac = match.ToString();
                                    if (mac.StartsWith("0:"))
                                    { mac = mac.Insert(0, "0"); }
                                    PrepareIpAndMacAddress(sqliteCommand, mac, "MAC_Addresses");
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

        private void PrepareIpAndMacAddress(SQLiteCommand sqliteCommand, string item, string table)
        {
            try
            {
                if (table.Equals("IP_Addresses"))
                {
                    sqliteCommand.Parameters["IP_Address"].Value = item;
                    databaseInterface.InsertAndMapIpAddress(sqliteCommand);
                }
                else
                {
                    sqliteCommand.Parameters["MAC_Address"].Value = item;
                    databaseInterface.InsertAndMapMacAddress(sqliteCommand);
                }
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to insert IP / MAC address \"{0}\" into database.", item));
                throw exception;
            }
        }

        private void ParseSourceData(SQLiteCommand sqliteCommand, XmlReader xmlReader)
        { 
            try
            {
                sqliteCommand.Parameters["Source_Name"].Value = xmlReader.GetAttribute("name").ToSanitizedSource();
                sqliteCommand.Parameters["Source_Version"].Value = xmlReader.GetAttribute("version");
                sqliteCommand.Parameters["Source_Release"].Value = xmlReader.GetAttribute("release");
                databaseInterface.UpdateVulnerabilitySource(sqliteCommand);
                databaseInterface.InsertVulnerabilitySource(sqliteCommand);
                databaseInterface.MapHardwareToVulnerabilitySource(sqliteCommand);
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to parse Ansible source data."));
                throw exception;
            }
        }

        private void ParseFindingData(SQLiteCommand sqliteCommand, XmlReader xmlReader)
        { 
            try
            {
                sqliteCommand.Parameters["Vulnerability_Group_ID"].Value = xmlReader.GetAttribute("v_id");
                string rule = xmlReader.GetAttribute("rule_id");
                string ruleRelease = string.Empty;
                if (rule.Contains("_"))
                { rule = rule.Split('_')[0]; }
                if (rule.Contains("r"))
                {
                    ruleRelease = rule.Split('r')[1];
                    rule = rule.Split('r')[0];
                }
                sqliteCommand.Parameters["Unique_Vulnerability_Identifier"].Value = rule.Trim();
                sqliteCommand.Parameters["Vulnerability_Version"].Value = ruleRelease.Trim();
                sqliteCommand.Parameters["Raw_Risk"].Value = xmlReader.GetAttribute("raw_risk");
                sqliteCommand.Parameters["First_Discovered"].Value = DateTime.Parse(xmlReader.GetAttribute("datetime"));
                sqliteCommand.Parameters["Last_Observed"].Value = DateTime.Parse(xmlReader.GetAttribute("datetime"));
                while (xmlReader.Read())
                {
                    if (xmlReader.IsStartElement())
                    {
                        switch (xmlReader.Name)
                        {
                            case "title":
                                {
                                    sqliteCommand.Parameters["Vulnerability_Title"].Value = Regex.Replace(xmlReader.ObtainCurrentNodeValue(true), @"\s+", " ").Trim();
                                    break;
                                }
                            case "discussion":
                                {
                                    sqliteCommand.Parameters["Vulnerability_Description"].Value = Regex.Replace(xmlReader.ObtainCurrentNodeValue(true), @"\s+", " ").Trim();
                                    break;
                                }
                            case "check_content":
                                {
                                    sqliteCommand.Parameters["Check_Content"].Value = Regex.Replace(xmlReader.ObtainCurrentNodeValue(true), @"\s+", " ").Trim();
                                    break;
                                }
                            case "fix_text":
                                {
                                    sqliteCommand.Parameters["Fix_Text"].Value = Regex.Replace(xmlReader.ObtainCurrentNodeValue(true), @"\s+", " ").Trim();
                                    break;
                                }
                            case "procedure":
                                {
                                    sqliteCommand.Parameters["Tool_Generated_Output"].Value = Regex.Replace(xmlReader.ObtainCurrentNodeValue(true), @"\s+", " ").Trim();
                                    break;
                                }
                            case "output":
                                {
                                    sqliteCommand.Parameters["Tool_Generated_Output"].Value = string.Format(
                                        "{0}{1}{2}{3}{4}{5}",
                                        sqliteCommand.Parameters["Tool_Generated_Output"].Value.ToString(),
                                        Environment.NewLine,
                                        Environment.NewLine,
                                        "Output:",
                                        Environment.NewLine,
                                        xmlReader.ObtainCurrentNodeValue(true).Trim()
                                        );
                                    break;
                                }
                            case "comments":
                                {
                                    sqliteCommand.Parameters["Comments"].Value = Regex.Replace(xmlReader.ObtainCurrentNodeValue(true), @"\s+", " ").Trim();
                                    break;
                                }
                            case "status":
                                {
                                    sqliteCommand.Parameters["Status"].Value = Regex.Replace(xmlReader.ObtainCurrentNodeValue(true), @"\s+", " ")
                                        .Trim()
                                        .ToVulneratorStatus();
                                    break;
                                }
                            case "cci":
                                {
                                    Regex regex = new Regex(Properties.Resources.RegexCciSelector);
                                    ccis.Add(regex.Match(xmlReader.ObtainCurrentNodeValue(true)).ToString());
                                    break;
                                }
                            default:
                                { break; }
                        }
                    }
                    else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("finding"))
                    {
                        databaseInterface.UpdateVulnerability(sqliteCommand);
                        databaseInterface.InsertVulnerability(sqliteCommand);
                        databaseInterface.MapVulnerabilityToSource(sqliteCommand);
                        databaseInterface.UpdateUniqueFinding(sqliteCommand);
                        databaseInterface.InsertUniqueFinding(sqliteCommand);
                        foreach (string cci in ccis)
                        {
                            sqliteCommand.Parameters["CCI"].Value = cci.Replace("CCI-", string.Empty).Trim();
                            if (string.IsNullOrWhiteSpace(sqliteCommand.Parameters["CCI"].Value.ToString()))
                            { continue; }
                            databaseInterface.MapVulnerabilityToCci(sqliteCommand);
                        }
                        foreach (SQLiteParameter parameter in sqliteCommand.Parameters)
                        {
                            if (!persistentParameters.Contains(parameter.ParameterName))
                            { parameter.Value = string.Empty; }
                        }
                        ccis.Clear();
                        return;
                    } 
                }
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to parse finding node for \"{0}\".", 
                    sqliteCommand.Parameters["Unique_Vulnerability_Identifier"].Value.ToString()));
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
    }
}