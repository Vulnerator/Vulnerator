using log4net;
using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Xml;
using Vulnerator.Model.ModelHelper;
using Vulnerator.Model.Object;
using Vulnerator.Model.DataAccess;

namespace Vulnerator.Model.BusinessLogic
{
    public class AnsibleReader
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(Logger));
        DatabaseInterface databaseInterface = new DatabaseInterface();
        private string[] persistentParameters = new string[] { "Group_Name", "Finding_Source_File_Name", "Source_Name", "Scan_IP", "Host_Name", "Finding_Type" };

        public string ReadAnsibleFile(Object.File file)
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
                        databaseInterface.InsertGroup(sqliteCommand, file);
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
                                                foreach (SQLiteParameter parameter in sqliteCommand.Parameters)
                                                {
                                                    if (!persistentParameters.Contains(parameter.ParameterName))
                                                    { parameter.Value = string.Empty; }
                                                }
                                                break;
                                            }
                                        default:
                                            { break; }
                                    }
                                }
                                else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals(""))
                                {

                                }
                            }
                        }
                    }
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
                sqliteCommand.Parameters["Discovered_Host_Name"].Value = xmlReader.GetAttribute("hostname");
                sqliteCommand.Parameters["Displayed_Host_Name"].Value = xmlReader.GetAttribute("hostname");
                string ipAddress = xmlReader.GetAttribute("ip_address");
                string macAddress = xmlReader.GetAttribute("mac_address");
                databaseInterface.InsertHardware(sqliteCommand);
                ParseIpAndMacAddress(sqliteCommand, ipAddress);
                ParseIpAndMacAddress(sqliteCommand, macAddress);
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to insert Hardware \"{0}\".", sqliteCommand.Parameters["Discovered_Host_Name"].Value.ToString()));
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
                                    PrepareIpAndMacAddress(sqliteCommand, match.ToString(), "MAC_Addresses");
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
                sqliteCommand.Parameters["Source_Name"].Value = xmlReader.GetAttribute("name");
                sqliteCommand.Parameters["Source_Version"].Value = xmlReader.GetAttribute("version");
                sqliteCommand.Parameters["Source_Release"].Value = xmlReader.GetAttribute("release");
                databaseInterface.InsertVulnerabilitySource(sqliteCommand);
            }
            catch (Exception exception)
            {
                log.Error(string.Format(""));
                throw exception;
            }
        }

        private void ParseFindingData(SQLiteCommand sqliteCommand, XmlReader xmlReader)
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
    }
}
