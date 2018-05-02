using log4net;
using System;
using System.Collections.ObjectModel;
using System.Data.SQLite;
using System.IO;
using System.Xml;
using Vulnerator.Model.DataAccess;
using Vulnerator.Helper;
using Vulnerator.Model.Object;

namespace Vulnerator.Model.BusinessLogic
{
    class XmlWasspReader
    {
        private string fileNameWithoutPath = string.Empty;
        private static readonly ILog log = LogManager.GetLogger(typeof(Logger));
        private DatabaseInterface databaseInterface = new DatabaseInterface();

        public string ReadXmlWassp(Object.File file)
        {
            try
            {
                if (file.FilePath.IsFileInUse())
                {
                    log.Error(file.FilePath + " is in use; please close any open instances and try again.");
                    return "Failed; File In Use";
                }

                ParseWasspWithXmlReader(file);
                return "Processed";
            }
            catch (Exception exception)
            {
                log.Error("Unable to process WASSP file.");
                log.Debug("Exception details:", exception);
                return "Failed; See Log";
            }
        }

        private void ParseWasspWithXmlReader(Object.File file)
        {
            try
            {
                XmlReaderSettings xmlReaderSettings = GenerateXmlReaderSettings();
                if (DatabaseBuilder.sqliteConnection.State.ToString().Equals("Closed"))
                { DatabaseBuilder.sqliteConnection.Open(); }
                using (SQLiteTransaction sqliteTransaction = DatabaseBuilder.sqliteConnection.BeginTransaction())
                {
                    using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                    {
                        databaseInterface.InsertParameterPlaceholders(sqliteCommand);
                        sqliteCommand.Parameters["Finding_Type"].Value =  "WASSP";
                        sqliteCommand.Parameters["Source_Name"].Value = "Windows Automated Security Scanning Program (WASSP)";
                        databaseInterface.InsertParsedFileSource(sqliteCommand, file);
                        using (XmlReader xmlReader = XmlReader.Create(file.FilePath, xmlReaderSettings))
                        { ParseVulnerabilityInfoFromWassp(sqliteCommand, xmlReader); }
                    }
                    sqliteTransaction.Commit();
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to parse WASSP file using XML reader.");
                throw exception;
            }
            finally
            { DatabaseBuilder.sqliteConnection.Close(); }
        }

        private void ParseVulnerabilityInfoFromWassp(SQLiteCommand sqliteCommand, XmlReader xmlReader)
        {
            try
            {
                while (xmlReader.Read())
                {
                    if (xmlReader.IsStartElement())
                    {
                        switch (xmlReader.Name)
                        {
                            case "date":
                                {
                                    sqliteCommand.Parameters["First_Discovered"].Value = xmlReader.ObtainCurrentNodeValue(false);
                                    sqliteCommand.Parameters["Last_Observed"].Value = xmlReader.ObtainCurrentNodeValue(false);
                                    break;
                                }
                            case "host":
                                {
                                    sqliteCommand.Parameters["IP_Address"].Value = xmlReader.GetAttribute("ip");
                                    sqliteCommand.Parameters["Host_Name"].Value = xmlReader.GetAttribute("name");
                                    sqliteCommand.Parameters["MAC_Address"].Value = xmlReader.GetAttribute("mac");
                                    break;
                                }
                            case "test":
                                {
                                    sqliteCommand.Parameters["Unique_Vulnerability_Identifier"].Value = xmlReader.GetAttribute("id");
                                    break;
                                }
                            case "check":
                                {
                                    sqliteCommand.Parameters["Vulnerability_Title"].Value = xmlReader.ObtainCurrentNodeValue(false);
                                    break;
                                }
                            case "description":
                                {
                                    sqliteCommand.Parameters["Vulnerability_Description"].Value = xmlReader.ObtainCurrentNodeValue(false);
                                    break;
                                }
                            case "vulnerability":
                                {
                                    sqliteCommand.Parameters["Raw_Risk"].Value = xmlReader.ObtainCurrentNodeValue(false).ToRawRisk();
                                    break;
                                }
                            case "control":
                                {
                                    switch (xmlReader.GetAttribute("regulation"))
                                    {
                                        case "NIST":
                                            { break; }
                                        case "DOD":
                                            { break; }
                                        default:
                                            { break; }
                                    }
                                    break;
                                }
                            case "result":
                                {
                                    sqliteCommand.Parameters["Status"].Value = xmlReader.ObtainCurrentNodeValue(false).ToVulneratorStatus();
                                    break;
                                }
                            case "recommendation":
                                {
                                    sqliteCommand.Parameters["Fix_Text"].Value = xmlReader.ObtainCurrentNodeValue(false);
                                    break;
                                }
                            default:
                                { break; }
                        }
                    }
                    else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("test"))
                    {
                        databaseInterface.InsertVulnerabilitySource(sqliteCommand);
                        databaseInterface.InsertHardware(sqliteCommand);
                        databaseInterface.InsertAndMapIpAddress(sqliteCommand);
                        databaseInterface.InsertAndMapMacAddress(sqliteCommand);
                        databaseInterface.InsertVulnerability(sqliteCommand);
                        databaseInterface.InsertUniqueFinding(sqliteCommand);
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to parse vulnerability information.");
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
                xmlReaderSettings.DtdProcessing = DtdProcessing.Parse;
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
