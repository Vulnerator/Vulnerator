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
        private DatabaseInterface databaseInterface = new DatabaseInterface();

        public string ReadXmlWassp(Object.File file)
        {
            try
            {
                if (file.FilePath.IsFileInUse())
                {
                    LogWriter.LogError($"'{file.FileName}' is in use; please close any open instances and try again.");
                    return "Failed; File In Use";
                }

                ParseWasspWithXmlReader(file);
                return "Processed";
            }
            catch (Exception exception)
            {
                string error = $"Unable to process WASSP file '{file.FileName}'.";
                LogWriter.LogErrorWithDebug(error, exception);
                return "Failed; See Log";
            }
        }

        private void ParseWasspWithXmlReader(Object.File file)
        {
            try
            {
                XmlReaderSettings xmlReaderSettings = GenerateXmlReaderSettings();
                if (DatabaseBuilder.sqliteConnection.State.ToString().Equals("Closed"))
                {
                    DatabaseBuilder.sqliteConnection.Open();
                }

                using (SQLiteTransaction sqliteTransaction = DatabaseBuilder.sqliteConnection.BeginTransaction())
                {
                    using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                    {
                        databaseInterface.InsertParameterPlaceholders(sqliteCommand);
                        sqliteCommand.Parameters["FindingType"].Value = "WASSP";
                        sqliteCommand.Parameters["GroupName"].Value = "All";
                        sqliteCommand.Parameters["SourceName"].Value =
                            "Windows Automated Security Scanning Program (WASSP)";
                        databaseInterface.InsertParsedFileSource(sqliteCommand, file);
                        using (XmlReader xmlReader = XmlReader.Create(file.FilePath, xmlReaderSettings))
                        {
                            ParseVulnerabilityInfoFromWassp(sqliteCommand, xmlReader);
                        }
                    }

                    sqliteTransaction.Commit();
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to parse WASSP file '{file.FileName}' using XML reader.");
                throw exception;
            }
            finally
            {
                DatabaseBuilder.sqliteConnection.Close();
            }
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
                                sqliteCommand.Parameters["FirstDiscovered"].Value =
                                    sqliteCommand.Parameters["LastObserved"].Value =
                                        xmlReader.ObtainCurrentNodeValue(false);
                                break;
                            }
                            case "host":
                            {
                                sqliteCommand.Parameters["IP_Address"].Value = xmlReader.GetAttribute("ip");
                                sqliteCommand.Parameters["DiscoveredHostName"].Value = xmlReader.GetAttribute("name");
                                sqliteCommand.Parameters["MAC_Address"].Value = xmlReader.GetAttribute("mac");
                                break;
                            }
                            case "test":
                            {
                                sqliteCommand.Parameters["UniqueVulnerabilityIdentifier"].Value =
                                    xmlReader.GetAttribute("id");
                                break;
                            }
                            case "check":
                            {
                                sqliteCommand.Parameters["VulnerabilityTitle"].Value =
                                    xmlReader.ObtainCurrentNodeValue(false);
                                break;
                            }
                            case "description":
                            {
                                sqliteCommand.Parameters["VulnerabilityDescription"].Value =
                                    xmlReader.ObtainCurrentNodeValue(false);
                                break;
                            }
                            case "vulnerability":
                            {
                                sqliteCommand.Parameters["PrimaryRawRiskIndicator"].Value =
                                    xmlReader.ObtainCurrentNodeValue(false).ToRawRisk();
                                break;
                            }
                            case "control":
                            {
                                switch (xmlReader.GetAttribute("regulation"))
                                {
                                    case "NIST":
                                    {
                                        break;
                                    }
                                    case "DOD":
                                    {
                                        break;
                                    }
                                    default:
                                    {
                                        break;
                                    }
                                }

                                break;
                            }
                            case "result":
                            {
                                sqliteCommand.Parameters["Status"].Value =
                                    xmlReader.ObtainCurrentNodeValue(false).ToVulneratorStatus();
                                break;
                            }
                            case "recommendation":
                            {
                                sqliteCommand.Parameters["FixText"].Value = xmlReader.ObtainCurrentNodeValue(false);
                                break;
                            }
                            default:
                            {
                                break;
                            }
                        }
                    }
                    else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("test"))
                    {
                        sqliteCommand.Parameters["DeltaAnalysisIsRequired"].Value = "False";
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
                LogWriter.LogError("Unable to parse vulnerability information.");
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
                LogWriter.LogError("Unable to generate XmlReaderSettings.");
                throw exception;
            }
        }
    }
}