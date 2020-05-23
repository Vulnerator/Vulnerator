using log4net;
using System;
using System.Collections.ObjectModel;
using System.Data.SQLite;
using System.Globalization;
using System.IO;
using System.Text.RegularExpressions;
using System.Xml;
using Vulnerator.Model.DataAccess;
using Vulnerator.Helper;
using Vulnerator.Model.Object;
using File = System.IO.File;

namespace Vulnerator.Model.BusinessLogic
{
    class WasspReader
    {
        private string fileNameWithoutPath = string.Empty;
        private bool UserPrefersHostName => Properties.Settings.Default.CklRequiresHostName;
        private DatabaseInterface databaseInterface = new DatabaseInterface();

        public string ReadWassp(Object.File file)
        {
            try
            {
                if (file.FilePath.IsFileInUse())
                {
                    LogWriter.LogError($"'{file.FileName}' is in use; please close any open instances and try again.");
                    return "Failed; File In Use";
                }

                HTMLtoXML htmlReader = new HTMLtoXML();
                string wasspFile = htmlReader.Convert(file.FilePath);

                if (wasspFile.Equals("Failed; See Log"))
                { return wasspFile; }
                else
                {
                    ParseWasspWithXmlReader(wasspFile, file);
                    System.IO.File.Delete(wasspFile);
                    return "Processed";
                }
            }
            catch (Exception exception)
            {
                string error = $"Unable to process WASSP file '{file.FileName}'.";
                LogWriter.LogErrorWithDebug(error, exception);
                return "Failed; See Log";
            }
        }

        private void ParseWasspWithXmlReader(string wasspFile, Object.File file)
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
                        sqliteCommand.Parameters["FindingType"].Value = "WASSP";
                        sqliteCommand.Parameters["Name"].Value = "All";
                        sqliteCommand.Parameters["SourceName"].Value = "Windows Automated Security Scanning Program (WASSP)";
                        databaseInterface.InsertParsedFileSource(sqliteCommand, file);
                        using (XmlReader xmlReader = XmlReader.Create(wasspFile, xmlReaderSettings))
                        {
                            while (xmlReader.Read())
                            {
                                if (xmlReader.IsStartElement() && xmlReader.Name.Equals("table"))
                                {
                                    while (xmlReader.Read())
                                    {
                                        if (xmlReader.NodeType == XmlNodeType.Element)
                                        {
                                            switch (xmlReader.Name)
                                            {
                                                case "MachineInfo":
                                                    {
                                                        sqliteCommand.Parameters["DiscoveredHostName"].Value = ObtainItemValue(xmlReader);
                                                        break;
                                                    }
                                                case "TestInfo":
                                                    {
                                                        sqliteCommand.Parameters["UniqueVulnerabilityIdentifier"].Value = ObtainItemValue(xmlReader);
                                                        break;
                                                    }
                                                case "DateInfo":
                                                    {
                                                        string dateTime = ObtainItemValue(xmlReader).Replace("\n", string.Empty);
                                                        sqliteCommand.Parameters["FirstDiscovered"].Value = DateTime.ParseExact(
                                                            dateTime, "ddd MMM dd HH:mm:ss yyyy", CultureInfo.InvariantCulture).ToShortDateString();
                                                        sqliteCommand.Parameters["LastObserved"].Value = sqliteCommand.Parameters["FirstDiscovered"].Value;
                                                        break;
                                                    }
                                                case "ValueInfo":
                                                    {
                                                        sqliteCommand.Parameters["VulnerabilityTitle"].Value = ObtainItemValue(xmlReader);
                                                        break;
                                                    }
                                                case "DescriptionInfo":
                                                    {
                                                        sqliteCommand.Parameters["VulnerabilityDescription"].Value = ObtainItemValue(xmlReader);
                                                        break;
                                                    }
                                                case "TestRes":
                                                    {
                                                        sqliteCommand.Parameters["Status"].Value = ObtainItemValue(xmlReader).ToVulneratorStatus();
                                                        break;
                                                    }
                                                case "VulnInfo":
                                                    {
                                                        sqliteCommand.Parameters["RawRisk"].Value = ObtainItemValue(xmlReader).ToRawRisk();
                                                        break;
                                                    }
                                                case "RecInfo":
                                                    {
                                                        sqliteCommand.Parameters["FixText"].Value = ObtainItemValue(xmlReader);
                                                        break;
                                                    }
                                                default:
                                                    { break; }
                                            }
                                        }
                                        else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("table"))
                                        {
                                            databaseInterface.InsertVulnerabilitySource(sqliteCommand);
                                            databaseInterface.InsertHardware(sqliteCommand);
                                            databaseInterface.InsertVulnerability(sqliteCommand);
                                            databaseInterface.InsertUniqueFinding(sqliteCommand);
                                            databaseInterface.UpdateUniqueFinding(sqliteCommand);
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    sqliteTransaction.Commit();
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to parse WASSP file with XML reader.");
                throw exception;
            }
            finally
            { DatabaseBuilder.sqliteConnection.Close(); }
        }

        private string ObtainItemValue(XmlReader xmlReader)
        {
            try
            {
                while (xmlReader.Read())
                {
                    if (xmlReader.IsStartElement())
                    { break; }
                }
                xmlReader.Read();
                return xmlReader.Value;
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to obtain current node value.");
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
    }
}
