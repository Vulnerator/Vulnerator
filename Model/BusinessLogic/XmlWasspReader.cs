using log4net;
using System;
using System.Collections.ObjectModel;
using System.Data.SQLite;
using System.IO;
using System.Text.RegularExpressions;
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
        string _groupName = null;

        public string ReadXmlWassp(Object.File file, string groupName)
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
                        sqliteCommand.Parameters["GroupName"].Value = string.IsNullOrWhiteSpace(_groupName) ? "All" : _groupName;
                        sqliteCommand.Parameters["SourceName"].Value =
                            "Windows Automated Security Scanning Program (WASSP)";
                        sqliteCommand.Parameters["SourceVersion"].Value = string.Empty;
                        sqliteCommand.Parameters["SourceRelease"].Value = string.Empty;
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
                            case "scanner":
                            {
                                ObtainWasspVersion(xmlReader, sqliteCommand);
                                break;
                            }
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
                                sqliteCommand.Parameters["DiscoveredHostName"].Value = xmlReader.GetAttribute("name").Trim();
                                sqliteCommand.Parameters["DisplayedHostName"].Value = sqliteCommand.Parameters["DiscoveredHostName"].Value;
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
                                string parsed = xmlReader.ObtainCurrentNodeValue(false).ToString();
                                Regex regex = new Regex(Properties.Resources.RegexWasspRawRisk);
                                sqliteCommand.Parameters["PrimaryRawRiskIndicator"].Value =
                                    regex.Match(parsed).Value.ToRawRisk();
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
                                }

                                break;
                            }
                            case "result":
                            {
                                sqliteCommand.Parameters["Status"].Value =
                                    xmlReader.ObtainCurrentNodeValue(false).ToString().ToVulneratorStatus();
                                break;
                            }
                            case "recommendation":
                            {
                                sqliteCommand.Parameters["FixText"].Value = xmlReader.ObtainCurrentNodeValue(false);
                                break;
                            }
                        }
                    }
                    else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("test"))
                    {
                        sqliteCommand.Parameters["DeltaAnalysisIsRequired"].Value = "False";
                        if (sqliteCommand.Parameters["VulnerabilityVersion"].Value == DBNull.Value)
                        { sqliteCommand.Parameters["VulnerabilityVersion"].Value = string.Empty; }
                        if (sqliteCommand.Parameters["VulnerabilityRelease"].Value == DBNull.Value)
                        { sqliteCommand.Parameters["VulnerabilityRelease"].Value = string.Empty; }
                        databaseInterface.InsertVulnerabilitySource(sqliteCommand);
                        databaseInterface.InsertHardware(sqliteCommand);
                        databaseInterface.InsertAndMapIpAddress(sqliteCommand);
                        databaseInterface.InsertAndMapMacAddress(sqliteCommand);
                        databaseInterface.InsertVulnerability(sqliteCommand);
                        databaseInterface.MapVulnerabilityToSource(sqliteCommand);
                        databaseInterface.UpdateUniqueFinding(sqliteCommand);
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

        private void ObtainWasspVersion(XmlReader xmlReader, SQLiteCommand sqliteCommand)
        {
            try
            {
                while (xmlReader.Read())
                {
                    if (xmlReader.IsStartElement() && xmlReader.Name.Equals("version"))
                    {
                        sqliteCommand.Parameters["SourceVersion"].Value =
                            xmlReader.ObtainCurrentNodeValue(false);
                        return;
                    }
                    if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("scanner"))
                    { return; }
                }

                
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to obtain WASSP version information.");
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