using log4net;
using System;
using System.Collections.ObjectModel;
using System.Data.SQLite;
using System.IO;
using System.Xml;
using Vulnerator.Model.DataAccess;
using Vulnerator.Model.ModelHelper;
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
                        databaseInterface.InsertGroup(sqliteCommand, file);
                        databaseInterface.InsertParsedFile(sqliteCommand, file);
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
                                    sqliteCommand.Parameters["First_Discovered"].Value = ObtainXmlReaderValue(xmlReader);
                                    sqliteCommand.Parameters["Last_Observed"].Value = ObtainXmlReaderValue(xmlReader);
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
                                    sqliteCommand.Parameters["Vulnerability_Title"].Value = ObtainXmlReaderValue(xmlReader);
                                    break;
                                }
                            case "description":
                                {
                                    sqliteCommand.Parameters["Vulnerability_Description"].Value = ObtainXmlReaderValue(xmlReader);
                                    break;
                                }
                            case "vulnerability":
                                {
                                    sqliteCommand.Parameters["Raw_Risk"].Value = ConvertImpactToRawRisk(ObtainXmlReaderValue(xmlReader));
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
                                    sqliteCommand.Parameters["Status"].Value = ConvertTestResultToStatus(ObtainXmlReaderValue(xmlReader));
                                    break;
                                }
                            case "recommendation":
                                {
                                    sqliteCommand.Parameters["Fix_Text"].Value = ObtainXmlReaderValue(xmlReader);
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

        private string ObtainXmlReaderValue(XmlReader xmlReader)
        {
            try
            {
                xmlReader.Read();
                return xmlReader.Value;
            }
            catch (Exception exception)
            {
                log.Error("Unable to obtain node value.");
                throw exception;
            }
        }

        private string ConvertImpactToRawRisk(string impact)
        {
            try
            {
                switch (impact)
                {
                    case "High":
                        { return "I"; }
                    case "Medium":
                        { return "II"; }
                    case "Low":
                        { return "III"; }
                    case "Informational":
                        { return "IV"; }
                    default:
                        { return "Undetermined"; }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to convert impact to raw risk.");
                throw exception;
            }
        }

        private string ConvertTestResultToStatus(string testResult)
        {
            try
            {
                switch (testResult)
                {
                    case "Fail":
                        { return "Ongoing"; }
                    case "Pass":
                        { return "Completed"; }
                    case "Unknown":
                        { return "Not Reviewed"; }
                    case "Manual Review":
                        { return "Not Reviewed"; }
                    default:
                        { return "Not Reviewed"; }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to convert test result to status.");
                throw exception;
            }
        }

        private string SetSqliteCommandText(string tableName)
        {
            try
            {
                switch (tableName)
                {
                    case "Groups":
                        { return "INSERT INTO Groups VALUES (NULL, @GroupName);"; }
                    case "VulnerabilitySources":
                        { return "INSERT INTO VulnerabilitySources VALUES (NULL, @Source, '', '');"; }
                    case "Assets":
                        {
                            return "INSERT INTO Assets (AssetIdToReport, GroupIndex) VALUES (@AssetIdToReport, " +
                                  "(SELECT GroupIndex FROM Groups WHERE GroupName = @GroupName));";
                        }
                    case "FileNames":
                        { return "INSERT INTO FileNames VALUES (NULL, @FileName);"; }
                    case "ScapScores":
                        {
                            return "INSERT INTO ScapScores VALUES (@ScapScore, " +
                                "(SELECT AssetIndex FROM Assets WHERE AssetIdToReport = @AssetIdToReport), " +
                                "(SELECT SourceIndex FROM VulnerabilitySources WHERE Source = @Source));";
                        }
                    case "Vulnerability":
                        {
                            return "INSERT INTO Vulnerability (VulnId, VulnTitle, Description, RawRisk, " +
                                "Impact) VALUES (@VulnId, @VulnTitle, @Description, @RawRisk, @Impact);";
                        }
                    case "UniqueFinding":
                        {
                            return "INSERT INTO UniqueFinding (FindingTypeIndex, SourceIndex, StatusIndex, " +
                                "FileNameIndex, VulnerabilityIndex, AssetIndex) VALUES (" +
                                "(SELECT FindingTypeIndex FROM FindingTypes WHERE FindingType = @FindingType), " +
                                "(SELECT SourceIndex FROM VulnerabilitySources WHERE Source = @Source), " +
                                "(SELECT StatusIndex FROM FindingStatuses WHERE Status = @Status), " +
                                "(SELECT FileNameIndex FROM FileNames WHERE FileName = @FileName), " +
                                "(SELECT VulnerabilityIndex FROM Vulnerability WHERE VulnId = @VulnId), " +
                                "(SELECT AssetIndex FROM Assets WHERE AssetIdToReport = @AssetIdToReport));";
                        }
                    default:
                        { break; }
                }
                return "";
            }
            catch (Exception exception)
            {
                log.Error("Unable to set SQLite command text.");
                throw exception;
            }
        }

        private void InsertVulnerabilityCommand(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = SetSqliteCommandText("Vulnerability");
                foreach (SQLiteParameter parameter in sqliteCommand.Parameters)
                {
                    if (parameter.ParameterName.Equals("NistControl"))
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(84, "@NistControl, "); }
                    if (parameter.ParameterName.Equals("IaControl"))
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(84, "@IaControl, "); }
                    if (parameter.ParameterName.Equals("FixText"))
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(84, "@FixText, "); }
                }
                foreach (SQLiteParameter parameter in sqliteCommand.Parameters)
                {
                    if (parameter.ParameterName.Equals("NistControl"))
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(27, "NistControl, "); }
                    if (parameter.ParameterName.Equals("IaControl"))
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(27, "IaControl, "); }
                    if (parameter.ParameterName.Equals("FixText"))
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(27, "FixText, "); }
                }
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                log.Error("Unable to create insert vulnerability command.");
                throw exception;
            }
        }

        private void InsertAssetCommand(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = SetSqliteCommandText("Assets");
                foreach (SQLiteParameter parameter in sqliteCommand.Parameters)
                {
                    if (parameter.ParameterName.Equals("HostName"))
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(57, "@HostName, "); }
                    if (parameter.ParameterName.Equals("IpAddress"))
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(57, "@IpAddress, "); }
                }
                foreach (SQLiteParameter parameter in sqliteCommand.Parameters)
                {
                    if (parameter.ParameterName.Equals("HostName"))
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(20, "HostName, "); }
                    if (parameter.ParameterName.Equals("IpAddress"))
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(20, "IpAddress, "); }
                }
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                log.Error("Unable to create insert asset command.");
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
