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
        private bool UserPrefersHostName { get { return bool.Parse(ConfigAlter.ReadSettingsFromDictionary("rbHostIdentifier")); } }
        private static readonly ILog log = LogManager.GetLogger(typeof(Logger));

        public string ReadXmlWassp(string fileName, string systemName)
        {
            try
            {
                if (fileName.IsFileInUse())
                {
                    log.Error(fileName + " is in use; please close any open instances and try again.");
                    return "Failed; File In Use";
                }

                ParseWasspWithXmlReader(fileName, systemName);
                return "Processed";
            }
            catch (Exception exception)
            {
                log.Error("Unable to process WASSP file.");
                log.Debug("Exception details:", exception);
                return "Failed; See Log";
            }
        }

        private void ParseWasspWithXmlReader(string fileName, string systemName)
        {
            try
            {
                XmlReaderSettings xmlReaderSettings = new XmlReaderSettings();
                xmlReaderSettings.IgnoreWhitespace = true;
                xmlReaderSettings.IgnoreComments = true;
                xmlReaderSettings.ValidationType = ValidationType.DTD;
                xmlReaderSettings.ValidationFlags = System.Xml.Schema.XmlSchemaValidationFlags.ProcessSchemaLocation;
                xmlReaderSettings.DtdProcessing = DtdProcessing.Ignore;
                fileNameWithoutPath = Path.GetFileName(fileName);

                using (SQLiteTransaction sqliteTransaction = FindingsDatabaseActions.sqliteConnection.BeginTransaction())
                {
                    using (SQLiteCommand sqliteCommand = FindingsDatabaseActions.sqliteConnection.CreateCommand())
                    {
                        sqliteCommand.Parameters.Add(new SQLiteParameter("FindingType", "WASSP"));
                        sqliteCommand.Parameters.Add(new SQLiteParameter("Source", "Windows Automated Security Scanning Program (WASSP)"));
                        sqliteCommand.CommandText = SetSqliteCommandText("VulnerabilitySources");
                        sqliteCommand.ExecuteNonQuery();
                        sqliteCommand.Parameters.Add(new SQLiteParameter("GroupName", systemName));
                        sqliteCommand.CommandText = SetSqliteCommandText("Groups");
                        sqliteCommand.ExecuteNonQuery();

                        sqliteCommand.Parameters.Add(new SQLiteParameter("FileName", fileNameWithoutPath));
                        sqliteCommand.CommandText = SetSqliteCommandText("FileNames");
                        sqliteCommand.ExecuteNonQuery();

                        using (XmlReader xmlReader = XmlReader.Create(fileName, xmlReaderSettings))
                        {
                            ParseVulnerabilityInfoFromWassp(sqliteCommand, xmlReader);
                        }
                    }
                    sqliteTransaction.Commit();
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to parse WASSP file using XML reader.");
                throw exception;
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
                            case "host":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("IpAddress", xmlReader.GetAttribute("ip")));
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("HostName", xmlReader.GetAttribute("name")));
                                    if (sqliteCommand.Parameters.Contains("HostName") && UserPrefersHostName &&
                                        !string.IsNullOrWhiteSpace(sqliteCommand.Parameters["Hostname"].Value.ToString()))
                                    {
                                        sqliteCommand.Parameters.Add(new SQLiteParameter(
                                          "AssetIdToReport", sqliteCommand.Parameters["HostName"].Value));
                                    }
                                    else
                                    {
                                        sqliteCommand.Parameters.Add(new SQLiteParameter(
                                          "AssetIdToReport", sqliteCommand.Parameters["IpAddress"].Value));
                                    }
                                    InsertAssetCommand(sqliteCommand);
                                    break;
                                }
                            case "test":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("VulnId", xmlReader.GetAttribute("id")));
                                    break;
                                }
                            case "check":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("VulnTitle", ObtainXmlReaderValue(xmlReader)));
                                    break;
                                }
                            case "description":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Description", ObtainXmlReaderValue(xmlReader)));
                                    break;
                                }
                            case "vulnerability":
                                {
                                    xmlReader.Read();
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Impact", xmlReader.Value));
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("RawRisk", ConvertImpactToRawRisk(xmlReader.Value)));
                                    break;
                                }
                            case "control":
                                {
                                    switch (xmlReader.GetAttribute("regulation"))
                                    {
                                        case "NIST":
                                            {
                                                xmlReader.Read();
                                                if (!sqliteCommand.Parameters.Contains("NistControl"))
                                                { sqliteCommand.Parameters.Add(new SQLiteParameter("NistControl", xmlReader.Value)); }
                                                else
                                                {
                                                    sqliteCommand.Parameters["NistControl"].Value =
                                                        sqliteCommand.Parameters["NistControl"].Value + Environment.NewLine +
                                                        xmlReader.Value;
                                                }
                                                break;
                                            }
                                        case "DOD":
                                            {
                                                xmlReader.Read();
                                                if (!sqliteCommand.Parameters.Contains("IaControl"))
                                                { sqliteCommand.Parameters.Add(new SQLiteParameter("IaControl", xmlReader.Value)); }
                                                else
                                                {
                                                    sqliteCommand.Parameters["IaControl"].Value =
                                                        sqliteCommand.Parameters["IaControl"].Value + Environment.NewLine +
                                                        xmlReader.Value;
                                                }
                                                break;
                                            }
                                        default:
                                            { break; }
                                    }
                                    break;
                                }
                            case "result":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Status", ConvertTestResultToStatus(ObtainXmlReaderValue(xmlReader))));
                                    break;
                                }
                            case "recommendation":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("FixText", ObtainXmlReaderValue(xmlReader)));
                                    break;
                                }
                            default:
                                { break; }
                        }
                    }
                    else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("test"))
                    {
                        InsertVulnerabilityCommand(sqliteCommand);
                        sqliteCommand.CommandText = SetSqliteCommandText("UniqueFinding");
                        sqliteCommand.ExecuteNonQuery();
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
    }
}
