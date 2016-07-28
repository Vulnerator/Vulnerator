using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Data;
using System.Data.SQLite;
using System.IO;
using System.Linq;
using System.Xml;
using Vulnerator.ViewModel;

namespace Vulnerator.Model
{
    class XmlWasspReader
    {
        private string fileNameWithoutPath = string.Empty;
        private bool UserPrefersHostName { get { return bool.Parse(ConfigAlter.ReadSettingsFromDictionary("rbHostIdentifier")); } }

        public string ReadXmlWassp(string fileName, ObservableCollection<MitigationItem> mitigationsList, string systemName)
        {
            try
            {
                if (fileName.IsFileInUse())
                {
                    WriteLog.DiagnosticsInformation(fileName, "File is in use; please close any open instances and try again.", string.Empty);
                    return "Failed; File In Use";
                }

                ParseWasspWithXmlReader(fileName, mitigationsList, systemName);
                return "Processed";
            }
            catch (Exception exception)
            {
                WriteLog.LogWriter(exception, fileName);
                return "Failed; See Log";
            }
        }

        private void ParseWasspWithXmlReader(string fileName, ObservableCollection<MitigationItem> mitigationsList, string systemName)
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

        private void ParseVulnerabilityInfoFromWassp(SQLiteCommand sqliteCommand, XmlReader xmlReader)
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

        private string ObtainXmlReaderValue(XmlReader xmlReader)
        {
            xmlReader.Read();
            return xmlReader.Value;
        }

        private string ConvertImpactToRawRisk(string impact)
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

        private string ConvertTestResultToStatus(string testResult)
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

        private string SetSqliteCommandText(string tableName)
        {
            switch (tableName)
            {
                case "Groups":
                    { return "INSERT INTO Groups VALUES (NULL, @GroupName);"; }
                case "VulnerabilitySources":
                    { return "INSERT INTO VulnerabilitySources VALUES (NULL, @Source);"; }
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

        private void InsertVulnerabilityCommand(SQLiteCommand sqliteCommand)
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

        private void InsertAssetCommand(SQLiteCommand sqliteCommand)
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
    }
}
