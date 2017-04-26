using log4net;
using System;
using System.Collections.ObjectModel;
using System.Data.SQLite;
using System.IO;
using System.Text.RegularExpressions;
using System.Xml;
using Vulnerator.Model.DataAccess;
using Vulnerator.Model.ModelHelper;
using Vulnerator.Model.Object;

namespace Vulnerator.Model.BusinessLogic
{
    class WasspReader
    {
        private string fileNameWithoutPath = string.Empty;
        private bool UserPrefersHostName { get { return bool.Parse(ConfigAlter.ReadSettingsFromDictionary("rbHostIdentifier")); } }
        private static readonly ILog log = LogManager.GetLogger(typeof(Logger));

        public string ReadWassp(string fileName, ObservableCollection<MitigationItem> mitigationsList, string systemName)
        {
            try
            {
                if (fileName.IsFileInUse())
                {
                    log.Error(fileName + " is in use; please close any open instances and try again.");
                    return "Failed; File In Use";
                }

                fileNameWithoutPath = Path.GetFileName(fileName);

                HTMLtoXML htmlReader = new HTMLtoXML();
                string wasspFile = htmlReader.Convert(fileName);

                if (wasspFile.Equals("Failed; See Log"))
                { return wasspFile; }
                else
                {
                    ParseWasspWithXmlReader(wasspFile, mitigationsList, systemName);
                    System.IO.File.Delete(wasspFile);
                    return "Processed"; 
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to process WASSP file.");
                log.Debug("Exception details:", exception);
                return "Failed; See Log";
            }
        }

        private void ParseWasspWithXmlReader(string fileName, ObservableCollection<MitigationItem> mitigationsList, string systemName)
        {
            try
            {
                XmlReaderSettings xmlReaderSettings = new XmlReaderSettings();
                xmlReaderSettings.IgnoreWhitespace = true;
                xmlReaderSettings.IgnoreComments = true;
                xmlReaderSettings.ValidationType = ValidationType.Schema;
                xmlReaderSettings.ValidationFlags = System.Xml.Schema.XmlSchemaValidationFlags.ProcessInlineSchema;
                xmlReaderSettings.ValidationFlags = System.Xml.Schema.XmlSchemaValidationFlags.ProcessSchemaLocation;

                using (SQLiteTransaction sqliteTransaction = FindingsDatabaseActions.sqliteConnection.BeginTransaction())
                {
                    using (SQLiteCommand sqliteCommand = FindingsDatabaseActions.sqliteConnection.CreateCommand())
                    {
                        sqliteCommand.Parameters.Add(new SQLiteParameter("FindingType", "WASSP"));
                        sqliteCommand.Parameters.Add(new SQLiteParameter(
                            "Source", "Windows Automated Security Scanning Program (WASSP)"));
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
                log.Error("Unable to parse WASSP file with XML reader.");
                throw exception;
            }
        }

        private void ParseVulnerabilityInfoFromWassp(SQLiteCommand sqliteCommand, XmlReader xmlReader)
        {
            try
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
                                            RetrieveAndWriteHostInformation(sqliteCommand, xmlReader);
                                            break;
                                        }
                                    case "TestInfo":
                                        {
                                            sqliteCommand.Parameters.Add(new SQLiteParameter(
                                                "VulnId", ObtainItemValue(xmlReader)));
                                            break;
                                        }
                                    case "Requirements":
                                        {
                                            RetrieveRequirements(sqliteCommand, xmlReader);
                                            break;
                                        }
                                    case "ValueInfo":
                                        {
                                            sqliteCommand.Parameters.Add(new SQLiteParameter(
                                                "VulnTitle", ObtainItemValue(xmlReader)));
                                            break;
                                        }
                                    case "DescriptionInfo":
                                        {
                                            sqliteCommand.Parameters.Add(new SQLiteParameter(
                                                "Description", ObtainItemValue(xmlReader)));
                                            break;
                                        }
                                    case "TestRes":
                                        {
                                            sqliteCommand.Parameters.Add(new SQLiteParameter(
                                                "Status", ConvertTestResultToStatus(ObtainItemValue(xmlReader))));
                                            break;
                                        }
                                    case "VulnInfo":
                                        {
                                            sqliteCommand.Parameters.Add(new SQLiteParameter(
                                                "Impact", ObtainItemValue(xmlReader)));
                                            sqliteCommand.Parameters.Add(new SQLiteParameter(
                                                "RawRisk", ConvertImpactToRawRisk(xmlReader.Value)));
                                            break;
                                        }
                                    case "RecInfo":
                                        {
                                            sqliteCommand.Parameters.Add(new SQLiteParameter(
                                                "FixText", ObtainItemValue(xmlReader)));
                                            break;
                                        }
                                    default:
                                        { break; }
                                }
                            }
                            else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("table"))
                            {
                                InsertVulnerabilityCommand(sqliteCommand);
                                sqliteCommand.CommandText = SetSqliteCommandText("UniqueFinding");
                                sqliteCommand.ExecuteNonQuery();
                                break;
                            }
                        }
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to parse vulnerability information from WASSP file.");
                throw exception;
            }
        }

        private void RetrieveAndWriteHostInformation(SQLiteCommand sqliteCommand, XmlReader xmlReader)
        {
            try
            {
                sqliteCommand.Parameters.Add(new SQLiteParameter("HostName", ObtainItemValue(xmlReader)));
                sqliteCommand.Parameters.Add(new SQLiteParameter(
                    "IpAddress", "Not Provided"));
                sqliteCommand.Parameters.Add(new SQLiteParameter("AssetIdToReport", sqliteCommand.Parameters["HostName"].Value));

                sqliteCommand.CommandText = SetSqliteCommandText("Assets");
                InsertAssetCommand(sqliteCommand);
            }
            catch (Exception exception)
            {
                log.Error("Unable to retrieve and/or write host information.");
                throw exception;
            }
        }

        private void RetrieveRequirements(SQLiteCommand sqliteCommand, XmlReader xmlReader)
        {
            try
            {
                while (xmlReader.Read())
                {
                    if (xmlReader.IsStartElement() && xmlReader.Name.Equals("a"))
                    {
                        xmlReader.Read();
                        Regex CciRegex = new Regex(@"\b[A-Z]{2}-");
                        Regex IacRegex = new Regex(@"\b[A-Z]{4}-");
                        if (CciRegex.IsMatch(xmlReader.Value))
                        {
                            if (!sqliteCommand.Parameters.Contains("NistControl"))
                            { sqliteCommand.Parameters.Add(new SQLiteParameter("NistControl", xmlReader.Value)); }
                            else
                            {
                                sqliteCommand.Parameters["NistControl"].Value =
                                    sqliteCommand.Parameters["NistControl"].Value + Environment.NewLine +
                                    xmlReader.Value;
                            }
                        }
                        else if (IacRegex.IsMatch(xmlReader.Value))
                        {
                            if (!sqliteCommand.Parameters.Contains("IaControl"))
                            { sqliteCommand.Parameters.Add(new SQLiteParameter("IaControl", xmlReader.Value)); }
                            else
                            {
                                sqliteCommand.Parameters["IaControl"].Value =
                                    sqliteCommand.Parameters["IaControl"].Value + Environment.NewLine +
                                    xmlReader.Value;
                            }
                        }
                    }
                    else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("Requirements"))
                    { break; }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to retrieve requirements node value.");
                throw exception;
            }
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
                log.Error("Unable to obtain node value.");
                throw exception;
            }
        }
        
        private string ConvertTestResultToStatus(string testResult)
        {
            try
            {
                switch (testResult)
                {
                    case "\nFail\n":
                        { return "Ongoing"; }
                    case "\nPass\n":
                        { return "Completed"; }
                    case "\nUnknown\n":
                        { return "Not Reviewed"; }
                    case "\nManual Review\n":
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

        private string ConvertImpactToRawRisk(string impact)
        {
            try
            {
                switch (impact)
                {
                    case "\nHigh\n":
                        { return "I"; }
                    case "\nMedium\n":
                        { return "II"; }
                    case "\nLow\n":
                        { return "III"; }
                    case "\nInformational\n":
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
                log.Error("Unable to create command to insert vulnerability.");
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
                log.Error("Unable to create command to insert asset.");
                throw exception;
            }
        }
    }
}
