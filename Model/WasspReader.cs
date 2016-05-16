using System;
using System.Collections.ObjectModel;
using System.Data.SQLite;
using System.IO;
using System.Text.RegularExpressions;
using System.Xml;

namespace Vulnerator.Model
{
    class WasspReader
    {
        private string fileNameWithoutPath = string.Empty;

        public string ReadWassp(string fileName, ObservableCollection<MitigationItem> mitigationsList, string systemName)
        {
            try
            {
                if (fileName.IsFileInUse())
                {
                    WriteLog.DiagnosticsInformation(fileName, "File is in use; please close any open instances and try again.", string.Empty);
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
                    File.Delete(wasspFile);
                    return "Processed"; 
                }
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

        private void ParseVulnerabilityInfoFromWassp(SQLiteCommand sqliteCommand, XmlReader xmlReader)
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

        private void RetrieveAndWriteHostInformation(SQLiteCommand sqliteCommand, XmlReader xmlReader)
        {
            sqliteCommand.Parameters.Add(new SQLiteParameter(
                                            "HostName", ObtainItemValue(xmlReader)));
            sqliteCommand.Parameters.Add(new SQLiteParameter(
                "AssetIdToReport", sqliteCommand.Parameters["HostName"].Value));
            sqliteCommand.Parameters.Add(new SQLiteParameter(
                "IpAddress", "Not Provided"));
            sqliteCommand.CommandText = SetSqliteCommandText("Assets");
            InsertAssetCommand(sqliteCommand);
        }

        private void RetrieveRequirements(SQLiteCommand sqliteCommand, XmlReader xmlReader)
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
                        if (!sqliteCommand.Parameters.Contains("CciReference"))
                        { sqliteCommand.Parameters.Add(new SQLiteParameter("CciReference", xmlReader.Value)); }
                        else
                        {
                            sqliteCommand.Parameters["CciReference"].Value =
                                sqliteCommand.Parameters["CciReference"].Value + Environment.NewLine +
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

        private string ObtainItemValue(XmlReader xmlReader)
        {
            while (xmlReader.Read())
            {
                if (xmlReader.IsStartElement())
                { break; }
            }
            xmlReader.Read();
            return xmlReader.Value;
        }
        
        private string ConvertTestResultToStatus(string testResult)
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

        private string ConvertImpactToRawRisk(string impact)
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
                if (parameter.ParameterName.Equals("CciReference"))
                { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(84, "@CciReference, "); }
                if (parameter.ParameterName.Equals("IaControl"))
                { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(84, "@IaControl, "); }
                if (parameter.ParameterName.Equals("FixText"))
                { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(84, "@FixText, "); }
            }
            foreach (SQLiteParameter parameter in sqliteCommand.Parameters)
            {
                if (parameter.ParameterName.Equals("CciReference"))
                { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(27, "CciReference, "); }
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
