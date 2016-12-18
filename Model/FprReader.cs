using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Data.SQLite;
using System.IO;
using System.IO.Compression;
using System.Linq;
using log4net;
using System.Xml;

namespace Vulnerator.Model
{
    class FprReader
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(Logger));
        private string softwareName = string.Empty;
        private string lastObserved = string.Empty;
        private string file = string.Empty;
        private string sourcePlaceholder = "HPE Fortify SCA";
        private List<FprDescription> fprDescriptionList = new List<FprDescription>();

        public string ReadFpr(string fileName, ObservableCollection<MitigationItem> mitigationsList, string systemName)
        {
            try
            {
                if (fileName.IsFileInUse())
                {
                    log.Error(fileName + " is in use; please close any open instances and try again.");
                    return "Failed; File In Use";
                }
                file = Path.GetFileName(fileName);
                ReadFprArchive(fileName, mitigationsList, systemName);
                return "Processed";
            }
            catch (Exception exception)
            {
                log.Error("Unable to process FPR file.");
                log.Debug("Exception details:", exception);
                return "Failed; See Log";
            }
        }

        private void ReadFprArchive(string fileName, ObservableCollection<MitigationItem> mitigationsList, string systemName)
        {
            try
            {
                using (SQLiteTransaction sqliteTransaction = FindingsDatabaseActions.sqliteConnection.BeginTransaction())
                {
                    CreateAddFileNameCommand(fileName);
                    CreateAddGroupNameCommand(systemName);
                    CreateAddSourceCommand();
                    using (Stream stream = File.OpenRead(fileName))
                    {
                        using (ZipArchive zipArchive = new ZipArchive(stream, ZipArchiveMode.Read))
                        {
                            foreach (ZipArchiveEntry zipArchiveEntry in zipArchive.Entries)
                            {
                                if (zipArchiveEntry.Name.Equals("audit.fvdl"))
                                { ParseAuditFvdlWithXmlReader(zipArchiveEntry, systemName); }
                                if (zipArchiveEntry.Name.Equals("audit.xml"))
                                { ParseAuditXmlWithXmlReader(zipArchiveEntry); }
                            }
                        }
                    }
                    sqliteTransaction.Commit();
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to read FPR Archive.");
                throw exception;
            }
        }

        private void ParseAuditFvdlWithXmlReader(ZipArchiveEntry zipArchiveEntry, string systemName)
        {
            try
            {
                XmlReaderSettings xmlReaderSettings = GenerateXmlReaderSettings();
                using (XmlReader xmlReader = XmlReader.Create(zipArchiveEntry.Open(), xmlReaderSettings))
                {
                    while (xmlReader.Read())
                    {
                        if (xmlReader.IsStartElement())
                        {
                            switch (xmlReader.Name)
                            {
                                case "CreatedTS":
                                    {
                                        lastObserved = DateTime.Parse(xmlReader.GetAttribute("date")).ToLongDateString();
                                        break;
                                    }
                                case "BuildID":
                                    {
                                        CreateAddAssetCommand(xmlReader, systemName);
                                        break;
                                    }
                                case "Vulnerability":
                                    {
                                        ParseFvdlVulnerablityNode(xmlReader);
                                        break;
                                    }
                                case "Description":
                                    {
                                        ParseFvdlDescriptionNode(xmlReader);
                                        break;
                                    }
                                case "EngineVersion":
                                    {
                                        CreateUpdateSourceCommand(xmlReader);
                                        break;
                                    }
                                default:
                                    { break; }
                            }
                        }
                    }
                }
                foreach (FprDescription fprDescription in fprDescriptionList)
                { CreateUpdateVulnerabilityCommand(fprDescription); }
            }
            catch (Exception exception)
            {
                log.Error("Unable to read \"audit.fvdl\".");
                throw exception;
            }
        }

        private void ParseFvdlVulnerablityNode(XmlReader xmlReader)
        {
            try
            {
                using (SQLiteCommand sqliteCommand = FindingsDatabaseActions.sqliteConnection.CreateCommand())
                {

                    while (xmlReader.Read())
                    {
                        if (xmlReader.IsStartElement())
                        {
                            switch (xmlReader.Name)
                            {
                                case "ClassID":
                                    {
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("VulnId", ObtainCurrentNodeValue(xmlReader)));
                                        break;
                                    }
                                case "InstanceID":
                                    {
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("Comments", "Instance ID:" + Environment.NewLine + ObtainCurrentNodeValue(xmlReader)));
                                        break;
                                    }
                                default:
                                    { break; }
                            }
                        }
                        else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("Vulnerability"))
                        {
                            CreateAddVulnerabilityCommand(sqliteCommand);
                            CreateAddUniqueFindingCommand(sqliteCommand);
                            return;
                        }
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to parse FVDL Vulnerability node.");
                throw exception;
            }
        }

        private void ParseFvdlDescriptionNode(XmlReader xmlReader)
        {
            try
            {
                FprDescription fprDescription = new FprDescription();
                fprDescription.VulnId = xmlReader.GetAttribute("classID");
                while (xmlReader.Read())
                {
                    if (xmlReader.IsStartElement())
                    {
                        switch (xmlReader.Name)
                        {
                            case "Abstract":
                                {
                                    xmlReader.Read();
                                    fprDescription.VulnTitle = SanitizeVulnTitle(xmlReader.Value);
                                    fprDescription.RiskStatement = SanitizeRiskStatement(xmlReader.Value);
                                    break;
                                }
                            case "Explanation":
                                {
                                    xmlReader.Read();
                                    fprDescription.Description = SanitizeDescription(xmlReader.Value);
                                    break;
                                }
                            case "Recommendations":
                                {
                                    xmlReader.Read();
                                    fprDescription.FixText = SanitizeRecommendations(xmlReader.Value);
                                    break;
                                }
                            case "Reference":
                                {
                                    string value = ObtainReferencesValue(xmlReader);
                                    string key = ObtainReferencesKey(xmlReader);
                                    fprDescription.References.Add(key, value);
                                    break;
                                }
                            default:
                                { break; }
                        }
                    }
                    else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name == "Description")
                    {
                        fprDescriptionList.Add(fprDescription);
                        return;
                    }
                }
                
            }
            catch (Exception exception)
            {
                log.Error("Unable to parse FVDL Description node.");
                throw exception;
            }
        }

        private void ParseAuditXmlWithXmlReader(ZipArchiveEntry zipArchiveEntry)
        {
            try
            {
                XmlReaderSettings xmlReaderSettings = GenerateXmlReaderSettings();
            }
            catch (Exception exception)
            {
                log.Error("Unable to read \"audit.xml\".");
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

        private void CreateAddFileNameCommand(string fileName)
        {
            try
            {
                using (SQLiteCommand sqliteCommand = FindingsDatabaseActions.sqliteConnection.CreateCommand())
                {
                    sqliteCommand.CommandText = "INSERT INTO FileNames VALUES (NULL, @FileName);";
                    sqliteCommand.Parameters.Add(new SQLiteParameter("FileName", Path.GetFileName(fileName)));
                    sqliteCommand.ExecuteNonQuery();
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to insert file name into FileNames.");
                throw exception;
            }
        }

        private void CreateAddGroupNameCommand(string groupName)
        {
            try
            {
                using (SQLiteCommand sqliteCommand = FindingsDatabaseActions.sqliteConnection.CreateCommand())
                {
                    sqliteCommand.CommandText = "INSERT INTO Groups VALUES (NULL, @GroupName);";
                    sqliteCommand.Parameters.Add(new SQLiteParameter("GroupName", groupName));
                    sqliteCommand.ExecuteNonQuery();
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to insert GroupName into Groups.");
                throw exception;
            }
        }

        private void CreateAddAssetCommand(XmlReader xmlReader, string systemName)
        {
            try
            {
                using (SQLiteCommand sqliteCommand = FindingsDatabaseActions.sqliteConnection.CreateCommand())
                {
                    softwareName = ObtainCurrentNodeValue(xmlReader);
                    sqliteCommand.Parameters.Add(new SQLiteParameter("AssetIdToReport", softwareName));
                    sqliteCommand.Parameters.Add(new SQLiteParameter("GroupName", systemName));
                    sqliteCommand.CommandText = "INSERT INTO Assets (AssetIndex, AssetIdToReport, GroupIndex) VALUES(NULL, @AssetIdToReport, (SELECT GroupIndex FROM Groups WHERE GroupName = @GroupName));";
                    sqliteCommand.ExecuteNonQuery();
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to insert Asset into Assets.");
                throw exception;
            }
        }

        private void CreateAddSourceCommand()
        {
            try
            {
                using (SQLiteCommand sqliteCommand = FindingsDatabaseActions.sqliteConnection.CreateCommand())
                {
                    sqliteCommand.Parameters.Add(new SQLiteParameter("Source", sourcePlaceholder));
                    sqliteCommand.CommandText = "INSERT INTO VulnerabilitySources (SourceIndex, Source, Version) VALUES (NULL, @Source, 'V?');";
                    sqliteCommand.ExecuteNonQuery();
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to insert Source into VunerabilitySources.");
                throw exception;
            }
        }

        private void CreateAddVulnerabilityCommand(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = "INSERT INTO Vulnerability (VulnerabilityIndex, VulnId) VALUES (NULL, @VulnId);";
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                log.Error("Unable to insert Vulnerability into Vulnerability.");
                throw exception;
            }
        }

        private void CreateAddUniqueFindingCommand(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.Parameters.Add(new SQLiteParameter("FileName", file));
                sqliteCommand.Parameters.Add(new SQLiteParameter("LastObserved", lastObserved));
                sqliteCommand.Parameters.Add(new SQLiteParameter("AssetIdToReport", softwareName));
                sqliteCommand.CommandText = "INSERT INTO UniqueFinding (Comments, LastObserved, " +
                    "FindingTypeIndex, SourceIndex, FileNameIndex, VulnerabilityIndex, StatusIndex, AssetIndex) " +
                    "VALUES (@Comments, @LastObserved, " +
                    "(SELECT FindingTypeIndex FROM FindingTypes WHERE FindingType = 'FPR'), " +
                    "(SELECT SourceIndex FROM VulnerabilitySources WHERE Source = 'HPE Fortify SCA' AND Version = 'V?'), " +
                    "(SELECT FileNameIndex FROM FileNames WHERE FileName = @FileName), " +
                    "(SELECT VulnerabilityIndex FROM Vulnerability WHERE VulnId = @VulnId), " +
                    "(SELECT StatusIndex FROM FindingStatuses WHERE Status = 'Ongoing'), " +
                    "(SELECT AssetIndex FROM Assets WHERE AssetIdToReport = @AssetIdToReport));";
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                log.Error("Unable to insert UniqueFinding into UniqueFindings.");
                throw exception;
            }
        }

        private void CreateUpdateSourceCommand(XmlReader xmlReader)
        {
            try
            {
                xmlReader.Read();
                using (SQLiteCommand sqliteCommand = FindingsDatabaseActions.sqliteConnection.CreateCommand())
                {
                    sqliteCommand.Parameters.Add(new SQLiteParameter("Version", xmlReader.Value));
                    sqliteCommand.CommandText = "UPDATE VulnerabilitySources SET Version = @Version WHERE Source = 'HPE Fortify SCA' AND Version = 'V?';";
                    sqliteCommand.ExecuteNonQuery();
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to update Source.");
                throw exception;
            }
        }

        private void CreateUpdateVulnerabilityCommand(FprDescription fprDescription)
        {
            try
            {
                using (SQLiteCommand sqliteCommand = FindingsDatabaseActions.sqliteConnection.CreateCommand())
                {
                    sqliteCommand.Parameters.Add(new SQLiteParameter("Description", fprDescription.Description));
                    sqliteCommand.Parameters.Add(new SQLiteParameter("RiskStatement", fprDescription.RiskStatement));
                    sqliteCommand.Parameters.Add(new SQLiteParameter("VulnTitle", fprDescription.VulnTitle));
                    List<KeyValuePair<string, string>> asdStigs = fprDescription.References.Where(
                        x => x.Key.Contains("AS&D")).ToList();
                    if (asdStigs != null && asdStigs.Count > 0)
                    {
                        asdStigs = asdStigs.OrderByDescending(x => x.Key.Substring(5).Length).ThenByDescending(x => Convert.ToDecimal(x.Key.Substring(5))).ToList();
                        sqliteCommand.Parameters.Add(new SQLiteParameter("StigId", asdStigs[0].Value));
                    }
                    List<KeyValuePair<string, string>> nistControls = fprDescription.References.Where(
                        x => x.Key.Contains("800-53")).OrderByDescending(x => x.Key).ToList();
                    if (nistControls != null && nistControls.Count > 0)
                    { sqliteCommand.Parameters.Add(new SQLiteParameter("NistControl", nistControls[0].Value)); }
                    sqliteCommand.Parameters.Add(new SQLiteParameter("FixText", fprDescription.FixText));
                    sqliteCommand.Parameters.Add(new SQLiteParameter("VulnId", fprDescription.VulnId));
                    sqliteCommand.CommandText = "UPDATE Vulnerability SET  WHERE VulnId = @VulnId;";
                    for (int i = 0; i < sqliteCommand.Parameters.Count; i++)
                    {
                        if (i == 0)
                        {
                            sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(
                                25, sqliteCommand.Parameters[i].ParameterName + " = @" + sqliteCommand.Parameters[i].ParameterName);
                        }
                        else
                        {
                            sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(
                                25, sqliteCommand.Parameters[i].ParameterName + " = @" + sqliteCommand.Parameters[i].ParameterName + ", ");
                        }
                    }
                    sqliteCommand.ExecuteNonQuery();
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to update Vulnerability.");
                throw exception;
            }
        }

        private string ObtainCurrentNodeValue(XmlReader xmlReader)
        {
            try
            {
                xmlReader.Read();
                return xmlReader.Value;
            }
            catch (Exception exception)
            {
                log.Error("Unable to obtain currently accessed node value.");
                throw exception;
            }
        }

        private string SantizeNodeContent(XmlReader xmlReader)
        {
            try
            {
                string nodeValue = ObtainCurrentNodeValue(xmlReader);
                nodeValue = nodeValue.Replace("&lt;", "<");
                nodeValue = nodeValue.Replace("&gt;", ">");
                return nodeValue;
            }
            catch (Exception exception)
            {
                log.Error("Unable to sanitize node content.");
                throw exception;
            }
        }

        private string SanitizeVulnTitle(string unsanitizedVulnTitle)
        {
            try
            {
                string delimiter = "<AltParagraph>";
                string sanitizedVulnTitle = unsanitizedVulnTitle.Split(new string[] { delimiter }, StringSplitOptions.None)[0];
                sanitizedVulnTitle = sanitizedVulnTitle.Replace("<Content>", "");
                sanitizedVulnTitle = sanitizedVulnTitle.Replace("<Paragraph>", "");
                return sanitizedVulnTitle;
            }
            catch (Exception exception)
            {
                log.Error("Unable to sanitize VulnTitle value.");
                throw exception;
            }
        }

        private string SanitizeRiskStatement(string unsanitizedRiskStatement)
        {
            try
            {
                string delimiter = "<AltParagraph>";
                string sanitizedRiskStatement = unsanitizedRiskStatement.Split(new string[] { delimiter }, StringSplitOptions.None)[1];
                delimiter = "</AltParagraph>";
                sanitizedRiskStatement = sanitizedRiskStatement.Split(new string[] { delimiter }, StringSplitOptions.None)[0];
                return sanitizedRiskStatement;
            }
            catch (Exception exception)
            {
                log.Error("Unable to sanitize RiskStatement value.");
                throw exception;
            }
        }

        private string SanitizeDescription(string unsanitizedDescription)
        {
            try
            {
                string sanitizedDescription = unsanitizedDescription;
                string doubleCarriageReturn = Environment.NewLine + Environment.NewLine;
                string[] stringsToRemove = new string[] {
                "<Content>", "<Paragraph>", "</Paragraph>", "</Content>", "<b>", "</b>", "<pre>", "</pre>"
            };
                foreach (string trash in stringsToRemove)
                {
                    switch (trash)
                    {
                        case "<Paragraph>":
                            {
                                sanitizedDescription = sanitizedDescription.Replace(trash, doubleCarriageReturn);
                                break;
                            }
                        case "<b>":
                            {
                                sanitizedDescription = sanitizedDescription.Replace(trash, doubleCarriageReturn);
                                break;
                            }
                        case "</b>":
                            {
                                sanitizedDescription = sanitizedDescription.Replace(trash, Environment.NewLine);
                                break;
                            }
                        case "<pre>":
                            {
                                sanitizedDescription = sanitizedDescription.Replace(trash, doubleCarriageReturn);
                                break;
                            }
                        default:
                            {
                                sanitizedDescription = sanitizedDescription.Replace(trash, "");
                                break;
                            }
                    }

                }
                return sanitizedDescription;
            }
            catch (Exception exception)
            {
                log.Error("Unable to sanitize Description value.");
                throw exception;
            }
        }

        private string SanitizeRecommendations(string unsanitizedRecommendations)
        {
            try
            {
                string sanitizedRecommendations = unsanitizedRecommendations;
                string doubleCarriageReturn = Environment.NewLine + Environment.NewLine;
                string[] stringsToRemove = new string[] {
                "<Content>", "<Paragraph>", "</Paragraph>", "</Content>", "<b>", "</b>", "<pre>", "</pre>"
            };
                foreach (string trash in stringsToRemove)
                {
                    switch (trash)
                    {
                        case "<Paragraph>":
                            {
                                sanitizedRecommendations = sanitizedRecommendations.Replace(trash, doubleCarriageReturn);
                                break;
                            }
                        case "<b>":
                            {
                                sanitizedRecommendations = sanitizedRecommendations.Replace(trash, doubleCarriageReturn);
                                break;
                            }
                        case "</b>":
                            {
                                sanitizedRecommendations = sanitizedRecommendations.Replace(trash, Environment.NewLine);
                                break;
                            }
                        case "<pre>":
                            {
                                sanitizedRecommendations = sanitizedRecommendations.Replace(trash, doubleCarriageReturn);
                                break;
                            }
                        default:
                            {
                                sanitizedRecommendations = sanitizedRecommendations.Replace(trash, "");
                                break;
                            }
                    }
                }
                return sanitizedRecommendations;
            }
            catch (Exception exception)
            {
                log.Error("Unable to sanitize Recommendations value.");
                throw exception;
            }
        }

        private string ObtainReferencesValue(XmlReader xmlReader)
        {
            try
            {
                string value = string.Empty;
                while (!xmlReader.Name.Equals("Title"))
                { xmlReader.Read(); }
                xmlReader.Read();
                value = xmlReader.Value;
                return value;
            }
            catch (Exception exception)
            {
                log.Error("Unable to obtain References key.");
                throw exception;
            }
        }

        private string ObtainReferencesKey(XmlReader xmlReader)
        {
            try
            {
                string key = string.Empty;
                while (!xmlReader.Name.Equals("Author"))
                { xmlReader.Read(); }
                xmlReader.Read();
                if (xmlReader.Value.Contains("Security Technical Implementation"))
                { key = "AS&D" + xmlReader.Value.RemoveAlphaCharacters(); }
                else
                { key = xmlReader.Value; }
                return key;
            }
            catch (Exception exception)
            {
                log.Error("Unable to obtain References value.");
                throw exception;
            }
        }
    }
}
