using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Data.SQLite;
using System.IO;
using System.IO.Compression;
using System.Linq;
using log4net;
using System.Xml;
using Vulnerator.Model.DataAccess;
using Vulnerator.Model.ModelHelper;
using Vulnerator.Model.Object;

namespace Vulnerator.Model.BusinessLogic
{
    class FprReader
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(Logger));
        private string softwareName = string.Empty;
        private string lastObserved = string.Empty;
        private string file = string.Empty;
        private string sourcePlaceholder = "HPE Fortify SCA";
        private string version = string.Empty;
        private List<FprDescription> fprDescriptionList = new List<FprDescription>();
        private List<FprVulnerability> fprVulnerabilityList = new List<FprVulnerability>();

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
                    using (Stream stream = System.IO.File.OpenRead(fileName))
                    {
                        using (ZipArchive zipArchive = new ZipArchive(stream, ZipArchiveMode.Read))
                        {
                            ZipArchiveEntry auditFvdl = zipArchive.Entries.FirstOrDefault(x => x.Name.Equals("audit.fvdl"));
                            ParseAuditFvdlWithXmlReader(auditFvdl, systemName);
                            ZipArchiveEntry auditXml = zipArchive.Entries.FirstOrDefault(x => x.Name.Equals("audit.xml"));
                            ParseAuditXmlWithXmlReader(auditXml);
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
                foreach (FprVulnerability fprVulnerability in fprVulnerabilityList)
                {
                    using (SQLiteCommand sqliteCommand = FindingsDatabaseActions.sqliteConnection.CreateCommand())
                    { AddVulnerabilityAndUniqueFinding(fprVulnerability); }
                }
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
                FprVulnerability fprVulnerability = new FprVulnerability();
                string kingdom = string.Empty;
                string type = string.Empty;
                string subType = string.Empty;
                while (xmlReader.Read())
                {
                    if (xmlReader.IsStartElement())
                    {
                        switch (xmlReader.Name)
                        {
                            case "ClassID":
                                {
                                    fprVulnerability.ClassId = ObtainCurrentNodeValue(xmlReader);
                                    break;
                                }
                            case "Kingdom":
                                {
                                    kingdom = ObtainCurrentNodeValue(xmlReader);
                                    break;
                                }
                            case "Type":
                                {
                                    type = ObtainCurrentNodeValue(xmlReader);
                                    break;
                                }
                            case "Subtype":
                                {
                                    subType = ObtainCurrentNodeValue(xmlReader);
                                    break;
                                }
                            case "InstanceID":
                                {
                                    fprVulnerability.InstanceId = ObtainCurrentNodeValue(xmlReader);
                                    break;
                                }
                            case "Def":
                                {
                                    fprVulnerability.ReplacementDefinitions.Add(xmlReader.GetAttribute("key"), xmlReader.GetAttribute("value"));
                                    break;
                                }
                            case "LocationDef":
                                {
                                    FprVulnerability.LocationDef locationDef = new FprVulnerability.LocationDef();
                                    locationDef.Path = xmlReader.GetAttribute("path");
                                    locationDef.Line = xmlReader.GetAttribute("line");
                                    locationDef.LineEnd = xmlReader.GetAttribute("lineEnd");
                                    locationDef.ColumnStart = xmlReader.GetAttribute("colStart");
                                    locationDef.ColumnEnd = xmlReader.GetAttribute("colEnd");
                                    fprVulnerability.LocationDefinitions.Add(locationDef);
                                    break;
                                }
                            default:
                                { break; }
                        }
                    }
                    else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("Vulnerability"))
                    {
                        if (!string.IsNullOrWhiteSpace(subType))
                        { fprVulnerability.Category = kingdom + " : " + type + " : " + subType; }
                        else
                        { fprVulnerability.Category = kingdom + " : " + type; }
                        fprVulnerabilityList.Add(fprVulnerability);
                        return;
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
                fprDescription.ClassId = xmlReader.GetAttribute("classID");
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
                                    string keyCheck;
                                    if (!fprDescription.References.TryGetValue(key, out keyCheck))
                                    { fprDescription.References.Add(key, value); }
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
                    if (string.IsNullOrWhiteSpace(softwareName))
                    { softwareName = file; }
                    sqliteCommand.Parameters.Add(new SQLiteParameter("AssetIdToReport", softwareName));
                    sqliteCommand.Parameters.Add(new SQLiteParameter("GroupName", systemName));
                    sqliteCommand.CommandText = "INSERT INTO Assets (AssetIndex, AssetIdToReport, HostName, GroupIndex) " +
                        "VALUES(NULL, @AssetIdToReport, @AssetIdToReport, (SELECT GroupIndex FROM Groups WHERE GroupName = @GroupName));";
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

        private void AddVulnerabilityAndUniqueFinding(FprVulnerability fprVulnerability)
        {
            try
            {
                using (SQLiteCommand sqliteCommand = FindingsDatabaseActions.sqliteConnection.CreateCommand())
                {
                    FprDescription fprDescription = fprDescriptionList.FirstOrDefault(x => x.ClassId == fprVulnerability.ClassId);
                    sqliteCommand.Parameters.Add(new SQLiteParameter("VulnId", fprVulnerability.ClassId));
                    sqliteCommand.Parameters.Add(new SQLiteParameter("Description", InjectDefinitionValues(fprDescription.Description, fprVulnerability)));
                    sqliteCommand.Parameters.Add(new SQLiteParameter("RiskStatement", InjectDefinitionValues(fprDescription.RiskStatement, fprVulnerability)));
                    sqliteCommand.Parameters.Add(new SQLiteParameter("VulnTitle", InjectDefinitionValues(fprDescription.VulnTitle, fprVulnerability)));
                    sqliteCommand.Parameters.Add(new SQLiteParameter("CrossReferences", fprVulnerability.InstanceId));
                    sqliteCommand.Parameters.Add(new SQLiteParameter("CheckContent", fprVulnerability.Category));
                    sqliteCommand.Parameters.Add(new SQLiteParameter("FileName", file));
                    sqliteCommand.Parameters.Add(new SQLiteParameter("LastObserved", lastObserved));
                    sqliteCommand.Parameters.Add(new SQLiteParameter("AssetIdToReport", softwareName));
                    sqliteCommand.Parameters.Add(new SQLiteParameter("Version", version));
                    sqliteCommand.Parameters.Add(new SQLiteParameter("FindingDetails", "Instance ID:" + Environment.NewLine + fprVulnerability.InstanceId));
                    List<KeyValuePair<string, string>> nistControls = fprDescription.References.Where(
                        x => x.Key.Contains("800-53")).OrderByDescending(x => x.Key).ToList();
                    if (nistControls != null && nistControls.Count > 0)
                    { sqliteCommand.Parameters.Add(new SQLiteParameter("NistControl", nistControls[0].Value.Split(' ')[0])); }
                    sqliteCommand.Parameters.Add(new SQLiteParameter("FixText", fprDescription.FixText));
                    List<KeyValuePair<string, string>> asdStigs = fprDescription.References.Where(
                        x => x.Key.Contains("AS&D")).ToList();
                    string[] delimiter = new string[] { "CAT" };
                    if (asdStigs != null && asdStigs.Count > 0)
                    {
                        asdStigs = asdStigs.OrderByDescending(x => Convert.ToDecimal(x.Key.Substring(5,1))).
                            ThenByDescending(x => x.Key.Split(',')[0].Substring(7).Length).
                            ThenByDescending(x => x.Key.Substring(7)).ToList();
                        if (asdStigs[0].Value.Contains(", "))
                        {
                            string[] asdStigValues = asdStigs[0].Value.Split(',').ToArray();
                            foreach (string stigValue in asdStigValues)
                            {
                                sqliteCommand.Parameters.Add(new SQLiteParameter("StigId", stigValue.Trim().Split(' ')[0]));
                                sqliteCommand.Parameters.Add(new SQLiteParameter("RawRisk", stigValue.Split(delimiter, StringSplitOptions.None)[1].Trim()));
                                sqliteCommand.Parameters.Add(new SQLiteParameter("Impact", RawRiskToImpactConverter(stigValue.Split(delimiter, StringSplitOptions.None)[1].Trim())));
                                CreateAddVulnerabilityCommand(sqliteCommand);
                                CreateAddUniqueFindingCommand(sqliteCommand);
                            }
                        }
                        else
                        {
                            sqliteCommand.Parameters.Add(new SQLiteParameter("StigId", asdStigs[0].Value.Replace(", ", Environment.NewLine).Trim().Split(' ')[0]));
                            sqliteCommand.Parameters.Add(new SQLiteParameter("RawRisk", asdStigs[0].Value.Split(delimiter, StringSplitOptions.None)[1].Trim()));
                            sqliteCommand.Parameters.Add(new SQLiteParameter("Impact", RawRiskToImpactConverter(asdStigs[0].Value.Split(delimiter, StringSplitOptions.None)[1].Trim())));
                            CreateAddVulnerabilityCommand(sqliteCommand);
                            CreateAddUniqueFindingCommand(sqliteCommand);
                        }
                    }
                    else
                    {
                        CreateAddVulnerabilityCommand(sqliteCommand);
                        CreateAddUniqueFindingCommand(sqliteCommand);
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to generate SQLiteParameter List.");
                throw exception;
            }
        }

        private void CreateAddVulnerabilityCommand(SQLiteCommand sqliteCommand)
        {
            try
            {
                string[] ignorableParametersArray = new string[] { "FileName", "LastObserved", "AssetIdToReport", "FindingDetails", "Version" };
                sqliteCommand.CommandText = "INSERT INTO Vulnerability () VALUES ();";
                for (int i = 0; i < sqliteCommand.Parameters.Count; i++)
                {
                    if (ignorableParametersArray.Contains(sqliteCommand.Parameters[i].ParameterName))
                    { continue; }
                    if (i == 0)
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(37, "@" + sqliteCommand.Parameters[i].ParameterName); }
                    else
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(37, "@" + sqliteCommand.Parameters[i].ParameterName + ", "); }
                }
                for (int i = 0; i < sqliteCommand.Parameters.Count; i++)
                {
                    if (ignorableParametersArray.Contains(sqliteCommand.Parameters[i].ParameterName))
                    { continue; }
                    if (i == 0)
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(27, sqliteCommand.Parameters[i].ParameterName); }
                    else
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(27, sqliteCommand.Parameters[i].ParameterName + ", "); }
                }
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
                sqliteCommand.CommandText = "INSERT INTO UniqueFinding (FindingDetails, LastObserved, " +
                    "FindingTypeIndex, SourceIndex, FileNameIndex, VulnerabilityIndex, StatusIndex, AssetIndex) " +
                    "VALUES (@FindingDetails, @LastObserved, " +
                    "(SELECT FindingTypeIndex FROM FindingTypes WHERE FindingType = 'FPR'), " +
                    "(SELECT SourceIndex FROM VulnerabilitySources WHERE Source = 'HPE Fortify SCA' AND Version = @Version), " +
                    "(SELECT FileNameIndex FROM FileNames WHERE FileName = @FileName), " +
                    "(SELECT VulnerabilityIndex FROM Vulnerability WHERE CrossReferences = @CrossReferences), " +
                    "(SELECT StatusIndex FROM FindingStatuses WHERE Status = 'Ongoing'), " +
                    "(SELECT AssetIndex FROM Assets WHERE AssetIdToReport = @AssetIdToReport));";
                if (sqliteCommand.Parameters.Contains("StigId"))
                { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(515, " AND StigId = @StigId"); }
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
                    version = xmlReader.Value;
                    sqliteCommand.Parameters.Add(new SQLiteParameter("Version", version));
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
                string sanitizedVulnTitle = unsanitizedVulnTitle;
                if (sanitizedVulnTitle.Contains(delimiter))
                { sanitizedVulnTitle = unsanitizedVulnTitle.Split(new string[] { delimiter }, StringSplitOptions.None)[0]; }
                sanitizedVulnTitle = sanitizedVulnTitle.Replace("<Content>", "");
                sanitizedVulnTitle = sanitizedVulnTitle.Replace("<Paragraph>", "");
                string[] stringsToRemove = new string[] {
                    "<Content>", "<Paragraph>", "</Paragraph>", "</Content>", "<b>", "</b>", "<pre>", "</pre>", "<code>", "</code>", "&lt;", "&gt;"
                };
                foreach (string trash in stringsToRemove)
                { sanitizedVulnTitle = sanitizedVulnTitle.Replace(trash, ""); }
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
                string sanitizedRiskStatement = unsanitizedRiskStatement;
                if (sanitizedRiskStatement.Contains(delimiter))
                { sanitizedRiskStatement = unsanitizedRiskStatement.Split(new string[] { delimiter }, StringSplitOptions.None)[1]; }
                delimiter = "</AltParagraph>";
                if (sanitizedRiskStatement.Contains(delimiter))
                { sanitizedRiskStatement = sanitizedRiskStatement.Split(new string[] { delimiter }, StringSplitOptions.None)[0]; }
                string[] stringsToRemove = new string[] {
                    "<Content>", "<Paragraph>", "</Paragraph>", "</Content>", "<b>", "</b>", "<pre>", "</pre>", "<code>", "</code>", "&lt;", "&gt;"
                };
                foreach (string trash in stringsToRemove)
                { sanitizedRiskStatement = sanitizedRiskStatement.Replace(trash, ""); }
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
                    "<Content>", "<Paragraph>", "</Paragraph>", "</Content>", "<b>", "</b>", "<pre>", "</pre>", "<code>", "</code>", "&lt;", "&gt;"
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
                "<Content>", "<Paragraph>", "</Paragraph>", "</Content>", "<b>", "</b>", "<pre>", "</pre>", "<code>", "</code>", "&lt;", "&gt;"
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

        private string InjectDefinitionValues(string input, FprVulnerability fprVulnerability)
        {
            string output = input;
            string placeholder = string.Empty;
            foreach (string key in fprVulnerability.ReplacementDefinitions.Keys)
            {
                string[] locationDefArray = new string[] { "SourceFunction", "SinkFunction", "PrimaryCall.name" };
                placeholder = "<Replace key=\"" + key + "\"/>";
                if (output.Contains(placeholder))
                { output = output.Replace(placeholder, fprVulnerability.ReplacementDefinitions[key]); }
                if (locationDefArray.Contains(key))
                {
                    switch (key)
                    {
                        case "SourceFunction":
                            {
                                placeholder = "<Replace key=\"" + key + "\" link=\"SourceLocation\"/>";
                                if (output.Contains(placeholder))
                                { output = output.Replace(placeholder, fprVulnerability.ReplacementDefinitions[key]); }
                                break;
                            }
                        case "SinkFunction":
                            {
                                placeholder = "<Replace key=\"" + key + "\" link=\"SinkLocation\"/>";
                                if (output.Contains(placeholder))
                                { output = output.Replace(placeholder, fprVulnerability.ReplacementDefinitions[key]); }
                                break;
                            }
                        case "PrimaryCall.name":
                            {
                                placeholder = "<Replace key=\"" + key + "\" link=\"PrimaryLocation\"/>";
                                if (output.Contains(placeholder))
                                { output = output.Replace(placeholder, fprVulnerability.ReplacementDefinitions[key]); }
                                break;
                            }
                        default:
                            { break; }
                    }
                }
            }

            output = output.Replace("<", "");
            output = output.Replace(">", "");
            return output;
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
                while (xmlReader.Read())
                {
                    if (xmlReader.Name.Equals("Author") || xmlReader.Name.Equals("Publisher"))
                    { break; }
                }
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

        private string RawRiskToImpactConverter(string rawRisk)
        {
            switch (rawRisk)
            {
                case "I":
                    { return "High"; }
                case "II":
                    { return "Medium"; }
                case "III":
                    { return "Low"; }
                case "IV":
                    { return "Informational"; }
                default:
                    { return "Unknown"; }
            }
        }

        private void ParseAuditXmlWithXmlReader(ZipArchiveEntry zipArchiveEntry)
        {
            try
            {
                XmlReaderSettings xmlReaderSettings = GenerateXmlReaderSettings();
                using (XmlReader xmlReader = XmlReader.Create(zipArchiveEntry.Open(), xmlReaderSettings))
                {
                    string instanceId = string.Empty;
                    string analysisValue = string.Empty;
                    Dictionary<DateTime, string> commentsDictionary = new Dictionary<DateTime, string>();
                    while (xmlReader.Read())
                    {
                        if (xmlReader.IsStartElement())
                        {
                            switch (xmlReader.Name)
                            {
                                case "ns2:Issue":
                                    {
                                        instanceId = xmlReader.GetAttribute("instanceId");
                                        analysisValue = ObtainAnalysisValue(xmlReader);
                                        break;
                                    }
                                case "ns2:ThreadedComments":
                                    {
                                        PopulateCommentsDictionary(xmlReader, commentsDictionary);
                                        break;
                                    }
                                default:
                                    { break; }
                            }
                        }
                        else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("ns2:Issue"))
                        {
                            FinalizeUniqueFinding(instanceId, analysisValue, commentsDictionary);
                            commentsDictionary.Clear();
                            instanceId = string.Empty;
                            analysisValue = string.Empty;
                        }
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to read \"audit.xml\".");
                throw exception;
            }
        }

        private string ObtainAnalysisValue(XmlReader xmlReader)
        {
            try
            {
                xmlReader.Read();
                if (xmlReader.Name.Equals("ns2:Tag"))
                {
                    while (!xmlReader.Name.Equals("ns2:Value"))
                    { xmlReader.Read(); }
                    xmlReader.Read();
                    return xmlReader.Value;
                }
                else
                { return "Analysis Not Set"; }
            }
            catch (Exception exception)
            {
                log.Error("Unable to obtain analysis value.");
                throw exception;
            }
        }

        private void PopulateCommentsDictionary(XmlReader xmlReader, Dictionary<DateTime, string> commentsDictionary)
        {
            try
            {
                string comment = string.Empty;
                DateTime timestamp = new DateTime();
                while (xmlReader.Read())
                {
                    if (xmlReader.IsStartElement())
                    {
                        switch (xmlReader.Name)
                        {
                            case "ns2:Content":
                                {
                                    comment = ObtainCurrentNodeValue(xmlReader);
                                    break;
                                }
                            case "ns2:Timestamp":
                                {
                                    timestamp = DateTime.Parse(ObtainCurrentNodeValue(xmlReader));
                                    break;
                                }
                            default:
                                { break; }
                        }
                    }
                    else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("ns2:Comment"))
                    {
                        string keyCheck;
                        if (!commentsDictionary.TryGetValue(timestamp, out keyCheck))
                        { commentsDictionary.Add(timestamp, comment); }
                        comment = string.Empty;
                        timestamp = new DateTime();
                    }
                    else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("ns2:ThreadedComments"))
                    { return; }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to obtain FPR comment values.");
                throw exception;
            }
        }

        private void FinalizeUniqueFinding(string instanceId, string analysisValue, Dictionary<DateTime, string> commentsDictionary)
        {
            try
            {
                using (SQLiteCommand sqliteCommand = FindingsDatabaseActions.sqliteConnection.CreateCommand())
                {
                    string comment = string.Empty;
                    sqliteCommand.Parameters.Add(new SQLiteParameter("FindingDetails", "%" + instanceId + "%"));
                    string status = ConvertAnalysisValue(analysisValue);
                    if (status.Equals("Completed"))
                    { sqliteCommand.Parameters.Add(new SQLiteParameter("Status", status)); }
                    else
                    { sqliteCommand.Parameters.Add(new SQLiteParameter("Status", "Ongoing")); }
                    if (commentsDictionary.Count > 0)
                    {
                        List<KeyValuePair<DateTime, string>> orderedComments = commentsDictionary.OrderByDescending(x => x.Key).ToList();
                        comment = "Analysis Value:" + Environment.NewLine + analysisValue;
                        comment = comment + Environment.NewLine + Environment.NewLine + "User Comments:" + Environment.NewLine + orderedComments[0].Value;
                    }
                    sqliteCommand.Parameters.Add(new SQLiteParameter("Comments", comment));
                    sqliteCommand.CommandText = "UPDATE UniqueFinding SET Comments = @Comments, " +
                        "StatusIndex = (SELECT StatusIndex FROM FindingStatuses WHERE Status = @Status) " +
                        "WHERE FindingDetails LIKE @FindingDetails;";
                    sqliteCommand.ExecuteNonQuery();
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to finalize UniqueFinding.");
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

        private string ConvertAnalysisValue(string analysisValue)
        {
            try
            {
                if (analysisValue.Equals("Not an Issue"))
                { return "Completed"; }
                if (analysisValue.Equals("Not a Finding"))
                { return "Completed"; }
                else if (analysisValue.Equals("true"))
                { return "Analysis Not Set"; }
                else
                { return analysisValue; }
            }
            catch (Exception exception)
            {
                log.Error("Unable to convert analysis value.");
                throw exception;
            }
        }
    }
}