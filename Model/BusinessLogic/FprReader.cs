using log4net;
using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text.RegularExpressions;
using System.Xml;
using Vulnerator.Model.DataAccess;
using Vulnerator.Helper;
using Vulnerator.Model.Object;

namespace Vulnerator.Model.BusinessLogic
{
    class FprReader
    {
        private string softwareName = string.Empty;
        private DateTime firstDiscovered = DateTime.Now;
        private DateTime lastObserved = DateTime.Now;
        private string version = string.Empty;
        private DatabaseInterface databaseInterface = new DatabaseInterface();
        private List<FprVulnerability> fprVulnerabilityList = new List<FprVulnerability>();

        string[] persistentParameters = new string[]
        {
            "SourceName", "SourceVersion", "SourceRelease", "DiscoveredSoftwareName", "DisplayedSoftwareName",
            "FindingSourceFileName",
            "FindingType", "FirstDiscovered", "LastObserved", "GroupName"
        };

        private List<FortifySeverity> _fortifySeverities = new List<FortifySeverity>
        {
            new FortifySeverity() {Impact = "Low", Probability = "Low", Severity = "IV"},
            new FortifySeverity() {Impact = "Low", Probability = "High", Severity = "III"},
            new FortifySeverity() {Impact = "High", Probability = "Low", Severity = "II"},
            new FortifySeverity() {Impact = "High", Probability = "High", Severity = "I"},
        };

        public string ReadFpr(Object.File file)
        {
            try
            {
                if (file.FilePath.IsFileInUse())
                {
                    LogWriter.LogError($"'{file.FileName}' is in use; please close any open instances and try again.");
                    return "Failed; File In Use";
                }

                ReadFprArchive(file);
                return "Processed";
            }
            catch (Exception exception)
            {
                string error = $"Unable to process FPR file '{file.FileName}'.";
                LogWriter.LogErrorWithDebug(error, exception);
                return "Failed; See Log";
            }
        }

        private void ReadFprArchive(Object.File file)
        {
            try
            {
                if (DatabaseBuilder.sqliteConnection.State.ToString().Equals("Closed"))
                {
                    DatabaseBuilder.sqliteConnection.Open();
                }

                using (SQLiteTransaction sqliteTransaction = DatabaseBuilder.sqliteConnection.BeginTransaction())
                {
                    using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                    {
                        databaseInterface.InsertParameterPlaceholders(sqliteCommand);
                        sqliteCommand.Parameters["GroupName"].Value = "All";
                        databaseInterface.InsertParsedFileSource(sqliteCommand, file);
                        using (Stream stream = System.IO.File.OpenRead(file.FilePath))
                        {
                            using (ZipArchive zipArchive = new ZipArchive(stream, ZipArchiveMode.Read))
                            {
                                ZipArchiveEntry auditFvdl =
                                    zipArchive.Entries.FirstOrDefault(x => x.Name.Equals("audit.fvdl"));
                                ParseAuditFvdlWithXmlReader(auditFvdl, sqliteCommand);
                                ZipArchiveEntry auditXml =
                                    zipArchive.Entries.FirstOrDefault(x => x.Name.Equals("audit.xml"));
                                if (auditXml != null)
                                {
                                    ParseAuditXmlWithXmlReader(auditXml);
                                }
                            }
                        }

                        sqliteCommand.Parameters["SourceName"].Value = "HPE Fortify SCA";
                        sqliteCommand.Parameters["SourceVersion"].Value = version;
                        sqliteCommand.Parameters["SourceRelease"].Value = string.Empty;
                        sqliteCommand.Parameters["DiscoveredSoftwareName"].Value = softwareName;
                        sqliteCommand.Parameters["DisplayedSoftwareName"].Value = softwareName;
                        sqliteCommand.Parameters["FindingSourceFileName"].Value = file.FileName;
                        sqliteCommand.Parameters["FindingType"].Value = "Fortify";
                        sqliteCommand.Parameters["FirstDiscovered"].Value = firstDiscovered;
                        sqliteCommand.Parameters["LastObserved"].Value = lastObserved;
                        databaseInterface.InsertVulnerabilitySource(sqliteCommand);
                        databaseInterface.InsertSoftware(sqliteCommand);
                        foreach (FprVulnerability fprVulnerability in fprVulnerabilityList)
                        {
                            sqliteCommand.Parameters["UniqueVulnerabilityIdentifier"].Value = fprVulnerability.ClassId;
                            sqliteCommand.Parameters["VulnerabilityGroupTitle"].Value = fprVulnerability.Kingdom;
                            sqliteCommand.Parameters["VulnerabilityFamilyOrClass"].Value = fprVulnerability.Type;
                            sqliteCommand.Parameters["VulnerabilityTitle"].Value = fprVulnerability.SubType;
                            sqliteCommand.Parameters["VulnerabilityDescription"].Value = fprVulnerability.Description;
                            sqliteCommand.Parameters["RiskStatement"].Value = fprVulnerability.RiskStatement;
                            sqliteCommand.Parameters["FixText"].Value = fprVulnerability.FixText;
                            sqliteCommand.Parameters["InstanceIdentifier"].Value = fprVulnerability.InstanceId;
                            sqliteCommand.Parameters["ToolGeneratedOutput"].Value = fprVulnerability.Output;
                            
                            sqliteCommand.Parameters["Comments"].Value = fprVulnerability.Comments;
                            sqliteCommand.Parameters["PrimaryRawRiskIndicator"].Value = fprVulnerability.RawRisk;
                            sqliteCommand.Parameters["DeltaAnalysisIsRequired"].Value = "False";
                            foreach (FprVulnerability.AuditComment comment in fprVulnerability.AuditComments.OrderBy(x => x.EditTime))
                            {
                                string concatenatedComment =
                                    $"{comment.EditTime.ToShortDateString()}{Environment.NewLine}{comment.UserName}: {comment.Content}";
                                sqliteCommand.Parameters["Comments"].Value =
                                    string.IsNullOrEmpty(sqliteCommand.Parameters["Comments"].Value.ToString())
                                        ? concatenatedComment
                                        : $"{sqliteCommand.Parameters["Comments"].Value}{Environment.NewLine}{Environment.NewLine}{concatenatedComment}";
                            }
                            sqliteCommand.Parameters["Status"].Value = fprVulnerability.Status;
                            databaseInterface.InsertVulnerability(sqliteCommand);
                            databaseInterface.MapVulnerabilityToSource(sqliteCommand);
                            databaseInterface.InsertUniqueFinding(sqliteCommand);
                            foreach (string cci in fprVulnerability.CCIs)
                            {
                                sqliteCommand.Parameters["CCI_Number"].Value = cci;
                                databaseInterface.MapVulnerabilityToCci(sqliteCommand);
                                sqliteCommand.Parameters["CCI_Number"].Value = DBNull.Value;
                            }

                            foreach (SQLiteParameter parameter in sqliteCommand.Parameters)
                            {
                                if (!persistentParameters.Contains(parameter.ParameterName))
                                {
                                    sqliteCommand.Parameters[parameter.ParameterName].Value = string.Empty;
                                }
                            }
                        }
                    }

                    sqliteTransaction.Commit();
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to read FPR Archive.");
                throw exception;
            }
            finally
            {
                DatabaseBuilder.sqliteConnection.Close();
            }
        }

        private void ParseAuditFvdlWithXmlReader(ZipArchiveEntry zipArchiveEntry, SQLiteCommand sqliteCommand)
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
                            Console.WriteLine(xmlReader.Name);
                            switch (xmlReader.Name)
                            {
                                case "CreatedTS":
                                {
                                    firstDiscovered = lastObserved = DateTime.Parse(xmlReader.GetAttribute("date"));
                                    break;
                                }
                                case "BuildID":
                                {
                                    softwareName = xmlReader.ObtainCurrentNodeValue(false);
                                    break;
                                }
                                case "Vulnerability":
                                {
                                    ParseFvdlVulnerablityNode(xmlReader);
                                    break;
                                }
                                case "UnifiedNodePool":
                                {
                                    while (!(xmlReader.NodeType == XmlNodeType.EndElement &&
                                          xmlReader.Name.Equals("UnifiedNodePool")))
                                    {
                                        xmlReader.Read();
                                    }

                                    break;
                                }
                                case "Description":
                                {
                                    ParseFvdlDescriptionNode(xmlReader);
                                    break;
                                }
                                case "EngineVersion":
                                {
                                    version = xmlReader.ObtainCurrentNodeValue(false);
                                    break;
                                }
                                case "Rule":
                                {
                                    ParseFvdlRuleNode(xmlReader);
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to read FPR 'audit.fvdl'.");
                throw exception;
            }
        }

        private void ParseFvdlVulnerablityNode(XmlReader xmlReader)
        {
            try
            {
                FprVulnerability fprVulnerability = new FprVulnerability();
                fprVulnerability.Status = "Not Reviewed";
                while (xmlReader.Read())
                {
                    if (xmlReader.IsStartElement())
                    {
                        switch (xmlReader.Name)
                        {
                            case "ClassID":
                            {
                                fprVulnerability.ClassId = xmlReader.ObtainCurrentNodeValue(false);
                                break;
                            }
                            case "Kingdom":
                            {
                                fprVulnerability.Kingdom = xmlReader.ObtainCurrentNodeValue(false);
                                break;
                            }
                            case "Type":
                            {
                                fprVulnerability.Type = xmlReader.ObtainCurrentNodeValue(false);
                                break;
                            }
                            case "Subtype":
                            {
                                fprVulnerability.SubType = xmlReader.ObtainCurrentNodeValue(false);
                                break;
                            }
                            case "InstanceID":
                            {
                                fprVulnerability.InstanceId = xmlReader.ObtainCurrentNodeValue(false);
                                break;
                            }
                            case "Def":
                            {
                                fprVulnerability.ReplacementDefinitions.Add(xmlReader.GetAttribute("key"),
                                    xmlReader.GetAttribute("value"));
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
                            {
                                break;
                            }
                        }
                    }
                    else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("Vulnerability"))
                    {
                        fprVulnerabilityList.Add(fprVulnerability);
                        return;
                    }
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to parse the FPR FVDL 'Vulnerability' node.");
                throw exception;
            }
        }

        private void ParseFvdlDescriptionNode(XmlReader xmlReader)
        {
            try
            {
                string classId = xmlReader.GetAttribute("classID");
                string abstractNode = string.Empty;
                string explanationNode = string.Empty;
                string recommendationsNode = string.Empty;
                Tuple<string, string> abstractOutput = new Tuple<string, string>(string.Empty, string.Empty);
                List<Tuple<string, string>> references = new List<Tuple<string, string>>();
                while (xmlReader.Read())
                {
                    if (xmlReader.IsStartElement())
                    {
                        switch (xmlReader.Name)
                        {
                            case "Abstract":
                            {
                                abstractNode = xmlReader.ObtainCurrentNodeValue(false);
                                abstractOutput = SanitizeAndParseAbstract(abstractNode);
                                break;
                            }
                            case "Explanation":
                            {
                                explanationNode = xmlReader.ObtainCurrentNodeValue(false);
                                explanationNode = SanitizeAndParseExplanation(explanationNode);
                                break;
                            }
                            case "Recommendations":
                            {
                                recommendationsNode = xmlReader.ObtainCurrentNodeValue(false);
                                recommendationsNode = SanitizeAndParseRecommendations(recommendationsNode);
                                break;
                            }
                            default:
                            {
                                break;
                            }
                        }
                    }
                    else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name == "Description")
                    {
                        foreach (FprVulnerability fprVulnerability in fprVulnerabilityList.Where(x =>
                            x.ClassId.Equals(classId)))
                        {
                            fprVulnerability.Description = explanationNode;
                            fprVulnerability.FixText = recommendationsNode;
                            fprVulnerability.Output = InjectDefinitionValues(abstractOutput.Item1, fprVulnerability);
                            fprVulnerability.RiskStatement = abstractOutput.Item2;
                        }

                        return;
                    }
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to parse FVDL 'Description' node.");
                throw exception;
            }
        }

        private void ParseFvdlRuleNode(XmlReader xmlReader)
        {
            try
            {
                string classId = xmlReader.GetAttribute("id");
                string impact = string.Empty;
                string probability = string.Empty;
                string[] ccis = { };

                while (xmlReader.Read())
                {
                    if (xmlReader.IsStartElement() && xmlReader.Name.Equals("Group"))
                    {
                        switch (xmlReader.GetAttribute("name"))
                        {
                            case "altcategoryDISACCI2":
                            {
                                ccis = ParseCciValues(xmlReader.ObtainCurrentNodeValue(false));
                                break;
                            }
                            case "Impact":
                            {
                                impact = xmlReader.ObtainCurrentNodeValue(false).ToFortifyThreshold();
                                break;
                            }
                            case "Probability":
                            {
                                probability = xmlReader.ObtainCurrentNodeValue(false).ToFortifyThreshold();
                                break;
                            }
                        }
                    }
                    else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name == "Rule")
                    {
                        foreach (FprVulnerability fprVulnerability in fprVulnerabilityList.Where(x =>
                            x.ClassId.Equals(classId)))
                        {
                            fprVulnerability.RawRisk = ObtainRawRisk(impact, probability);
                            fprVulnerability.CCIs = ccis;
                        }

                        return;
                    }
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to parse the FVDL 'Rule' Node.");
                throw exception;
            }
        }

        private string[] ParseCciValues(string rawText)
        {
            try
            {
                if (rawText.Equals("None"))
                {
                    return new string[] { };
                }

                string sanitized = rawText.Replace("CCI-", "");
                string[] delimiter = {", "};
                return sanitized.Split(delimiter, StringSplitOptions.None);
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to parse CCI values from the FVDL 'Rule' Node.");
                throw exception;
            }
        }

        private string ObtainRawRisk(string impact, string probability)
        {
            try
            {
                return _fortifySeverities
                    .FirstOrDefault(x => x.Impact.Equals(impact) && x.Probability.Equals(probability)).Severity;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }
        }

        private string SantizeNodeContent(string content)
        {
            try
            {
                return content.Replace("&lt;", "<").Replace("&gt;", ">");
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to sanitize the FPR node content.");
                throw exception;
            }
        }

        private Tuple<string, string> SanitizeAndParseAbstract(string unsanitizedAbstract)
        {
            try
            {
                string sanitizedAbstract = SantizeNodeContent(unsanitizedAbstract);
                string riskStatement = string.Empty;
                string output = string.Empty;
                string[] stringsToRemove = new string[]
                {
                    "<b>", "</b>", "<pre>", "</pre>", "<code>", "</code>", "&lt;", "&gt;"
                };
                foreach (string item in stringsToRemove)
                {
                    sanitizedAbstract = sanitizedAbstract.Replace(item, string.Empty);
                }

                sanitizedAbstract = sanitizedAbstract.Replace("<Replace", "&lt;Replace").Replace("/>", "/&gt;");
                Stream stream = GenerateStreamFromString(sanitizedAbstract);
                using (XmlReader xmlReader = XmlReader.Create(stream))
                {
                    while (xmlReader.Read())
                    {
                        if (xmlReader.IsStartElement())
                        {
                            switch (xmlReader.Name)
                            {
                                case "Paragraph":
                                {
                                    output = xmlReader.ObtainCurrentNodeValue(false);
                                    break;
                                }
                                case "AltParagraph":
                                {
                                    riskStatement = xmlReader.ObtainCurrentNodeValue(false);
                                    break;
                                }
                                default:
                                {
                                    break;
                                }
                            }
                        }
                        else if (xmlReader.NodeType == XmlNodeType.Text)
                        {
                            riskStatement = xmlReader.Value;
                        }
                    }
                }

                return new Tuple<string, string>(output, riskStatement);
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to sanitize the FPR 'Abstract' node value.");
                throw exception;
            }
        }

        private string SanitizeAndParseExplanation(string unsanitizedExplanation)
        {
            try
            {
                string sanitizedExplanation = unsanitizedExplanation;
                string doubleCarriageReturn = Environment.NewLine + Environment.NewLine;
                string description = string.Empty;
                string[] stringsToRemove = new string[]
                {
                    "<b>", "</b>", "<pre>", "</pre>", "<code>", "</code>", "&lt;", "&gt;"
                };
                foreach (string item in stringsToRemove)
                {
                    switch (item)
                    {
                        case "<b>":
                        {
                            sanitizedExplanation = unsanitizedExplanation.Replace(item, doubleCarriageReturn);
                            break;
                        }
                        case "</b>":
                        {
                            sanitizedExplanation = unsanitizedExplanation.Replace(item, Environment.NewLine);
                            break;
                        }
                        case "<pre>":
                        {
                            sanitizedExplanation = unsanitizedExplanation.Replace(item, doubleCarriageReturn);
                            break;
                        }
                        default:
                        {
                            sanitizedExplanation = unsanitizedExplanation.Replace(item, "");
                            break;
                        }
                    }
                }

                Stream stream = GenerateStreamFromString(sanitizedExplanation);
                using (XmlReader xmlReader = XmlReader.Create(stream))
                {
                    while (xmlReader.Read())
                    {
                        if (xmlReader.NodeType == XmlNodeType.Text)
                        {
                            description = string.Concat(description, xmlReader.Value);
                            continue;
                        }

                        if (xmlReader.IsStartElement())
                        {
                            if (xmlReader.Name.Equals("Content"))
                            {
                                continue;
                            }

                            string nodeName = xmlReader.Name;
                            while (xmlReader.NodeType != XmlNodeType.EndElement && !xmlReader.Name.Equals(nodeName))
                            {
                                xmlReader.Read();
                            }
                        }
                    }
                }

                return description;
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to sanitize FPR 'Description' value.");
                throw exception;
            }
        }

        private string SanitizeAndParseRecommendations(string unsanitizedRecommendations)
        {
            try
            {
                string sanitizedRecommendations = unsanitizedRecommendations;
                string doubleCarriageReturn = Environment.NewLine + Environment.NewLine;
                string[] stringsToRemove = new string[]
                {
                    "<Content>", "<Paragraph>", "</Paragraph>", "</Content>", "<b>", "</b>", "<pre>", "</pre>",
                    "<code>", "</code>", "&lt;", "&gt;"
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
                LogWriter.LogError("Unable to sanitize FPR 'Recommendations' value.");
                throw exception;
            }
        }

        private string InjectDefinitionValues(string input, FprVulnerability fprVulnerability)
        {
            try
            {
                string output = input;
                string placeholder = string.Empty;
                foreach (string key in fprVulnerability.ReplacementDefinitions.Keys)
                {
                    string[] locationDefArray = new string[] {"SourceFunction", "SinkFunction", "PrimaryCall.name"};
                    placeholder = "<Replace key=\"" + key + "\"/>";
                    if (output.Contains(placeholder))
                    {
                        output = output.Replace(placeholder, fprVulnerability.ReplacementDefinitions[key]);
                    }

                    if (locationDefArray.Contains(key))
                    {
                        switch (key)
                        {
                            case "SourceFunction":
                            {
                                placeholder = "<Replace key=\"" + key + "\" link=\"SourceLocation\"/>";
                                if (output.Contains(placeholder))
                                {
                                    output = output.Replace(placeholder, fprVulnerability.ReplacementDefinitions[key]);
                                }

                                break;
                            }
                            case "SinkFunction":
                            {
                                placeholder = "<Replace key=\"" + key + "\" link=\"SinkLocation\"/>";
                                if (output.Contains(placeholder))
                                {
                                    output = output.Replace(placeholder, fprVulnerability.ReplacementDefinitions[key]);
                                }

                                break;
                            }
                            case "PrimaryCall.name":
                            {
                                placeholder = "<Replace key=\"" + key + "\" link=\"PrimaryLocation\"/>";
                                if (output.Contains(placeholder))
                                {
                                    output = output.Replace(placeholder, fprVulnerability.ReplacementDefinitions[key]);
                                }

                                break;
                            }
                            default:
                            {
                                break;
                            }
                        }
                    }
                }

                return output;
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to inject definition values into FPR vulnerability.");
                throw exception;
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
                    List<FprVulnerability.AuditComment> auditComments = new List<FprVulnerability.AuditComment>();
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
                                    auditComments = PopulateCommentsList(xmlReader);
                                    break;
                                }
                            }
                        }
                        else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("ns2:Issue"))
                        {
                            FprVulnerability fprVulnerability =
                                fprVulnerabilityList.FirstOrDefault(x => x.InstanceId.Equals(instanceId));
                            if (fprVulnerability != null)
                            {
                                fprVulnerability.Status = analysisValue.ToVulneratorStatus();
                                fprVulnerability.AuditComments = auditComments;
                            }

                            auditComments = new List<FprVulnerability.AuditComment>();
                            instanceId = string.Empty;
                            analysisValue = string.Empty;
                        }
                    }
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to read FPR 'audit.xml' file.");
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
                    {
                        xmlReader.Read();
                    }

                    xmlReader.Read();
                    return xmlReader.Value;
                }

                return "Analysis Not Set";
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to obtain FPR 'Analysis' value.");
                throw exception;
            }
        }

        private List<FprVulnerability.AuditComment> PopulateCommentsList(XmlReader xmlReader)
        {
            try
            {
                List<FprVulnerability.AuditComment> auditComments = new List<FprVulnerability.AuditComment>();
                FprVulnerability.AuditComment auditComment = new FprVulnerability.AuditComment();

                while (xmlReader.Read())
                {
                    if (xmlReader.IsStartElement())
                    {
                        switch (xmlReader.Name)
                        {
                            case "ns2:Content":
                            {
                                auditComment.Content = xmlReader.ObtainCurrentNodeValue(false);
                                break;
                            }
                            case "ns2:Username":
                            {
                                auditComment.UserName = xmlReader.ObtainCurrentNodeValue(false);
                                break;
                            }
                            case "ns2:Timestamp":
                            {
                                auditComment.EditTime = DateTime.Parse(xmlReader.ObtainCurrentNodeValue(false));
                                break;
                            }
                        }
                    }
                    else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("ns2:Comment"))
                    {
                        auditComments.Add(auditComment);
                        auditComment = new FprVulnerability.AuditComment();
                    }
                    else if (xmlReader.NodeType == XmlNodeType.EndElement &&
                             xmlReader.Name.Equals("ns2:ThreadedComments"))
                    {
                        return auditComments;
                    }
                }
                return auditComments;
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to obtain FPR 'Comment' values.");
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

        private Stream GenerateStreamFromString(string streamString)
        {
            try
            {
                MemoryStream memoryStream = new MemoryStream();
                StreamWriter streamWriter = new StreamWriter(memoryStream);
                streamWriter.Write(streamString);
                streamWriter.Flush();
                memoryStream.Position = 0;
                return memoryStream;
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to generate a Stream from the provided string.");
                throw exception;
            }
        }
    }
}