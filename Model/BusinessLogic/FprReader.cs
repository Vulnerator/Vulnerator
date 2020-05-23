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
        private string firstDiscovered = DateTime.Now.ToShortDateString();
        private string lastObserved = DateTime.Now.ToShortDateString();
        private string version = string.Empty;
        private DatabaseInterface databaseInterface = new DatabaseInterface();
        private List<FprVulnerability> fprVulnerabilityList = new List<FprVulnerability>();
        string[] persistentParameters = new string[] {
            "SourceName", "SourceVersion", "DiscoveredSoftwareName", "DisplayedSoftwareName", "FindingSourceFileName",
            "FindingType", "FirstDiscovered", "LastObserved"
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
                { DatabaseBuilder.sqliteConnection.Open(); }
                using (SQLiteTransaction sqliteTransaction = DatabaseBuilder.sqliteConnection.BeginTransaction())
                {
                    using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                    {
                        InsertParameterPlaceholders(sqliteCommand);
                        sqliteCommand.Parameters["Name"].Value = "All";
                        databaseInterface.InsertParsedFileSource(sqliteCommand, file);
                        using (Stream stream = System.IO.File.OpenRead(file.FilePath))
                        {
                            using (ZipArchive zipArchive = new ZipArchive(stream, ZipArchiveMode.Read))
                            {
                                ZipArchiveEntry auditFvdl = zipArchive.Entries.FirstOrDefault(x => x.Name.Equals("audit.fvdl"));
                                ParseAuditFvdlWithXmlReader(auditFvdl, sqliteCommand);
                                ZipArchiveEntry auditXml = zipArchive.Entries.FirstOrDefault(x => x.Name.Equals("audit.xml"));
                                if (auditXml != null)
                                { ParseAuditXmlWithXmlReader(auditXml); }
                            }
                        }
                        sqliteCommand.Parameters["SourceName"].Value = "HPE Fortify SCA";
                        sqliteCommand.Parameters["SourceVersion"].Value = version;
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
                            sqliteCommand.Parameters["VulnerabilityGroup_Title"].Value = fprVulnerability.Kingdom;
                            sqliteCommand.Parameters["VulnerabilityFamilyOrClass"].Value = fprVulnerability.Type;
                            sqliteCommand.Parameters["VulnerabilityTitle"].Value = fprVulnerability.SubType;
                            sqliteCommand.Parameters["VulnerabilityDescription"].Value = fprVulnerability.Description;
                            sqliteCommand.Parameters["RiskStatement"].Value = fprVulnerability.RiskStatement;
                            sqliteCommand.Parameters["FixText"].Value = fprVulnerability.FixText;
                            sqliteCommand.Parameters["InstanceIdentifier"].Value = fprVulnerability.InstanceId;
                            sqliteCommand.Parameters["ToolGeneratedOutput"].Value = fprVulnerability.Output;
                            sqliteCommand.Parameters["Status"].Value = fprVulnerability.Status;
                            sqliteCommand.Parameters["Comments"].Value = fprVulnerability.Comments;
                            databaseInterface.InsertVulnerability(sqliteCommand);
                            databaseInterface.MapVulnerabilityToSource(sqliteCommand);
                            databaseInterface.InsertUniqueFinding(sqliteCommand);
                            foreach (Tuple<string, string> reference in fprVulnerability.References)
                            {
                                sqliteCommand.Parameters.Add(new SQLiteParameter("Reference", reference.Item2));
                                sqliteCommand.Parameters.Add(new SQLiteParameter("ReferenceType", reference.Item1));
                                databaseInterface.InsertAndMapVulnerabilityReferences(sqliteCommand);
                            }
                            foreach (SQLiteParameter parameter in sqliteCommand.Parameters)
                            {
                                if (!persistentParameters.Contains(parameter.ParameterName))
                                { sqliteCommand.Parameters[parameter.ParameterName].Value = string.Empty; }
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
            { DatabaseBuilder.sqliteConnection.Close(); }
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
                            switch (xmlReader.Name)
                            {
                                case "CreatedTS":
                                    {
                                        firstDiscovered = lastObserved = DateTime.Parse(xmlReader.GetAttribute("date")).ToShortDateString();
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
                                default:
                                    { break; }
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
                            case "Reference":
                                {
                                    string value = ObtainReferencesValue(xmlReader);
                                    string key = ObtainReferencesKey(xmlReader);
                                    if (key.Equals("Discard"))
                                    { break; }
                                    Regex regex = new Regex(Properties.Resources.RegexCatText);
                                    value = regex.Replace(value, string.Empty);
                                    regex = new Regex(Properties.Resources.RegexStigId);
                                    foreach (Match match in regex.Matches(value))
                                    {
                                        Tuple<string, string> reference = new Tuple<string, string>(key, match.ToString());
                                        if (!references.Contains(reference))
                                        { references.Add(reference); }
                                    }
                                    break;
                                }
                            default:
                                { break; }
                        }
                    }
                    else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name == "Description")
                    {
                        foreach (FprVulnerability fprVulnerability in fprVulnerabilityList.Where(x => x.ClassId.Equals(classId)))
                        {
                            fprVulnerability.Description = explanationNode;
                            fprVulnerability.FixText = recommendationsNode;
                            fprVulnerability.Output = InjectDefinitionValues(abstractOutput.Item1, fprVulnerability);
                            fprVulnerability.RiskStatement = abstractOutput.Item2;
                            foreach (Tuple<string, string> reference in references)
                            { fprVulnerability.References.Add(reference); }
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

        private string SantizeNodeContent(string content)
        {
            try
            { return content.Replace("&lt;", "<").Replace("&gt;", ">"); }
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
                string[] stringsToRemove = new string[] {
                    "<b>", "</b>", "<pre>", "</pre>", "<code>", "</code>", "&lt;", "&gt;"
                };
                foreach (string item in stringsToRemove)
                { sanitizedAbstract = sanitizedAbstract.Replace(item, string.Empty); }
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
                                    { break; }
                            }
                        }
                        else if (xmlReader.NodeType == XmlNodeType.Text)
                        { riskStatement = xmlReader.Value; }
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
                string[] stringsToRemove = new string[] {
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
                            { continue; }
                            string nodeName = xmlReader.Name;
                            while (xmlReader.NodeType != XmlNodeType.EndElement && !xmlReader.Name.Equals(nodeName))
                            { xmlReader.Read(); }
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
                return output;
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to inject definition values into FPR vulnerability.");
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
                LogWriter.LogError("Unable to obtain FPR 'References' value.");
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
                if (!xmlReader.Value.Contains("Security Technical Implementation"))
                { return "Discard"; }
                return "STIG";
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to obtain FPR 'References' key.");
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
                            FprVulnerability fprVulnerability = fprVulnerabilityList.FirstOrDefault(x => x.InstanceId.Equals(instanceId));
                            if (fprVulnerability != null)
                            {
                                fprVulnerability.Status = analysisValue.ToVulneratorStatus();
                                if (commentsDictionary.Count > 0)
                                {
                                    commentsDictionary.OrderByDescending(x => x.Key);
                                    fprVulnerability.Comments =
                                        $"{commentsDictionary.Last().Key.ToShortDateString()}:{Environment.NewLine}{commentsDictionary.Last().Value}";
                                }
                            }
                            commentsDictionary.Clear();
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
                    { xmlReader.Read(); }
                    xmlReader.Read();
                    return xmlReader.Value;
                }
                else
                { return "Analysis Not Set"; }
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to obtain FPR 'Analysis' value.");
                throw exception;
            }
        }

        private void PopulateCommentsDictionary(XmlReader xmlReader, Dictionary<DateTime, string> commentsDictionary)
        {
            try
            {
                string comment = string.Empty;
                DateTime timestamp = new DateTime();
                string username = string.Empty;
                while (xmlReader.Read())
                {
                    if (xmlReader.IsStartElement())
                    {
                        switch (xmlReader.Name)
                        {
                            case "ns2:Content":
                                {
                                    comment = xmlReader.ObtainCurrentNodeValue(false);
                                    break;
                                }
                            case "ns2:Username":
                                {
                                    username = xmlReader.ObtainCurrentNodeValue(false);
                                    break;
                                }
                            case "ns2:Timestamp":
                                {
                                    timestamp = DateTime.Parse(xmlReader.ObtainCurrentNodeValue(false));
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
                        { commentsDictionary.Add(timestamp, $"{username}: {comment}"); }
                        comment = string.Empty;
                        timestamp = new DateTime();
                    }
                    else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("ns2:ThreadedComments"))
                    { return; }
                }
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

        private void InsertParameterPlaceholders(SQLiteCommand sqliteCommand)
        {
            try
            {
                string[] parameters = new string[]
                {
                    // Groups Table
                    "Group_ID", "Name", "IsAccreditation", "Accreditation_ID", "Organization_ID",
                    // FindingTypes Table
                    "FindingType",
                    // Hardware Table
                    "Hardware_ID", "DiscoveredHostName", "FQDN", "NetBIOS", "IsVirtualServer", "NIAP_Level", "Manufacturer", "ModelNumber",
                    "IsIA_Enabled", "SerialNumber", "Role", "Lifecycle_Status_ID", "ScanIP",
                    // IP_Addresses Table
                    "IP_Address_ID", "IP_Address",
                    // MAC_Addresses Table
                    "MAC_Address_ID", "MAC_Address",
                    // Software Table
                    "Software_ID", "DiscoveredSoftwareName", "DisplayedSoftwareName", "SoftwareAcronym", "SoftwareVersion",
                    "Function", "InstallDate", "DADMS_ID", "DADMS_Disposition", "DADMS_LDA", "HasCustomCode", "IaOrIa_Enabled",
                    "Is_OS_Or_Firmware", "FAM_Accepted", "ExternallyAuthorized", "ReportInAccreditationGlobal",
                    "ApprovedForBaselineGlobal", "BaselineApproverGlobal", "Instance",
                    // UniqueFindings Table
                    "UniqueFinding_ID", "", "ToolGeneratedOutput", "Comments", "FindingDetails", "TechnicalMitigation",
                    "ProposedMitigation", "PredisposingConditions", "Impact", "Likelihood", "Severity", "Risk", "ResidualRisk",
                    "FirstDiscovered", "LastObserved", "Approval_Status", "ApprovalDate", "Approval_Expiration_Date",
                    "DeltaAnalysisRequired", "FindingType_ID", "Finding_Source_ID", "Status", "Vulnerability_ID", "Hardware_ID",
                    "SeverityOverride", "SeverityOverrideJustification", "TechnologyArea", "WebDB_Site", "WebDB_Instance",
                    "Classification", "CVSS_EnvironmentalScore", "CVSS_EnvironmentalVector",
                    // UniqueFindingSourceFiles Table
                    "FindingSourceFile_ID", "FindingSourceFileName", 
                    // Vulnerabilities Table
                    "Vulnerability_ID", "InstanceIdentifier", "UniqueVulnerabilityIdentifier", "VulnerabilityGroup_ID", "VulnerabilityGroup_Title",
                    "SecondaryVulnerabilityIdentifier", "VulnerabilityFamilyOrClass", "VulnerabilityVersion", "VulnerabilityRelease",
                    "VulnerabilityTitle", "VulnerabilityDescription", "RiskStatement", "FixText", "PublishedDate", "ModifiedDate",
                    "FixPublishedDate", "RawRisk", "CVSS_BaseScore", "CVSS_BaseVector", "CVSS_TemporalScore", "CVSS_TemporalVector",
                    "CheckContent", "FalsePositives", "FalseNegatives", "Documentable", "Mitigations", "MitigationControl",
                    "PotentialImpacts", "ThirdPartyTools", "SecurityOverrideGuidance", "Overflow",
                    // VulnerabilityReferences Table
                    "Reference_ID", "Reference", "ReferenceType",
                    // VulnerabilitySources Table
                    "VulnerabilitySource_ID", "SourceName", "SourceSecondaryIdentifier", "VulnerabilitySourceFileName",
                    "SourceDescription", "SourceVersion", "SourceRelease",
                    // CCI Table
                    "CCI",
                    // ScapScores Table
                    "Score", "ScanDate"
                };
                foreach (string parameter in parameters)
                { sqliteCommand.Parameters.Add(new SQLiteParameter(parameter, string.Empty)); }
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to insert SQLiteParameter placeholders into SQLiteCommand");
                throw exception;
            }
        }
    }
}