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
using Vulnerator.Model.ModelHelper;
using Vulnerator.Model.Object;

namespace Vulnerator.Model.BusinessLogic
{
    class FprReader
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(Logger));
        private string softwareName = string.Empty;
        private string firstDiscovered = DateTime.Now.ToShortDateString();
        private string lastObserved = DateTime.Now.ToShortDateString();
        private string version = string.Empty;
        private DatabaseInterface databaseInterface = new DatabaseInterface();
        private List<FprVulnerability> fprVulnerabilityList = new List<FprVulnerability>();
        string[] persistentParameters = new string[] {
            "Source_Name", "Source_Version", "Discovered_Software_Name", "Displayed_Software_Name", "Finding_Source_File_Name",
            "Finding_Type", "First_Discovered", "Last_Observed"
        };

        public string ReadFpr(Object.File file)
        {
            try
            {
                if (file.FilePath.IsFileInUse())
                {
                    log.Error(file.FileName + " is in use; please close any open instances and try again.");
                    return "Failed; File In Use";
                }
                ReadFprArchive(file);
                return "Processed";
            }
            catch (Exception exception)
            {
                log.Error("Unable to process FPR file.");
                log.Debug("Exception details:", exception);
                return "Failed; See Log";
            }
        }

        private void ReadFprArchive(Object.File file)
        {
            try
            {
                if (DatabaseBuilder.sqliteConnection.State.ToString().Equals("Closed"))
                { DatabaseBuilder.sqliteConnection.Open(); }
                using (SQLiteTransaction sqliteTransaction = FindingsDatabaseActions.sqliteConnection.BeginTransaction())
                {
                    using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                    {
                        InsertParameterPlaceholders(sqliteCommand);
                        databaseInterface.InsertDataEntryDate(sqliteCommand);
                        databaseInterface.InsertGroup(sqliteCommand, file);
                        databaseInterface.InsertParsedFile(sqliteCommand, file);
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
                        sqliteCommand.Parameters["Source_Name"].Value = "HPE Fortify SCA";
                        sqliteCommand.Parameters["Source_Version"].Value = version;
                        sqliteCommand.Parameters["Discovered_Software_Name"].Value = softwareName;
                        sqliteCommand.Parameters["Displayed_Software_Name"].Value = softwareName;
                        sqliteCommand.Parameters["Finding_Source_File_Name"].Value = file.FileName;
                        sqliteCommand.Parameters["Finding_Type"].Value = "Fortify";
                        sqliteCommand.Parameters["First_Discovered"].Value = firstDiscovered;
                        sqliteCommand.Parameters["Last_Observed"].Value = lastObserved;
                        databaseInterface.InsertVulnerabilitySource(sqliteCommand);
                        databaseInterface.InsertSoftware(sqliteCommand);
                        foreach (FprVulnerability fprVulnerability in fprVulnerabilityList)
                        {
                            sqliteCommand.Parameters["Unique_Vulnerability_Identifier"].Value = fprVulnerability.ClassId;
                            sqliteCommand.Parameters["Vulnerability_Group_Title"].Value = fprVulnerability.Kingdom;
                            sqliteCommand.Parameters["VulnerabilityFamilyOrClass"].Value = fprVulnerability.Type;
                            sqliteCommand.Parameters["Vulnerability_Title"].Value = fprVulnerability.SubType;
                            sqliteCommand.Parameters["Vulnerability_Description"].Value = fprVulnerability.Description;
                            sqliteCommand.Parameters["Risk_Statement"].Value = fprVulnerability.RiskStatement;
                            sqliteCommand.Parameters["Fix_Text"].Value = fprVulnerability.FixText;
                            sqliteCommand.Parameters["Instance_Identifier"].Value = fprVulnerability.InstanceId;
                            sqliteCommand.Parameters["Tool_Generated_Output"].Value = fprVulnerability.Output;
                            sqliteCommand.Parameters["Status"].Value = fprVulnerability.Status;
                            sqliteCommand.Parameters["Comments"].Value = fprVulnerability.Comments;
                            databaseInterface.InsertVulnerability(sqliteCommand);
                            databaseInterface.MapVulnerabilityToSource(sqliteCommand);
                            databaseInterface.InsertUniqueFinding(sqliteCommand);
                            foreach (Tuple<string,string> reference in fprVulnerability.References)
                            { databaseInterface.InsertAndMapVulnerabilityReferences(sqliteCommand, reference); }
                            foreach (SQLiteParameter parameter in sqliteCommand.Parameters)
                            {
                                if (!persistentParameters.Contains(parameter.ParameterName))
                                { sqliteCommand.Parameters[parameter.ParameterName].Value = string.Empty; }
                            }
                        }
                    }
                    sqliteTransaction.Commit();
                }
                DatabaseBuilder.sqliteConnection.Close();
            }
            catch (Exception exception)
            {
                log.Error("Unable to read FPR Archive.");
                throw exception;
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
                            switch (xmlReader.Name)
                            {
                                case "CreatedTS":
                                    {
                                        firstDiscovered = lastObserved = DateTime.Parse(xmlReader.GetAttribute("date")).ToShortDateString();
                                        break;
                                    }
                                case "BuildID":
                                    {
                                        softwareName = ObtainCurrentNodeValue(xmlReader);
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
                                        version = ObtainCurrentNodeValue(xmlReader);
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
                log.Error("Unable to read \"audit.fvdl\".");
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
                                    fprVulnerability.ClassId = ObtainCurrentNodeValue(xmlReader);
                                    break;
                                }
                            case "Kingdom":
                                {
                                    fprVulnerability.Kingdom = ObtainCurrentNodeValue(xmlReader);
                                    break;
                                }
                            case "Type":
                                {
                                    fprVulnerability.Type = ObtainCurrentNodeValue(xmlReader);
                                    break;
                                }
                            case "Subtype":
                                {
                                    fprVulnerability.SubType = ObtainCurrentNodeValue(xmlReader);
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
                                    abstractNode = ObtainCurrentNodeValue(xmlReader);
                                    abstractOutput = SanitizeAndParseAbstract(abstractNode);
                                    break;
                                }
                            case "Explanation":
                                {
                                    explanationNode = ObtainCurrentNodeValue(xmlReader);
                                    explanationNode = SanitizeAndParseExplanation(explanationNode);
                                    break;
                                }
                            case "Recommendations":
                                {
                                    recommendationsNode = ObtainCurrentNodeValue(xmlReader);
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
                log.Error("Unable to parse FVDL Description node.");
                throw exception;
            }
        }

        private string SantizeNodeContent(string content)
        {
            try
            { return content.Replace("&lt;", "<").Replace("&gt;", ">"); }
            catch (Exception exception)
            {
                log.Error("Unable to sanitize node content.");
                throw exception;
            }
        }

        private Tuple<string,string> SanitizeAndParseAbstract(string unsanitizedAbstract)
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
                                        output = ObtainCurrentNodeValue(xmlReader);
                                        break;
                                    }
                                case "AltParagraph":
                                    {
                                        riskStatement = ObtainCurrentNodeValue(xmlReader);
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
                log.Error("Unable to sanitize the \"Abstract\" node value.");
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
                log.Error("Unable to sanitize Description value.");
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
                if (!xmlReader.Value.Contains("Security Technical Implementation"))
                { return "Discard"; }
                return "STIG";
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
                            FprVulnerability fprVulnerability = fprVulnerabilityList.FirstOrDefault(x => x.InstanceId.Equals(instanceId));
                            if (fprVulnerability != null)
                            {
                                fprVulnerability.Status = ConvertAnalysisValue(analysisValue);
                                if (commentsDictionary.Count > 0)
                                {
                                    commentsDictionary.OrderByDescending(x => x.Key);
                                    fprVulnerability.Comments = string.Format("{0}:{1}{2}",
                                        commentsDictionary.Last().Key.ToShortDateString(),
                                        Environment.NewLine,
                                        commentsDictionary.Last().Value);
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
                switch (analysisValue)
                {
                    case "Not an Issue":
                        { return "Completed"; }
                    case "Not a Finding":
                        { return "Completed"; }
                    case "Reliability Issue":
                        { return "Ongoing"; }
                    case "Bad Practice":
                        { return "Ongoing"; }
                    case "Suspicious":
                        { return "Ongoing"; }
                    case "Exploitable":
                        { return "Ongoing"; }
                    default:
                        { return analysisValue; }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to convert analysis value.");
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
                log.Error("Unable to generate a Stream from the provided string.");
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
                    "Group_ID", "Group_Name", "Is_Accreditation", "Accreditation_ID", "Organization_ID",
                    // FindingTypes Table
                    "Finding_Type",
                    // Hardware Table
                    "Hardware_ID", "Host_Name", "FQDN", "NetBIOS", "Is_Virtual_Server", "NIAP_Level", "Manufacturer", "ModelNumber",
                    "Is_IA_Enabled", "SerialNumber", "Role", "Lifecycle_Status_ID", "Scan_IP",
                    // IP_Addresses Table
                    "IP_Address_ID", "IP_Address",
                    // MAC_Addresses Table
                    "MAC_Address_ID", "MAC_Address",
                    // Software Table
                    "Software_ID", "Discovered_Software_Name", "Displayed_Software_Name", "Software_Acronym", "Software_Version",
                    "Function", "Install_Date", "DADMS_ID", "DADMS_Disposition", "DADMS_LDA", "Has_Custom_Code", "IaOrIa_Enabled",
                    "Is_OS_Or_Firmware", "FAM_Accepted", "Externally_Authorized", "ReportInAccreditation_Global",
                    "ApprovedForBaseline_Global", "BaselineApprover_Global", "Instance",
                    // UniqueFindings Table
                    "Unique_Finding_ID", "", "Tool_Generated_Output", "Comments", "Finding_Details", "Technical_Mitigation",
                    "Proposed_Mitigation", "Predisposing_Conditions", "Impact", "Likelihood", "Severity", "Risk", "Residual_Risk",
                    "First_Discovered", "Last_Observed", "Approval_Status", "Approval_Date", "Approval_Expiration_Date",
                    "Delta_Analysis_Required", "Finding_Type_ID", "Finding_Source_ID", "Status", "Vulnerability_ID", "Hardware_ID",
                    "Severity_Override", "Severity_Override_Justification", "Technology_Area", "Web_DB_Site", "Web_DB_Instance",
                    "Classification", "CVSS_Environmental_Score", "CVSS_Environmental_Vector",
                    // UniqueFindingSourceFiles Table
                    "Finding_Source_File_ID", "Finding_Source_File_Name", 
                    // Vulnerabilities Table
                    "Vulnerability_ID", "Instance_Identifier", "Unique_Vulnerability_Identifier", "Vulnerability_Group_ID", "Vulnerability_Group_Title",
                    "Secondary_Vulnerability_Identifier", "VulnerabilityFamilyOrClass", "Vulnerability_Version", "Vulnerability_Release",
                    "Vulnerability_Title", "Vulnerability_Description", "Risk_Statement", "Fix_Text", "Published_Date", "Modified_Date",
                    "Fix_Published_Date", "Raw_Risk", "CVSS_Base_Score", "CVSS_Base_Vector", "CVSS_Temporal_Score", "CVSS_Temporal_Vector",
                    "Check_Content", "False_Positives", "False_Negatives", "Documentable", "Mitigations", "Mitigation_Control",
                    "Potential_Impacts", "Third_Party_Tools", "Security_Override_Guidance", "Overflow",
                    // VulnerabilityReferences Table
                    "Reference_ID", "Reference", "Reference_Type",
                    // VulnerabilitySources Table
                    "Vulnerability_Source_ID", "Source_Name", "Source_Secondary_Identifier", "Vulnerability_Source_File_Name",
                    "Source_Description", "Source_Version", "Source_Release",
                    // CCI Table
                    "CCI",
                    // ScapScores Table
                    "Score", "Scan_Date"
                };
                foreach (string parameter in parameters)
                { sqliteCommand.Parameters.Add(new SQLiteParameter(parameter, string.Empty)); }
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to insert SQLiteParameter placeholders into SQLiteCommand"));
                throw exception;
            }
        }
    }
}