using log4net;
using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.IO;
using System.IO.Compression;
using System.Linq;
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
        private string file = string.Empty;
        private string sourcePlaceholder = "HPE Fortify SCA";
        private string version = string.Empty;
        private DatabaseInterface databaseInterface = new DatabaseInterface();
        private List<FprVulnerability> fprVulnerabilityList = new List<FprVulnerability>();

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

                using (SQLiteTransaction sqliteTransaction = FindingsDatabaseActions.sqliteConnection.BeginTransaction())
                {
                    using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                    {
                        InsertParameterPlaceholders(sqliteCommand);
                        using (Stream stream = System.IO.File.OpenRead(file.FilePath))
                        {
                            using (ZipArchive zipArchive = new ZipArchive(stream, ZipArchiveMode.Read))
                            {
                                ZipArchiveEntry auditFvdl = zipArchive.Entries.FirstOrDefault(x => x.Name.Equals("audit.fvdl"));
                                ParseAuditFvdlWithXmlReader(auditFvdl, sqliteCommand);
                                ZipArchiveEntry auditXml = zipArchive.Entries.FirstOrDefault(x => x.Name.Equals("audit.xml"));
                                ParseAuditXmlWithXmlReader(auditXml);
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
                                        sqliteCommand.Parameters["Discovered_Software_Name"].Value = ObtainCurrentNodeValue(xmlReader);
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
                                        sqliteCommand.Parameters["Source_Version"].Value = ObtainCurrentNodeValue(xmlReader);
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
                                    fprVulnerability.Type = ObtainCurrentNodeValue(xmlReader);
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
                string output = string.Empty;
                string description = string.Empty;
                string riskStatement = string.Empty;
                string fixText = string.Empty;
                Dictionary<string, string> references = new Dictionary<string, string>();
                while (xmlReader.Read())
                {
                    if (xmlReader.IsStartElement())
                    {
                        switch (xmlReader.Name)
                        {
                            case "Abstract":
                                {
                                    output = ObtainCurrentNodeValue(xmlReader);
                                    break;
                                }
                            case "Explanation":
                                {
                                    description = ObtainCurrentNodeValue(xmlReader);
                                    break;
                                }
                            case "Recommendations":
                                {
                                    fixText = ObtainCurrentNodeValue(xmlReader);
                                    break;
                                }
                            case "Reference":
                                {
                                    string value = ObtainReferencesValue(xmlReader);
                                    string key = ObtainReferencesKey(xmlReader);
                                    string keyCheck;
                                    if (!references.TryGetValue(key, out keyCheck))
                                    { references.Add(key, value); }
                                    break;
                                }
                            default:
                                { break; }
                        }
                    }
                    else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name == "Description")
                    {
                        
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

        private void InsertParameterPlaceholders(SQLiteCommand sqliteCommand)
        {
            try
            {
                string[] parameters = new string[]
                {
                    // Groups Table
                    "Group_ID", "Group_Name", "Is_Accreditation", "Accreditation_ID", "Organization_ID",
                    // Hardware Table
                    "Hardware_ID", "Host_Name", "FQDN", "NetBIOS", "Is_Virtual_Server", "NIAP_Level", "Manufacturer", "ModelNumber",
                    "Is_IA_Enabled", "SerialNumber", "Role", "Lifecycle_Status_ID", "Scan_IP",
                    // IP_Addresses Table
                    "IP_Address_ID", "IP_Address",
                    // MAC_Addresses Table
                    "MAC_Address_ID", "MAC_Address",
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