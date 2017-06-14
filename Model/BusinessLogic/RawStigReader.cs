using log4net;
using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.IO;
using System.IO.Compression;
using System.Xml;
using Vulnerator.Model.DataAccess;
using Vulnerator.Model.Object;

namespace Vulnerator.Model.BusinessLogic
{
    public class RawStigReader
    {
        DatabaseInterface databaseInterface = new DatabaseInterface();
        private static readonly ILog log = LogManager.GetLogger(typeof(Logger));
        private int lastVulnerabilitySourceId = 0;
        private int lastVulnerabilityId = 0;
        private bool sourceUpdated = true;
        private List<string> iaControls = new List<string>();
        private List<string> ccis = new List<string>();
        private List<string> responsibilities = new List<string>();
        private Dictionary<string, string> replaceDictionary = PopulateReplaceDictionary();

        public void ReadRawStig(ZipArchiveEntry rawStig)
        {
            try
            {
                log.Info(string.Format("Begin ingestion of raw STIG file {0}", rawStig.Name));
                if (rawStig.Name.Contains("U_McAfee_MOVE3_0_Agentless_SVA_V1R3_Manual-xccdf.xml"))
                { Console.WriteLine("Not Parsing"); }
                if (DatabaseBuilder.sqliteConnection.State.ToString().Equals("Closed"))
                { DatabaseBuilder.sqliteConnection.Open(); }
                using (SQLiteTransaction sqliteTransaction = DatabaseBuilder.sqliteConnection.BeginTransaction())
                {
                    using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                    {
                        using (XmlReader xmlReader = XmlReader.Create(rawStig.Open(), GenerateXmlReaderSettings()))
                        {
                            while (xmlReader.Read() && sourceUpdated)
                            {
                                if (xmlReader.IsStartElement())
                                {
                                    switch (xmlReader.Name)
                                    {
                                        case "Benchmark":
                                            {
                                                sqliteCommand.Parameters.Add(new SQLiteParameter("Vulnerability_Source_File_Name", rawStig.Name));
                                                ReadBenchmarkNode(sqliteCommand, xmlReader);
                                                break;
                                            }
                                        case "Group":
                                            {
                                                ReadGroupNode(sqliteCommand, xmlReader);
                                                if (!sourceUpdated)
                                                { return; }
                                                break;
                                            }
                                        default:
                                            { break; }
                                    }
                                }
                            }
                        }
                    }
                    sqliteTransaction.Commit();
                }
                DatabaseBuilder.sqliteConnection.Close();
            }
            catch (Exception exception)
            {
                log.Error("Unable to process STIG file.");
                log.Debug("Exception details: " + exception);
            }
        }

        private void ReadBenchmarkNode(SQLiteCommand sqliteCommand, XmlReader xmlReader)
        {
            try
            {
                sqliteCommand.Parameters.Add(new SQLiteParameter("Source_Secondary_Identifier", xmlReader.GetAttribute("id")));
                while (xmlReader.Read())
                {
                    if (xmlReader.IsStartElement())
                    {
                        switch (xmlReader.Name)
                        {
                            case "title":
                                {
                                    string sourceName = ObtainCurrentNodeValue(xmlReader).Replace('_', ' ');
                                    sourceName = SanitizeSourceName(sourceName);
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Source_Name", sourceName));
                                    break;
                                }
                            case "description":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Source_Description", ObtainCurrentNodeValue(xmlReader)));
                                    break;
                                }
                            case "plain-text":
                                {
                                    string release = ObtainCurrentNodeValue(xmlReader);
                                    if (release.Contains(" "))
                                    { sqliteCommand.Parameters.Add(new SQLiteParameter("Source_Release", release.Split(' ')[1])); }
                                    else
                                    { sqliteCommand.Parameters.Add(new SQLiteParameter("Source_Release", release)); }
                                    break;
                                }
                            case "version":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Source_Version", ObtainCurrentNodeValue(xmlReader)));
                                    break;
                                }
                            case "Profile":
                                {
                                    SQLiteCommand clonedSqliteCommand = (SQLiteCommand)sqliteCommand.Clone();
                                    clonedSqliteCommand.CommandText = Properties.Resources.VerifyVulnerabilitySourceChange;
                                    using (SQLiteDataReader sqliteDataReader = clonedSqliteCommand.ExecuteReader())
                                    {
                                        int commandVersion;
                                        int commandRelease;
                                        bool commandVersionPopulated = int.TryParse(sqliteCommand.Parameters["Source_Version"].Value.ToString(), out commandVersion);
                                        bool commandReleasePopulated = int.TryParse(sqliteCommand.Parameters["Source_Release"].Value.ToString(), out commandRelease);
                                        if (!sqliteDataReader.HasRows || !commandVersionPopulated || !commandReleasePopulated)
                                        {
                                            lastVulnerabilitySourceId = databaseInterface.InsertVulnerabilitySource(sqliteCommand);
                                            return;
                                        }
                                        while (sqliteDataReader.Read())
                                        {
                                            int readerVersion;
                                            int readerRelease;
                                            bool readerVersionPopulated = int.TryParse(sqliteDataReader["Source_Version"].ToString(), out readerVersion);
                                            bool readerReleasePopulated = int.TryParse(sqliteDataReader["Source_Release"].ToString(), out readerRelease);
                                            if (commandVersion > readerVersion || commandRelease > readerRelease)
                                            {
                                                lastVulnerabilitySourceId = int.Parse(sqliteDataReader["Vulnerability_Source_ID"].ToString());
                                                databaseInterface.UpdateVulnerabilitySource(sqliteCommand, lastVulnerabilitySourceId);
                                                return;
                                            }
                                            else
                                            {
                                                sourceUpdated = false;
                                                sqliteCommand.Parameters.Clear();
                                                return;
                                            }
                                        }
                                    }
                                    return;
                                }
                            default:
                                { break; }
                        }
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to process Benchmark node.");
                throw exception;
            }
        }

        private void ReadGroupNode(SQLiteCommand sqliteCommand, XmlReader xmlReader)
        {
            try
            {
                sqliteCommand.Parameters.Add(new SQLiteParameter("Vulnerability_Group_ID", xmlReader.GetAttribute("id")));
                while (xmlReader.Read())
                {
                    if (xmlReader.IsStartElement())
                    {
                        switch (xmlReader.Name)
                        {
                            case "title":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Vulnerability_Group_Title", ObtainCurrentNodeValue(xmlReader)));
                                    break;
                                }
                            case "Rule":
                                {
                                    ProcessRuleNode(sqliteCommand, xmlReader);
                                    break;
                                }
                        }
                    }
                    else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("Group"))
                    {
                        SQLiteCommand clonedCommand = (SQLiteCommand)sqliteCommand.Clone();
                        clonedCommand.CommandText = Properties.Resources.VerifyVulnerabilityChange;
                        clonedCommand.Parameters.Add(new SQLiteParameter("Vulnerability_Source_ID", lastVulnerabilitySourceId));
                        bool updateRequired = false;
                        if (sqliteCommand.Parameters.Contains("Release"))
                        {
                            using (SQLiteDataReader sqliteDataReader = clonedCommand.ExecuteReader())
                            {
                                if (!sqliteDataReader.HasRows)
                                {
                                    lastVulnerabilityId = databaseInterface.InsertVulnerability(sqliteCommand, lastVulnerabilitySourceId);
                                    databaseInterface.MapVulnerabilityToCCI(sqliteCommand, ccis, lastVulnerabilityId);
                                    databaseInterface.MapVulnerabilityToSource(sqliteCommand, lastVulnerabilityId, lastVulnerabilitySourceId);
                                    return;
                                }
                                while (sqliteDataReader.Read())
                                {
                                    if (int.Parse(sqliteDataReader["Release"].ToString()) < int.Parse(sqliteCommand.Parameters["Release"].Value.ToString()))
                                    {
                                        lastVulnerabilityId = int.Parse(sqliteDataReader["Vulnerability_ID"].ToString());
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("Vulnerability_ID", lastVulnerabilityId));
                                        if (sqliteCommand.Parameters.Contains("Vulnerability_Source_ID"))
                                        { sqliteCommand.Parameters.Remove("Vulnerability_Source_ID"); }
                                        databaseInterface.UpdateVulnerability(sqliteCommand);
                                        databaseInterface.MapVulnerabilityToCCI(sqliteCommand, ccis, lastVulnerabilityId);
                                        updateRequired = true;
                                    }
                                    else
                                    { sqliteCommand.Parameters.Clear(); }
                                }
                            }
                        }
                        else
                        {
                            lastVulnerabilityId = databaseInterface.InsertVulnerability(sqliteCommand, lastVulnerabilitySourceId);
                            databaseInterface.MapVulnerabilityToCCI(sqliteCommand, ccis, lastVulnerabilityId);
                            databaseInterface.MapVulnerabilityToSource(sqliteCommand, lastVulnerabilityId, lastVulnerabilitySourceId);
                            updateRequired = true;
                        }
                        if (updateRequired)
                        {
                            sqliteCommand.CommandText = Properties.Resources.UpdateDeltaAnalysisFlag;
                            sqliteCommand.Parameters.Add(new SQLiteParameter("Vulnerability_ID", lastVulnerabilityId));
                            sqliteCommand.ExecuteNonQuery();
                            sqliteCommand.Parameters.Clear();
                        }
                        return;
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to process Group node.");
                throw exception;
            }
        }

        private void ProcessRuleNode(SQLiteCommand sqliteCommand, XmlReader xmlReader)
        {
            try
            {
                string rule = xmlReader.GetAttribute("id");
                string ruleRelease = string.Empty;
                if (rule.Contains("_"))
                { rule = rule.Split('_')[0]; }
                if (rule.Contains("r"))
                {
                    ruleRelease = rule.Split('r')[1];
                    rule = rule.Split('r')[0];
                }
                sqliteCommand.Parameters.Add(new SQLiteParameter("Unique_Vulnerability_Identifier", rule));
                sqliteCommand.Parameters.Add(new SQLiteParameter("Release", ruleRelease));
                sqliteCommand.Parameters.Add(new SQLiteParameter("Raw_Risk", ConvertSeverityToRawRisk(xmlReader.GetAttribute("severity"))));
                while (xmlReader.Read())
                {
                    if (xmlReader.IsStartElement())
                    {
                        switch (xmlReader.Name)
                        {
                            case "version":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Secondary_Vulnerability_Identifier", ObtainCurrentNodeValue(xmlReader)));
                                    break;
                                }
                            case "title":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Vulnerability_Title", ObtainCurrentNodeValue(xmlReader)));
                                    break;
                                }
                            case "description":
                                {
                                    ProcessRuleDescriptionNode(sqliteCommand, ObtainRuleDescriptionNodeValue(xmlReader));
                                    break;
                                }
                            case "dc:identifier":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Overflow", ObtainCurrentNodeValue(xmlReader)));
                                    break;
                                }
                            case "ident":
                                {
                                    if (xmlReader.GetAttribute("system").Equals("http://iase.disa.mil/cci"))
                                    { ccis.Add(ObtainCurrentNodeValue(xmlReader).Replace("CCI-", string.Empty)); }
                                    break;
                                }
                            case "fixtext":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Fix_Text", ObtainCurrentNodeValue(xmlReader)));
                                    break;
                                }
                            case "check-content":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Check_Content", ObtainCurrentNodeValue(xmlReader)));
                                    break;
                                }
                            default:
                                { break; }
                        }
                    }
                    else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("Rule"))
                    { return; }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to process Rule description node.");
                throw exception;
            }
        }

        private void ProcessRuleDescriptionNode(SQLiteCommand sqliteCommand, string descriptionNodeValue)
        {
            try
            {
                string rootNode = @"<root></root>";
                descriptionNodeValue = rootNode.Insert(6, descriptionNodeValue);
                using (XmlReader xmlReader = XmlReader.Create(GenerateStreamFromString(descriptionNodeValue)))
                {
                    while (xmlReader.Read())
                    {
                        if (xmlReader.IsStartElement())
                        {
                            switch (xmlReader.Name)
                            {
                                case "VulnDiscussion":
                                    {
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("Description", ObtainCurrentNodeValue(xmlReader)));
                                        break;
                                    }
                                case "FalsePositives":
                                    {
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("False_Positives", ObtainCurrentNodeValue(xmlReader)));
                                        break;
                                    }
                                case "FalseNegatives":
                                    {
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("False_Negatives", ObtainCurrentNodeValue(xmlReader)));
                                        break;
                                    }
                                case "Documentable":
                                    {
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("Documentable", ObtainCurrentNodeValue(xmlReader)));
                                        break;
                                    }
                                case "Mitigations":
                                    {
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("Mitigations", ObtainCurrentNodeValue(xmlReader)));
                                        break;
                                    }
                                case "SeverityOverrideGuidance":
                                    {
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("Severity_Override_Guidance", ObtainCurrentNodeValue(xmlReader)));
                                        break;
                                    }
                                case "PotentialImpacts":
                                    {
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("Potential_Impacts", ObtainCurrentNodeValue(xmlReader)));
                                        break;
                                    }
                                case "ThirdPartyTools":
                                    {
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("Third_Party_Tools", ObtainCurrentNodeValue(xmlReader)));
                                        break;
                                    }
                                case "MitigationControl":
                                    {
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("Mitigation_Control", ObtainCurrentNodeValue(xmlReader)));
                                        break;
                                    }
                                case "Responsibility":
                                    {
                                        responsibilities.Add(ObtainCurrentNodeValue(xmlReader));
                                        break;
                                    }
                                case "IAControls":
                                    {
                                        iaControls.Add(ObtainCurrentNodeValue(xmlReader));
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
                log.Error("Unable to process Rule description node.");
                throw exception;
            }
        }

        private void MapVulnerbailityToIAControl(SQLiteCommand sqliteCommand)
        {
            try
            {

            }
            catch (Exception exception)
            {
                log.Error("Unable to vulnerability to IA Control.");
                log.Debug("Exception details: " + exception);
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
                xmlReaderSettings.ValidationFlags = System.Xml.Schema.XmlSchemaValidationFlags.AllowXmlAttributes;
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
                string value = xmlReader.Value;
                return value;
            }
            catch (Exception exception)
            {
                log.Error("Unable to obtain currently accessed node value.");
                throw exception;
            }
        }

        private string ObtainRuleDescriptionNodeValue(XmlReader xmlReader)
        {
            try
            {
                xmlReader.Read();
                string value = xmlReader.Value;
                value = value.Replace("&", "&amp;");
                value = value.Replace("<", "&lt;");
                value = value.Replace(">", "&gt;");
                foreach (string key in replaceDictionary.Keys)
                { value.Replace(key, replaceDictionary[key]); }
                return value;
            }
            catch (Exception exception)
            {
                log.Error("Unable to obtain currently accessed node value.");
                throw exception;
            }
        }

        private string ConvertSeverityToRawRisk(string severity)
        {
            try
            {
                switch (severity)
                {
                    case "high":
                        { return "I"; }
                    case "medium":
                        { return "II"; }
                    case "low":
                        { return "III"; }
                    case "unknown":
                        { return "unknown"; }
                    default:
                        { return "unknown"; }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to convert impact to raw risk.");
                throw exception;
            }
        }

        private string SanitizeSourceName(string sourceName)
        {
            try
            {
                bool isSRG = sourceName.Contains("SRG") || sourceName.Contains("Security Requirement") ? true : false;
                string value = sourceName;
                string[] replaceArray = new string[] { "STIG", "Security", "Technical", "Implementation", "Guide", "(", ")", "Requirements", "SRG", "  " };
                foreach (string item in replaceArray)
                {
                    if (item.Equals("  "))
                    { value = value.Replace(item, " "); }
                    else
                    { value = value.Replace(item, ""); }
                }
                value = value.Trim();
                if (!isSRG)
                {
                    value = string.Format("{0} Security Technical Implementation Guide", value);
                    return value;
                }
                value = string.Format("{0} Security Requirements Guide", value);
                return value;
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to sanitize source name \"{0}\".", sourceName));
                log.Debug("Exception details:", exception);
                return sourceName;
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

        private static Dictionary<string,string> PopulateReplaceDictionary()
        {
            Dictionary<string, string> dictionary = new Dictionary<string, string>();
            dictionary.Add("&lt;VulnDiscussion&gt;", "<VulnDiscussion>");
            dictionary.Add("&lt;/VulnDiscussion&gt;", "</VulnDiscussion>");
            dictionary.Add("&lt;FalsePositives&gt;", "<FalsePositives>");
            dictionary.Add("&lt;/FalsePositives&gt;", "</FalsePositives>");
            dictionary.Add("&lt;FalseNegatives&gt;", "<FalseNegatives>");
            dictionary.Add("&lt;/FalseNegatives&gt;", "</FalseNegatives>");
            dictionary.Add("&lt;Documentable&gt;", "<Documentable>");
            dictionary.Add("&lt;/Documentable&gt;", "</Documentable>");
            dictionary.Add("&lt;Mitigations&gt;", "<Mitigations>");
            dictionary.Add("&lt;/Mitigations&gt;", "</Mitigations>");
            dictionary.Add("&lt;SeverityOverrideGuidance&gt;", "<SeverityOverrideGuidance>");
            dictionary.Add("&lt;/SeverityOverrideGuidance&gt;", "</SeverityOverrideGuidance>");
            dictionary.Add("&lt;PotentialImpacts&gt;", "<PotentialImpacts>");
            dictionary.Add("&lt;/PotentialImpacts&gt;", "</PotentialImpacts>");
            dictionary.Add("&lt;ThirdPartyTools&gt;", "<ThirdPartyTools>");
            dictionary.Add("&lt;/ThirdPartyTools&gt;", "</ThirdPartyTools>");
            dictionary.Add("&lt;MitigationControl&gt;", "<MitigationControl>");
            dictionary.Add("&lt;/MitigationControl&gt;", "</MitigationControl>");
            dictionary.Add("&lt;Responsibility&gt;", "<Responsibility>");
            dictionary.Add("&lt;/Responsibility&gt;", "</Responsibility>");
            dictionary.Add("&lt;IAControls&gt;", "<IAControls>");
            dictionary.Add("&lt;/IAControls&gt;", "</IAControls>");
            return dictionary;
        }
    }
}
