using log4net;
using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SQLite;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text.RegularExpressions;
using System.Xml;
using Vulnerator.Helper;
using Vulnerator.Model.DataAccess;
using Vulnerator.Model.Object;

namespace Vulnerator.Model.BusinessLogic
{
    public class RawStigReader
    {
        readonly DatabaseInterface databaseInterface = new DatabaseInterface();
        private bool sourceUpdated = true;
        private List<string> iaControls = new List<string>();
        private readonly List<string> ccis = new List<string>();
        private List<string> responsibilities = new List<string>();
        private readonly Dictionary<string, string> replaceDictionary = PopulateReplaceDictionary();
        private readonly string[] persistentParameters = new string[] {
            "VulnerabilitySourceFileName", "SourceDescription", "SourceSecondaryIdentifier",
            "SourceName", "SourceVersion", "SourceRelease", "DiscoveredHostName", "ScanIP", "FindingType",
            "PublishedDate"
        };

        public string ReadRawStig(ZipArchiveEntry rawStig)
        {
            try
            {
                LogWriter.LogStatusUpdate($"Begin ingestion of raw STIG file '{rawStig.Name}'.");
                if (DatabaseBuilder.sqliteConnection.State.ToString().Equals("Closed"))
                { DatabaseBuilder.sqliteConnection.Open(); }
                using (SQLiteTransaction sqliteTransaction = DatabaseBuilder.sqliteConnection.BeginTransaction())
                {
                    using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                    {
                        databaseInterface.InsertParameterPlaceholders(sqliteCommand);
                        sqliteCommand.Parameters["FindingType"].Value = "CKL";
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
                                                sqliteCommand.Parameters.Add(new SQLiteParameter("VulnerabilitySourceFileName", rawStig.Name));
                                                ReadBenchmarkNode(sqliteCommand, xmlReader);
                                                break;
                                            }
                                        case "Group":
                                            {
                                                ReadGroupNode(sqliteCommand, xmlReader);
                                                if (!sourceUpdated)
                                                { return "Parsed"; }
                                                break;
                                            }
                                        default:
                                            { break; }
                                    }
                                }
                            }
                        }
                        databaseInterface.DeleteRemovedVulnerabilities(sqliteCommand);
                    }
                    sqliteTransaction.Commit();
                    return "Parsed";
                }
            }
            catch (Exception exception)
            {
                string error = $"Unable to process STIG file '{rawStig.Name}'.";
                LogWriter.LogErrorWithDebug(error, exception);
                return "Failed";
            }
            finally
            { DatabaseBuilder.sqliteConnection.Close(); }
        }

        private void ReadBenchmarkNode(SQLiteCommand sqliteCommand, XmlReader xmlReader)
        {
            try
            {
                sqliteCommand.Parameters["SourceSecondaryIdentifier"].Value = xmlReader.GetAttribute("id");
                while (xmlReader.Read())
                {
                    if (!xmlReader.IsStartElement()) continue;
                    switch (xmlReader.Name)
                    {
                        case "title":
                            {
                                string sourceName = xmlReader.ObtainCurrentNodeValue(false).Replace('_', ' ');
                                sourceName = sourceName.ToSanitizedSource();
                                sqliteCommand.Parameters.Add(new SQLiteParameter("SourceName", sourceName));
                                break;
                            }
                        case "description":
                            {
                                sqliteCommand.Parameters.Add(new SQLiteParameter("SourceDescription", xmlReader.ObtainCurrentNodeValue(false)));
                                break;
                            }
                        case "plain-text":
                            {
                                string release = xmlReader.ObtainCurrentNodeValue(false);
                                if (release.Contains(" "))
                                {
                                    Regex regex = new Regex(Properties.Resources.RegexRawStigRelease);
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("SourceRelease", regex.Match(release)));
                                    regex = new Regex(Properties.Resources.RegexStigDate);
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("PublishedDate", DateTime
                                        .ParseExact(regex.Match(release).ToString(), "dd MMM yyyy", CultureInfo.InvariantCulture)
                                        .ToShortDateString()));
                                }
                                else
                                { sqliteCommand.Parameters.Add(new SQLiteParameter("SourceRelease", release)); }
                                break;
                            }
                        case "version":
                            {
                                sqliteCommand.Parameters.Add(new SQLiteParameter("SourceVersion", xmlReader.ObtainCurrentNodeValue(false)));
                                break;
                            }
                        case "Profile":
                            {
                                databaseInterface.UpdateVulnerabilitySource(sqliteCommand);
                                databaseInterface.InsertVulnerabilitySource(sqliteCommand);
                                return;
                            }
                        default:
                            { break; }
                    }
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to process 'Benchmark' node.");
                throw exception;
            }
        }

        private void ReadGroupNode(SQLiteCommand sqliteCommand, XmlReader xmlReader)
        {
            try
            {
                sqliteCommand.Parameters["VulnerabilityGroup_ID"].Value = xmlReader.GetAttribute("id");
                while (xmlReader.Read())
                {
                    if (xmlReader.IsStartElement())
                    {
                        switch (xmlReader.Name)
                        {
                            case "title":
                                {
                                    sqliteCommand.Parameters["VulnerabilityGroup_Title"].Value = xmlReader.ObtainCurrentNodeValue(false);
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
                        switch (databaseInterface.CompareVulnerabilityVersions(sqliteCommand))
                        {
                            case "Record Not Found":
                                {
                                    databaseInterface.InsertVulnerability(sqliteCommand);
                                    databaseInterface.MapVulnerabilityToSource(sqliteCommand);
                                    break;
                                }
                            case "Ingested Version Is Newer":
                                {
                                    databaseInterface.UpdateVulnerability(sqliteCommand);
                                    databaseInterface.UpdateDeltaAnalysisFlags(sqliteCommand);
                                    break;
                                }
                            case "Existing Version Is Newer":
                                {
                                    databaseInterface.UpdateVulnerabilityDates(sqliteCommand);
                                    sqliteCommand.Parameters["DeltaAnalysisIsRequired"].Value = "True";
                                    break;
                                }
                            case "Identical Versions":
                                {
                                    databaseInterface.UpdateVulnerabilityDates(sqliteCommand);
                                    break;
                                }
                            default:
                                { break; }
                        }
                        if (ccis.Count > 0)
                        {
                            foreach (string cci in ccis)
                            {
                                sqliteCommand.Parameters["CCI"].Value = cci;
                                databaseInterface.MapVulnerabilityToCci(sqliteCommand);
                                sqliteCommand.Parameters["CCI"].Value = string.Empty;
                            }
                        }
                        ccis.Clear();
                        foreach (SQLiteParameter parameter in sqliteCommand.Parameters)
                        {
                            if (!persistentParameters.Contains(parameter.ParameterName))
                            { parameter.Value = string.Empty; }
                        }
                        return;
                    }
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to process 'Group' node.");
                throw exception;
            }
        }

        private void ProcessRuleNode(SQLiteCommand sqliteCommand, XmlReader xmlReader)
        {
            try
            {
                string rule = xmlReader.GetAttribute("id");
                string ruleVersion = string.Empty;
                if (rule.Contains("_"))
                { rule = rule.Split('_')[0]; }
                if (rule.Contains("r"))
                {
                    ruleVersion = rule.Split('r')[1];
                    rule = rule.Split('r')[0];
                }
                sqliteCommand.Parameters["ModifiedDate"].Value = DateTime.Now.ToShortDateString();
                sqliteCommand.Parameters["UniqueVulnerabilityIdentifier"].Value = rule;
                sqliteCommand.Parameters["VulnerabilityVersion"].Value = ruleVersion;
                sqliteCommand.Parameters["RawRisk"].Value = xmlReader.GetAttribute("severity").ToRawRisk();
                while (xmlReader.Read())
                {
                    if (xmlReader.IsStartElement())
                    {
                        switch (xmlReader.Name)
                        {
                            case "version":
                                {
                                    sqliteCommand.Parameters["SecondaryVulnerabilityIdentifier"].Value = xmlReader.ObtainCurrentNodeValue(false);
                                    break;
                                }
                            case "title":
                                {
                                    sqliteCommand.Parameters["VulnerabilityTitle"].Value = xmlReader.ObtainCurrentNodeValue(false);
                                    break;
                                }
                            case "description":
                                {
                                    ProcessRuleDescriptionNode(sqliteCommand, ObtainRuleDescriptionNodeValue(xmlReader));
                                    break;
                                }
                            case "dc:identifier":
                                {
                                    sqliteCommand.Parameters["Overflow"].Value = xmlReader.ObtainCurrentNodeValue(false);
                                    break;
                                }
                            case "ident":
                                {
                                    if (xmlReader.GetAttribute("system").Equals("http://iase.disa.mil/cci"))
                                    { ccis.Add(xmlReader.ObtainCurrentNodeValue(false).Replace("CCI-", string.Empty)); }
                                    break;
                                }
                            case "fixtext":
                                {
                                    sqliteCommand.Parameters["FixText"].Value = xmlReader.ObtainCurrentNodeValue(false);
                                    break;
                                }
                            case "check-content":
                                {
                                    sqliteCommand.Parameters["CheckContent"].Value = xmlReader.ObtainCurrentNodeValue(false);
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
                LogWriter.LogError("Unable to process 'Rule' node.");
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
                                        sqliteCommand.Parameters["VulnerabilityDescription"].Value = xmlReader.ObtainCurrentNodeValue(false);
                                        break;
                                    }
                                case "FalsePositives":
                                    {
                                        sqliteCommand.Parameters["FalsePositives"].Value = xmlReader.ObtainCurrentNodeValue(false);
                                        break;
                                    }
                                case "FalseNegatives":
                                    {
                                        sqliteCommand.Parameters["FalseNegatives"].Value = xmlReader.ObtainCurrentNodeValue(false);
                                        break;
                                    }
                                case "Documentable":
                                    {
                                        sqliteCommand.Parameters["Documentable"].Value = xmlReader.ObtainCurrentNodeValue(false);
                                        break;
                                    }
                                case "Mitigations":
                                    {
                                        sqliteCommand.Parameters["Mitigations"].Value = xmlReader.ObtainCurrentNodeValue(false);
                                        break;
                                    }
                                case "SeverityOverrideGuidance":
                                    {
                                        sqliteCommand.Parameters["Severity_Override_Guidance"].Value = xmlReader.ObtainCurrentNodeValue(false);
                                        break;
                                    }
                                case "PotentialImpacts":
                                    {
                                        sqliteCommand.Parameters["PotentialImpacts"].Value = xmlReader.ObtainCurrentNodeValue(false);
                                        break;
                                    }
                                case "ThirdPartyTools":
                                    {
                                        sqliteCommand.Parameters["ThirdPartyTools"].Value = xmlReader.ObtainCurrentNodeValue(false);
                                        break;
                                    }
                                case "MitigationControl":
                                    {
                                        sqliteCommand.Parameters["MitigationControl"].Value = xmlReader.ObtainCurrentNodeValue(false);
                                        break;
                                    }
                                case "Responsibility":
                                    {
                                        responsibilities.Add(xmlReader.ObtainCurrentNodeValue(false));
                                        break;
                                    }
                                case "IAControls":
                                    {
                                        iaControls.Add(xmlReader.ObtainCurrentNodeValue(false));
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
                LogWriter.LogError("Unable to process Rule 'description' node.");
                throw exception;
            }
        }

        private XmlReaderSettings GenerateXmlReaderSettings()
        {
            try
            {
                XmlReaderSettings xmlReaderSettings = new XmlReaderSettings
                {
                    IgnoreWhitespace = true,
                    IgnoreComments = true,
                    ValidationType = ValidationType.Schema,
                    ValidationFlags = System.Xml.Schema.XmlSchemaValidationFlags.ProcessInlineSchema
                };
                xmlReaderSettings.ValidationFlags = System.Xml.Schema.XmlSchemaValidationFlags.ProcessSchemaLocation;
                xmlReaderSettings.ValidationFlags = System.Xml.Schema.XmlSchemaValidationFlags.AllowXmlAttributes;
                return xmlReaderSettings;
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to generate XmlReaderSettings.");
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
                { value = value.Replace(key, replaceDictionary[key]); }
                return value;
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to obtain currently accessed node value.");
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

        private static Dictionary<string, string> PopulateReplaceDictionary()
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