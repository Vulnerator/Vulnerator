using log4net;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data.SQLite;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text.RegularExpressions;
using System.Xml;
using Vulnerator.Model.DataAccess;
using Vulnerator.Model.Object;
using Vulnerator.ViewModel.ViewModelHelper;

namespace Vulnerator.Model.BusinessLogic
{
    public class RawStigReader
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(Logger));
        private int lastVulnerabilitySourceId = 0;
        private int lastVulnerabilityId = 0;
        private List<string> iaControls = new List<string>();
        private List<string> ccis = new List<string>();
        private List<string> responsibilities = new List<string>();
        private Dictionary<string, string> replaceDictionary = PopulateReplaceDictionary();

        public void ReadRawStig(ZipArchiveEntry rawStig)
        {
            try
            {
                log.Info(string.Format("Begin ingestion of raw STIG file {0}", rawStig.FullName));
                if (rawStig.Name.Contains("U_BlackBerry_Device_Service_v6.2_V1R1_manual-xccdf.xml"))
                { Console.WriteLine("Last isue!"); }
                if (DatabaseBuilder.sqliteConnection.State.ToString().Equals("Closed"))
                { DatabaseBuilder.sqliteConnection.Open(); }
                using (SQLiteTransaction sqliteTransaction = DatabaseBuilder.sqliteConnection.BeginTransaction())
                {
                    using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                    {
                        using (XmlReader xmlReader = XmlReader.Create(rawStig.Open(), GenerateXmlReaderSettings()))
                        {
                            while (xmlReader.Read())
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
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Source_Name", ObtainCurrentNodeValue(xmlReader)));
                                    break;
                                }
                            case "description":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Source_Description", ObtainCurrentNodeValue(xmlReader)));
                                    break;
                                }
                            case "plain-text":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Source_Release", ObtainCurrentNodeValue(xmlReader)));
                                    break;
                                }
                            case "version":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Source_Version", ObtainCurrentNodeValue(xmlReader)));
                                    break;
                                }
                            case "Profile":
                                {
                                    InsertVulnerabilitySource(sqliteCommand);
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
                sqliteCommand.Parameters.Add(new SQLiteParameter("Vulnerability_Source_ID", lastVulnerabilitySourceId));
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
                        SQLiteCommand clonedSqliteCommand = (SQLiteCommand)sqliteCommand.Clone();
                        clonedSqliteCommand.CommandText = Properties.Resources.VerifyVulnerabilityChange;
                        bool updateRequired = false;
                        using (SQLiteDataReader sqliteDataReader = clonedSqliteCommand.ExecuteReader())
                        {
                            if (sqliteDataReader.HasRows)
                            {
                                while (sqliteDataReader.Read())
                                {
                                    Console.WriteLine(sqliteDataReader["Release"].ToString());
                                    if (sqliteDataReader["Release"].ToString() != sqliteCommand.Parameters["Release"].Value.ToString())
                                    {
                                        InsertVulnerability(sqliteCommand);
                                        MapVulnerbailityToCCI(sqliteCommand);
                                        updateRequired = true;
                                    }
                                    else
                                    { sqliteCommand.Parameters.Clear(); }
                                }
                            }
                            else
                            {
                                InsertVulnerability(sqliteCommand);
                                MapVulnerbailityToCCI(sqliteCommand);
                            }
                            
                        }
                        if (updateRequired)
                        {
                            sqliteCommand.CommandText = Properties.Resources.UpdateDeltaAnalysisFlag;
                            sqliteCommand.Parameters.Add(new SQLiteParameter("Vulnerabililty_ID", lastVulnerabilityId));
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

        private void InsertVulnerabilitySource(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = Properties.Resources.InsertVulnerabilitySource;
                foreach (SQLiteParameter parameter in sqliteCommand.Parameters)
                {
                    if (sqliteCommand.Parameters.IndexOf(parameter) == 0)
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(55, "@" + parameter.ParameterName); }
                    else
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(55, "@" + parameter.ParameterName + ", "); }

                }
                foreach (SQLiteParameter parameter in sqliteCommand.Parameters)
                {
                    if (sqliteCommand.Parameters.IndexOf(parameter) == 0)
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(45, parameter.ParameterName); }
                    else
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(45, parameter.ParameterName + ", "); }
                }
                sqliteCommand.ExecuteNonQuery();
                sqliteCommand.Parameters.Clear();
                sqliteCommand.CommandText = "SELECT last_insert_rowid();";
                lastVulnerabilitySourceId = int.Parse(sqliteCommand.ExecuteScalar().ToString());
            }
            catch (Exception exception)
            {
                log.Error("Unable to insert vulnerability source.");
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

        private void InsertVulnerability(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = Properties.Resources.InsertVulnerability;
                foreach (SQLiteParameter parameter in sqliteCommand.Parameters)
                {
                    if (sqliteCommand.Parameters.IndexOf(parameter) == 0)
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(50, "@" + parameter.ParameterName); }
                    else
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(50, "@" + parameter.ParameterName + ", "); }

                }
                foreach (SQLiteParameter parameter in sqliteCommand.Parameters)
                {
                    if (sqliteCommand.Parameters.IndexOf(parameter) == 0)
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(40, parameter.ParameterName); }
                    else
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(40, parameter.ParameterName + ", "); }
                }
                sqliteCommand.ExecuteNonQuery();
                sqliteCommand.CommandText = "SELECT last_insert_rowid();";
                lastVulnerabilityId = int.Parse(sqliteCommand.ExecuteScalar().ToString());
                sqliteCommand.Parameters.Clear();
            }
            catch (Exception exception)
            {
                log.Error("Unable to insert vulnerability.");
                throw exception;
            }
        }

        private void MapVulnerbailityToCCI(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = Properties.Resources.MapVulnerabilityToCci;
                foreach (string cci in ccis)
                {
                    sqliteCommand.Parameters.Add(new SQLiteParameter("Vulnerability_ID", lastVulnerabilityId));
                    sqliteCommand.Parameters.Add(new SQLiteParameter("CCI", cci));
                    sqliteCommand.ExecuteNonQuery();
                    sqliteCommand.Parameters.Clear();
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to map vulnerability to CCI.");
                log.Debug("Exception details: " + exception);
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
