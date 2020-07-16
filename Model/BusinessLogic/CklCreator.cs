using log4net;
using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using Vulnerator.Helper;
using Vulnerator.Model.DataAccess;
using Vulnerator.Model.Entity;
using Vulnerator.Model.Object;

namespace Vulnerator.Model.BusinessLogic
{
    public class CklCreator
    {
        private DdlReader _ddlReader = new DdlReader();
        private Assembly assembly = Assembly.GetExecutingAssembly();
        private string _storedProcedureBase = "Vulnerator.Resources.DdlFiles.StoredProcedures.";
        public void CreateCklFromHardware(Hardware hardware, VulnerabilitySource vulnerabilitySource, string saveDirectory)
        {
            try
            {
                if (!DatabaseBuilder.sqliteConnection.State.ToString().Equals("Open"))
                { DatabaseBuilder.sqliteConnection.Open(); }
                using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                {
                    sqliteCommand.Parameters.Add(new SQLiteParameter("Hardware_ID", hardware.Hardware_ID));
                    sqliteCommand.Parameters.Add(new SQLiteParameter("VulnerabilitySource_ID", vulnerabilitySource.VulnerabilitySource_ID));
                    sqliteCommand.CommandText = sqliteCommand.CommandText = _ddlReader.ReadDdl(_storedProcedureBase + "Select.HardwareCklCreationData.dml", assembly);;
                    using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
                    {
                        string stigName = vulnerabilitySource.SourceName
                                    .Replace(" ", string.Empty)
                                    .Replace("Security Technical Implentation Guide", "_STIG");
                        string saveFile =
                            $"{saveDirectory}\\U_{stigName}_v{vulnerabilitySource.SourceVersion}_r{vulnerabilitySource.SourceRelease}_{hardware.DisplayedHostName}.ckl";
                        using (XmlWriter xmlWriter = XmlWriter.Create(saveFile, GenerateXmlWriterSettings()))
                        {
                            xmlWriter.WriteStartDocument(true);
                            xmlWriter.WriteStartElement("CHECKLIST");
                            int i = 0;
                            while (sqliteDataReader.Read())
                            {
                                if (i == 0)
                                {
                                    WriteAssetInformation(sqliteDataReader, xmlWriter, "Computing");
                                    WriteStigInformation(sqliteDataReader, xmlWriter);
                                    i++;
                                }
                                WriteVulnerabilityInformation(sqliteDataReader, xmlWriter);
                            }
                            xmlWriter.WriteEndElement();
                            xmlWriter.WriteEndElement();
                            xmlWriter.WriteEndElement();
                        }
                    }
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError(
                    $"Unable to generate a CKL for '{hardware.DisplayedHostName}' - '{vulnerabilitySource.SourceName}'.");
                throw exception;
            }
            finally
            { DatabaseBuilder.sqliteConnection.Close(); }
        }

        private void WriteAssetInformation(SQLiteDataReader sqliteDataReader, XmlWriter xmlWriter, string assetType)
        {
            try
            {
                xmlWriter.WriteStartElement("ASSET");
                xmlWriter.WriteElementString("ROLE", sqliteDataReader["Role"].ToString());
                xmlWriter.WriteElementString("ASSET_TYPE", assetType);
                xmlWriter.WriteElementString("HOST_NAME", sqliteDataReader["DisplayedHostName"].ToString());
                xmlWriter.WriteElementString("HOST_IP", sqliteDataReader["IpAddresses"].ToString());
                xmlWriter.WriteElementString("HOST_MAC", sqliteDataReader["MacAddresses"].ToString());
                xmlWriter.WriteElementString("HOST_GUID", string.Empty);
                xmlWriter.WriteElementString("HOST_FQDN", sqliteDataReader["FQDN"].ToString());
                xmlWriter.WriteElementString("TECH_AREA", sqliteDataReader["TechnologyArea"].ToString());
                xmlWriter.WriteElementString("TARGET_KEY", string.Empty);
                xmlWriter.WriteElementString("ROLE", sqliteDataReader["Role"].ToString());
                if (string.IsNullOrWhiteSpace(sqliteDataReader["WebDB_Site"].ToString()) || string.IsNullOrWhiteSpace(sqliteDataReader["WebDB_Instance"].ToString()))
                { xmlWriter.WriteElementString("WEB_OR_DATABASE", "false"); }
                else
                { xmlWriter.WriteElementString("WEB_OR_DATABASE", "true"); }
                xmlWriter.WriteElementString("WEB_DB_SITE", sqliteDataReader["WebDB_Site"].ToString());
                xmlWriter.WriteElementString("WEB_DB_INSTANCE", sqliteDataReader["WebDB_Instance"].ToString());
                xmlWriter.WriteEndElement();
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to write CKL asset information.");
                throw exception;
            }
        }

        private void WriteStigInformation(SQLiteDataReader sqliteDataReader, XmlWriter xmlWriter)
        {
            try
            {
                xmlWriter.WriteStartElement("STIGS");
                xmlWriter.WriteStartElement("iSTIG");
                xmlWriter.WriteStartElement("STIG_INFO");
                WriteSiDataNode(xmlWriter, "version", sqliteDataReader["SourceVersion"].ToString());
                WriteSiDataNode(xmlWriter, "classification", sqliteDataReader["Classification"].ToString());
                WriteSiDataNode(xmlWriter, "customname", string.Empty);
                WriteSiDataNode(xmlWriter, "stigid", sqliteDataReader["SourceSecondaryIdentifier"].ToString());
                WriteSiDataNode(xmlWriter, "description", sqliteDataReader["SourceDescription"].ToString());
                WriteSiDataNode(xmlWriter, "filename", sqliteDataReader["VulnerabilitySourceFileName"].ToString());
                WriteSiDataNode(xmlWriter, "releaseinfo", sqliteDataReader["SourceRelease"].ToString());
                WriteSiDataNode(xmlWriter, "title", sqliteDataReader["SourceName"].ToString());
                xmlWriter.WriteEndElement();
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to write CKL STIG information.");
                throw exception;
            }
        }

        private void WriteSiDataNode(XmlWriter xmlWriter, string sidName, string sidData)
        {
            try
            {
                xmlWriter.WriteStartElement("SI_DATA");
                xmlWriter.WriteElementString("SID_NAME", sidName);
                xmlWriter.WriteElementString("SID_DATA", sidData);
                xmlWriter.WriteEndElement();
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to generate 'SI_DATA' node.");
                throw exception;
            }
        }

        private void WriteVulnerabilityInformation(SQLiteDataReader sqliteDataReader, XmlWriter xmlWriter)
        {
            try
            {
                xmlWriter.WriteStartElement("VULN");
                WriteStigDataNode(xmlWriter, "Vuln_Num", sqliteDataReader["VulnerabilityGroup_ID"].ToString());
                WriteStigDataNode(xmlWriter, "Severity", sqliteDataReader["PrimaryRawRiskIndicator"].ToString().ToSeverity());
                WriteStigDataNode(xmlWriter, "Group_Title", sqliteDataReader["VulnerabilityGroup_Title"].ToString());
                string ruleId =
                    $"{sqliteDataReader["UniqueVulnerabilityIdentifier"]}r{sqliteDataReader["VulnerabilityVersion"]}_rule";
                WriteStigDataNode(xmlWriter, "Rule_ID", ruleId);
                WriteStigDataNode(xmlWriter, "Rule_Ver", sqliteDataReader["SecondaryVulnerabilityIdentifier"].ToString());
                WriteStigDataNode(xmlWriter, "Rule_Title", sqliteDataReader["VulnerabilityTitle"].ToString());
                WriteStigDataNode(xmlWriter, "Vuln_Discuss", sqliteDataReader["VulnerabilityDescription"].ToString());
                WriteStigDataNode(xmlWriter, "IA_Controls", string.Empty);
                WriteStigDataNode(xmlWriter, "CheckContent", sqliteDataReader["CheckContent"].ToString());
                WriteStigDataNode(xmlWriter, "FixText", sqliteDataReader["FixText"].ToString());
                WriteStigDataNode(xmlWriter, "FalsePositives", sqliteDataReader["FalsePositives"].ToString());
                WriteStigDataNode(xmlWriter, "FalseNegatives", sqliteDataReader["FalseNegatives"].ToString());
                WriteStigDataNode(xmlWriter, "Documentable", sqliteDataReader["Documentable"].ToString());
                WriteStigDataNode(xmlWriter, "Mitigations", sqliteDataReader["Mitigations"].ToString());
                WriteStigDataNode(xmlWriter, "Potential_Impact", sqliteDataReader["PotentialImpacts"].ToString());
                WriteStigDataNode(xmlWriter, "ThirdPartyTools", sqliteDataReader["ThirdPartyTools"].ToString());
                WriteStigDataNode(xmlWriter, "MitigationControl", sqliteDataReader["MitigationControl"].ToString());
                WriteStigDataNode(xmlWriter, "Responsibility", string.Empty);
                WriteStigDataNode(xmlWriter, "Severity_Override_Guidance", sqliteDataReader["SecurityOverrideGuidance"].ToString());
                WriteStigDataNode(xmlWriter, "Check_Content_Ref", string.Empty);
                WriteStigDataNode(xmlWriter, "Weight", "10.0");
                WriteStigDataNode(xmlWriter, "Class", sqliteDataReader["Classification"].ToString());
                string stigRef =
                    $"{sqliteDataReader["SourceName"].ToString()} v{sqliteDataReader["SourceVersion"].ToString()} r{sqliteDataReader["SourceRelease"].ToString()}";
                WriteStigDataNode(xmlWriter, "STIGRef", stigRef);
                WriteStigDataNode(xmlWriter, "TargetKey", string.Empty);
                foreach (string cci in sqliteDataReader["CCIs"].ToString().Split(',').ToArray())
                { WriteStigDataNode(xmlWriter, "CCI_REF", string.Concat("CCI-", cci)); }
                xmlWriter.WriteElementString("STATUS", sqliteDataReader["Status"].ToString().ToCklStatus());
                string toolGenerated;
                if (string.IsNullOrWhiteSpace(sqliteDataReader["ToolGeneratedOutput"].ToString()))
                { toolGenerated = string.Empty; }
                else
                {
                    toolGenerated =
                        $"Tool Generated Output:{Environment.NewLine}{sqliteDataReader["ToolGeneratedOutput"].ToString()}{Environment.NewLine + Environment.NewLine}";
                }
                string findingDetails;
                if (string.IsNullOrWhiteSpace(sqliteDataReader["FindingDetails"].ToString()))
                { findingDetails = string.Empty; }
                else
                {
                    findingDetails =
                        $"Manual Finding Details:{Environment.NewLine}{sqliteDataReader["FindingDetails"].ToString()}";
                }
                xmlWriter.WriteElementString("FINDING_DETAILS", toolGenerated + findingDetails);
                xmlWriter.WriteElementString("COMMENTS", sqliteDataReader["Comments"].ToString());
                xmlWriter.WriteElementString("SEVERITY_OVERRIDE", sqliteDataReader["SeverityOverride"].ToString());
                xmlWriter.WriteElementString("SEVERITY_JUSTIFICATION", sqliteDataReader["SeverityOverrideJustification"].ToString());
                xmlWriter.WriteEndElement();
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to write CKL 'vulnerability' node.");
                throw exception;
            }
        }

        private void WriteStigDataNode(XmlWriter xmlWriter, string vulnAttribute, string attributeData)
        {
            try
            {
                xmlWriter.WriteStartElement("STIG_DATA");
                xmlWriter.WriteElementString("VULN_ATTRIBUTE", vulnAttribute);
                xmlWriter.WriteElementString("ATTRIBUTE_DATA", attributeData);
                xmlWriter.WriteEndElement();
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to generate 'STIG_DATA' node.");
                throw exception;
            }
        }

        private XmlWriterSettings GenerateXmlWriterSettings()
        {
            try
            {
                XmlWriterSettings xmlWriterSettings = new XmlWriterSettings()
                {
                    Encoding = Encoding.UTF8,
                    Indent = true,
                    NewLineOnAttributes = true,
                    IndentChars = "\t",
                    NewLineChars = Environment.NewLine,
                    NewLineHandling = NewLineHandling.Replace
                };

                return xmlWriterSettings;
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to generate XmlWriterSettings.");
                throw exception;
            }
        }
    }
}
