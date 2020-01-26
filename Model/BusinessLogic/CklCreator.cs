using log4net;
using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.Linq;
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
        public void CreateCklFromHardware(Hardware hardware, VulnerabilitySource vulnerabilitySource, string saveDirectory)
        { 
            try
            {
                if (!DatabaseBuilder.sqliteConnection.State.ToString().Equals("Open"))
                { DatabaseBuilder.sqliteConnection.Open(); }
                using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                {
                    sqliteCommand.Parameters.Add(new SQLiteParameter("Hardware_ID", hardware.Hardware_ID));
                    sqliteCommand.Parameters.Add(new SQLiteParameter("Vulnerability_Source_ID", vulnerabilitySource.Vulnerability_Source_ID));
                    sqliteCommand.CommandText = Properties.Resources.SelectHardwareCklCreationData;
                    using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
                    {
                        string stigName = vulnerabilitySource.Source_Name
                                    .Replace(" ", string.Empty)
                                    .Replace("Security Technical Implentation Guide", "_STIG");
                        string saveFile =
                            $"{saveDirectory}\\U_{stigName}_v{vulnerabilitySource.Source_Version}_r{vulnerabilitySource.Source_Release}_{hardware.Displayed_Host_Name}.ckl";
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
                    $"Unable to generate a CKL for '{hardware.Displayed_Host_Name}' - '{vulnerabilitySource.Source_Name}'.");
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
                xmlWriter.WriteElementString("HOST_NAME", sqliteDataReader["Displayed_Host_Name"].ToString());
                xmlWriter.WriteElementString("HOST_IP", sqliteDataReader["IpAddresses"].ToString());
                xmlWriter.WriteElementString("HOST_MAC", sqliteDataReader["MacAddresses"].ToString());
                xmlWriter.WriteElementString("HOST_GUID", string.Empty);
                xmlWriter.WriteElementString("HOST_FQDN", sqliteDataReader["FQDN"].ToString());
                xmlWriter.WriteElementString("TECH_AREA", sqliteDataReader["Technology_Area"].ToString());
                xmlWriter.WriteElementString("TARGET_KEY", string.Empty);
                xmlWriter.WriteElementString("ROLE", sqliteDataReader["Role"].ToString());
                if (string.IsNullOrWhiteSpace(sqliteDataReader["Web_DB_Site"].ToString()) || string.IsNullOrWhiteSpace(sqliteDataReader["Web_DB_Instance"].ToString()))
                { xmlWriter.WriteElementString("WEB_OR_DATABASE", "false"); }
                else
                { xmlWriter.WriteElementString("WEB_OR_DATABASE", "true"); }
                xmlWriter.WriteElementString("WEB_DB_SITE", sqliteDataReader["Web_DB_Site"].ToString());
                xmlWriter.WriteElementString("WEB_DB_INSTANCE", sqliteDataReader["Web_DB_Instance"].ToString());
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
                WriteSiDataNode(xmlWriter, "version", sqliteDataReader["Source_Version"].ToString());
                WriteSiDataNode(xmlWriter, "classification", sqliteDataReader["Classification"].ToString());
                WriteSiDataNode(xmlWriter, "customname", string.Empty);
                WriteSiDataNode(xmlWriter, "stigid", sqliteDataReader["Source_Secondary_Identifier"].ToString());
                WriteSiDataNode(xmlWriter, "description", sqliteDataReader["Source_Description"].ToString());
                WriteSiDataNode(xmlWriter, "filename", sqliteDataReader["Vulnerability_Source_File_Name"].ToString());
                WriteSiDataNode(xmlWriter, "releaseinfo", sqliteDataReader["Source_Release"].ToString());
                WriteSiDataNode(xmlWriter, "title", sqliteDataReader["Source_Name"].ToString());
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
                WriteStigDataNode(xmlWriter, "Vuln_Num", sqliteDataReader["Vulnerability_Group_ID"].ToString());
                WriteStigDataNode(xmlWriter, "Severity", sqliteDataReader["Raw_Risk"].ToString().ToSeverity());
                WriteStigDataNode(xmlWriter, "Group_Title", sqliteDataReader["Vulnerability_Group_Title"].ToString());
                string ruleId =
                    $"{sqliteDataReader["Unique_Vulnerability_Identifier"]}r{sqliteDataReader["Vulnerability_Version"].ToString()}_rule";
                WriteStigDataNode(xmlWriter, "Rule_ID", ruleId);
                WriteStigDataNode(xmlWriter, "Rule_Ver", sqliteDataReader["Secondary_Vulnerability_Identifier"].ToString());
                WriteStigDataNode(xmlWriter, "Rule_Title", sqliteDataReader["Vulnerability_Title"].ToString());
                WriteStigDataNode(xmlWriter, "Vuln_Discuss", sqliteDataReader["Vulnerability_Description"].ToString());
                WriteStigDataNode(xmlWriter, "IA_Controls", string.Empty);
                WriteStigDataNode(xmlWriter, "Check_Content", sqliteDataReader["Check_Content"].ToString());
                WriteStigDataNode(xmlWriter, "Fix_Text", sqliteDataReader["Fix_Text"].ToString());
                WriteStigDataNode(xmlWriter, "False_Positives", sqliteDataReader["False_Positives"].ToString());
                WriteStigDataNode(xmlWriter, "False_Negatives", sqliteDataReader["False_Negatives"].ToString());
                WriteStigDataNode(xmlWriter, "Documentable", sqliteDataReader["Documentable"].ToString());
                WriteStigDataNode(xmlWriter, "Mitigations", sqliteDataReader["Mitigations"].ToString());
                WriteStigDataNode(xmlWriter, "Potential_Impact", sqliteDataReader["Potential_Impacts"].ToString());
                WriteStigDataNode(xmlWriter, "Third_Party_Tools", sqliteDataReader["Third_Party_Tools"].ToString());
                WriteStigDataNode(xmlWriter, "Mitigation_Control", sqliteDataReader["Mitigation_Control"].ToString());
                WriteStigDataNode(xmlWriter, "Responsibility", string.Empty);
                WriteStigDataNode(xmlWriter, "Severity_Override_Guidance", sqliteDataReader["Security_Override_Guidance"].ToString());
                WriteStigDataNode(xmlWriter, "Check_Content_Ref", string.Empty);
                WriteStigDataNode(xmlWriter, "Weight", "10.0");
                WriteStigDataNode(xmlWriter, "Class", sqliteDataReader["Classification"].ToString());
                string stigRef =
                    $"{sqliteDataReader["Source_Name"].ToString()} v{sqliteDataReader["Source_Version"].ToString()} r{sqliteDataReader["Source_Release"].ToString()}";
                WriteStigDataNode(xmlWriter, "STIGRef", stigRef);
                WriteStigDataNode(xmlWriter, "TargetKey", string.Empty);
                foreach (string cci in sqliteDataReader["CCIs"].ToString().Split(',').ToArray())
                { WriteStigDataNode(xmlWriter, "CCI_REF", string.Concat("CCI-", cci)); }
                xmlWriter.WriteElementString("STATUS", sqliteDataReader["Status"].ToString().ToCklStatus());
                string toolGenerated;
                if (string.IsNullOrWhiteSpace(sqliteDataReader["Tool_Generated_Output"].ToString()))
                { toolGenerated = string.Empty; }
                else
                {
                    toolGenerated =
                        $"Tool Generated Output:{Environment.NewLine}{sqliteDataReader["Tool_Generated_Output"].ToString()}{Environment.NewLine + Environment.NewLine}";
                }
                string findingDetails;
                if (string.IsNullOrWhiteSpace(sqliteDataReader["Finding_Details"].ToString()))
                { findingDetails = string.Empty; }
                else
                {
                    findingDetails =
                        $"Manual Finding Details:{Environment.NewLine}{sqliteDataReader["Finding_Details"].ToString()}";
                }
                xmlWriter.WriteElementString("FINDING_DETAILS", toolGenerated + findingDetails);
                xmlWriter.WriteElementString("COMMENTS", sqliteDataReader["Comments"].ToString());
                xmlWriter.WriteElementString("SEVERITY_OVERRIDE", sqliteDataReader["Severity_Override"].ToString());
                xmlWriter.WriteElementString("SEVERITY_JUSTIFICATION", sqliteDataReader["Severity_Override_Justification"].ToString());
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
