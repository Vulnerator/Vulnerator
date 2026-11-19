using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Xml;
using Vulnerator.Helper;
using Vulnerator.Model.DataAccess;
using Vulnerator.Model.Entity;

namespace Vulnerator.Model.BusinessLogic
{
    /// <summary>
    /// Writes a DISA STIG Viewer checklist (.ckl) for one host and one STIG: every rule of the STIG, with the host's
    /// status, details and comments where Vulnerator has a result, and Not_Reviewed elsewhere.
    /// </summary>
    public class CklCreator
    {
        private readonly DdlReader _ddlReader = new DdlReader();
        private readonly Assembly assembly = Assembly.GetExecutingAssembly();
        private const string StoredProcedureBase = "Vulnerator.Resources.DdlFiles.StoredProcedures.";

        /// <summary>The checklist's MARKING (classification / handling); from Settings when not set.</summary>
        public string Marking { get; set; }

        /// <summary>Writes the checklist into <paramref name="saveDirectory"/>; returns the file's path.</summary>
        public string CreateCklFromHardware(Hardware hardware, VulnerabilitySource vulnerabilitySource, string saveDirectory)
        {
            try
            {
                Dictionary<string, string> asset;
                List<Dictionary<string, object>> rules;
                if (!DatabaseBuilder.sqliteConnection.State.ToString().Equals("Open"))
                { DatabaseBuilder.sqliteConnection.Open(); }
                using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                {
                    sqliteCommand.Parameters.Add(new SQLiteParameter("Hardware_ID", hardware.Hardware_ID));
                    sqliteCommand.Parameters.Add(new SQLiteParameter("VulnerabilitySource_ID", vulnerabilitySource.VulnerabilitySource_ID));
                    sqliteCommand.CommandText = _ddlReader.ReadDdl(StoredProcedureBase + "Select.HardwareCklAsset.dml", assembly);
                    asset = ReadRows(sqliteCommand).Select(r => r.ToDictionary(c => c.Key, c => Text(c.Value))).FirstOrDefault()
                            ?? new Dictionary<string, string>();
                    sqliteCommand.CommandText = _ddlReader.ReadDdl(StoredProcedureBase + "Select.HardwareCklCreationData.dml", assembly);
                    rules = ReadRows(sqliteCommand);
                }
                if (rules.Count == 0)
                { throw new InvalidOperationException($"'{vulnerabilitySource.SourceName}' has no rules in the library."); }

                // One VULN per rule: the revision this host has a result for, else the newest revision.
                List<Dictionary<string, object>> vulns = rules
                    .GroupBy(r => Text(r["UniqueVulnerabilityIdentifier"]))
                    .Select(g => g.OrderByDescending(r => !string.IsNullOrWhiteSpace(Text(r["Status"])))
                        .ThenByDescending(r => Revision(Text(r["VulnerabilityVersion"]))).First())
                    .OrderBy(r => GroupNumber(Text(r["VulnerabilityGroupIdentifier"])))
                    .ToList();

                string hostName = Value(asset, "DisplayedHostName", Value(asset, "DiscoveredHostName", hardware.DisplayedHostName));
                string stigId = Text(rules[0]["SourceSecondaryIdentifier"]);
                string fileStem = $"{(string.IsNullOrWhiteSpace(stigId) ? vulnerabilitySource.SourceName : stigId)}_V{Text(rules[0]["SourceVersion"])}R{Text(rules[0]["SourceRelease"])}_{hostName}";
                string saveFile = Path.Combine(saveDirectory, SafeFileName(fileStem) + ".ckl");

                using (XmlWriter xmlWriter = XmlWriter.Create(saveFile, GenerateXmlWriterSettings()))
                {
                    xmlWriter.WriteStartDocument();
                    xmlWriter.WriteComment("DISA STIG Viewer :: 2.18");
                    xmlWriter.WriteComment("Written by Vulnerator");
                    xmlWriter.WriteStartElement("CHECKLIST");
                    WriteAsset(xmlWriter, asset, hostName, Marking ?? Properties.Settings.Default.EmassClassificationMarking ?? string.Empty);
                    xmlWriter.WriteStartElement("STIGS");
                    xmlWriter.WriteStartElement("iSTIG");
                    WriteStigInformation(xmlWriter, rules);
                    foreach (Dictionary<string, object> vuln in vulns)
                    { WriteVulnerability(xmlWriter, vuln, rules[0]); }
                    xmlWriter.WriteEndElement();
                    xmlWriter.WriteEndElement();
                    xmlWriter.WriteEndElement();
                    xmlWriter.WriteEndDocument();
                }
                LogWriter.LogStatusUpdate($"Wrote '{saveFile}' ({vulns.Count} rules).");
                return saveFile;
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to generate a CKL for '{hardware.DisplayedHostName}' - '{vulnerabilitySource.SourceName}'.");
                throw exception;
            }
            finally
            { DatabaseBuilder.sqliteConnection.Close(); }
        }

        private static List<Dictionary<string, object>> ReadRows(SQLiteCommand sqliteCommand)
        {
            List<Dictionary<string, object>> rows = new List<Dictionary<string, object>>();
            using (SQLiteDataReader reader = sqliteCommand.ExecuteReader())
            {
                while (reader.Read())
                {
                    Dictionary<string, object> row = new Dictionary<string, object>(StringComparer.OrdinalIgnoreCase);
                    for (int i = 0; i < reader.FieldCount; i++)
                    { row[reader.GetName(i)] = reader.IsDBNull(i) ? null : reader.GetValue(i); }
                    rows.Add(row);
                }
            }
            return rows;
        }

        private static void WriteAsset(XmlWriter xmlWriter, Dictionary<string, string> asset, string hostName, string marking)
        {
            string site = Value(asset, "WebDB_Site", string.Empty);
            string instance = Value(asset, "WebDB_Instance", string.Empty);
            xmlWriter.WriteStartElement("ASSET");
            xmlWriter.WriteElementString("ROLE", Value(asset, "Role", "None"));
            xmlWriter.WriteElementString("ASSET_TYPE", "Computing");
            xmlWriter.WriteElementString("MARKING", marking.Trim());
            xmlWriter.WriteElementString("HOST_NAME", hostName);
            xmlWriter.WriteElementString("HOST_IP", FirstOf(Value(asset, "IpAddresses", string.Empty)));
            xmlWriter.WriteElementString("HOST_MAC", FirstOf(Value(asset, "MacAddresses", string.Empty)));
            xmlWriter.WriteElementString("HOST_FQDN", Value(asset, "FQDN", string.Empty));
            xmlWriter.WriteElementString("TARGET_COMMENT", string.Empty);
            xmlWriter.WriteElementString("TECH_AREA", Value(asset, "TechnologyArea", string.Empty));
            xmlWriter.WriteElementString("TARGET_KEY", string.Empty);
            xmlWriter.WriteElementString("WEB_OR_DATABASE", (site != string.Empty || instance != string.Empty) ? "true" : "false");
            xmlWriter.WriteElementString("WEB_DB_SITE", site);
            xmlWriter.WriteElementString("WEB_DB_INSTANCE", instance);
            xmlWriter.WriteEndElement();
        }

        private static void WriteStigInformation(XmlWriter xmlWriter, List<Dictionary<string, object>> rules)
        {
            Dictionary<string, object> first = rules[0];
            string classification = rules.Select(r => Text(r["Classification"])).FirstOrDefault(c => c != string.Empty) ?? string.Empty;
            xmlWriter.WriteStartElement("STIG_INFO");
            WriteSiData(xmlWriter, "version", Text(first["SourceVersion"]));
            WriteSiData(xmlWriter, "classification", classification);
            WriteSiData(xmlWriter, "customname", string.Empty);
            WriteSiData(xmlWriter, "stigid", Text(first["SourceSecondaryIdentifier"]));
            WriteSiData(xmlWriter, "description", Text(first["SourceDescription"]));
            WriteSiData(xmlWriter, "filename", Text(first["VulnerabilitySourceFileName"]));
            WriteSiData(xmlWriter, "releaseinfo", ReleaseInfo(rules));
            WriteSiData(xmlWriter, "title", Text(first["SourceName"]));
            WriteSiData(xmlWriter, "uuid", Guid.NewGuid().ToString());
            WriteSiData(xmlWriter, "notice", "terms-of-use");
            WriteSiData(xmlWriter, "source", string.Empty);
            xmlWriter.WriteEndElement();
        }

        /// <summary>"Release: 4 Benchmark Date: 01 May 2026", the form STIG Viewer writes and Vulnerator reads back.</summary>
        private static string ReleaseInfo(List<Dictionary<string, object>> rules)
        {
            string release = $"Release: {Text(rules[0]["SourceRelease"])}";
            long ticks = rules.Select(r => r["PublishedTicks"]).OfType<long>().DefaultIfEmpty(0).Max();
            return ticks > 0
                ? $"{release} Benchmark Date: {new DateTime(ticks).ToString("dd MMM yyyy", CultureInfo.InvariantCulture)}"
                : release;
        }

        private static void WriteVulnerability(XmlWriter xmlWriter, Dictionary<string, object> vuln, Dictionary<string, object> source)
        {
            xmlWriter.WriteStartElement("VULN");
            WriteStigData(xmlWriter, "Vuln_Num", Text(vuln["VulnerabilityGroupIdentifier"]));
            WriteStigData(xmlWriter, "Severity", Text(vuln["PrimaryRawRiskIndicator"]).ToSeverity());
            WriteStigData(xmlWriter, "Group_Title", Text(vuln["VulnerabilityGroupTitle"]));
            string revision = Text(vuln["VulnerabilityVersion"]);
            WriteStigData(xmlWriter, "Rule_ID", $"{Text(vuln["UniqueVulnerabilityIdentifier"])}{(revision == string.Empty ? string.Empty : "r" + revision)}_rule");
            WriteStigData(xmlWriter, "Rule_Ver", Text(vuln["SecondaryVulnerabilityIdentifier"]));
            WriteStigData(xmlWriter, "Rule_Title", Text(vuln["VulnerabilityTitle"]));
            WriteStigData(xmlWriter, "Vuln_Discuss", Text(vuln["VulnerabilityDescription"]));
            WriteStigData(xmlWriter, "IA_Controls", string.Empty);
            WriteStigData(xmlWriter, "Check_Content", Text(vuln["CheckContent"]));
            WriteStigData(xmlWriter, "Fix_Text", Text(vuln["FixText"]));
            WriteStigData(xmlWriter, "False_Positives", Text(vuln["FalsePositives"]));
            WriteStigData(xmlWriter, "False_Negatives", Text(vuln["FalseNegatives"]));
            WriteStigData(xmlWriter, "Documentable", Text(vuln["IsDocumentable"]) == string.Empty ? "false" : Text(vuln["IsDocumentable"]));
            WriteStigData(xmlWriter, "Mitigations", Text(vuln["Mitigations"]));
            WriteStigData(xmlWriter, "Potential_Impact", Text(vuln["PotentialImpacts"]));
            WriteStigData(xmlWriter, "Third_Party_Tools", Text(vuln["ThirdPartyTools"]));
            WriteStigData(xmlWriter, "Mitigation_Control", Text(vuln["MitigationControl"]));
            WriteStigData(xmlWriter, "Responsibility", string.Empty);
            string overrideGuidance = Text(vuln["SeverityOverrideGuidance"]);
            WriteStigData(xmlWriter, "Security_Override_Guidance", overrideGuidance != string.Empty ? overrideGuidance : Text(vuln["SecurityOverrideGuidance"]));
            WriteStigData(xmlWriter, "Check_Content_Ref", "M");
            WriteStigData(xmlWriter, "Weight", "10.0");
            WriteStigData(xmlWriter, "Class", "Unclass");
            WriteStigData(xmlWriter, "STIGRef",
                $"{Text(source["SourceName"])} :: Version {Text(source["SourceVersion"])}, Release: {Text(source["SourceRelease"])}");
            WriteStigData(xmlWriter, "TargetKey", string.Empty);
            WriteStigData(xmlWriter, "STIG_UUID", string.Empty);
            foreach (string cci in Text(vuln["CCIs"]).Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries))
            { WriteStigData(xmlWriter, "CCI_REF", "CCI-" + cci.Trim()); }

            string status = Text(vuln["Status"]);
            xmlWriter.WriteElementString("STATUS", status == string.Empty ? "Not_Reviewed" : status.ToCklStatus());
            StringBuilder details = new StringBuilder(Text(vuln["FindingDetails"]));
            string toolOutput = Text(vuln["ToolGeneratedOutput"]);
            if (toolOutput != string.Empty)
            {
                if (details.Length > 0)
                { details.AppendLine().AppendLine(); }
                details.Append("Tool Generated Output:").AppendLine().Append(toolOutput);
            }
            xmlWriter.WriteElementString("FINDING_DETAILS", Clean(details.ToString()));
            xmlWriter.WriteElementString("COMMENTS", Clean(Text(vuln["Comments"])));
            xmlWriter.WriteElementString("SEVERITY_OVERRIDE", Text(vuln["SeverityOverride"]));
            xmlWriter.WriteElementString("SEVERITY_JUSTIFICATION", Clean(Text(vuln["SeverityOverrideJustification"])));
            xmlWriter.WriteEndElement();
        }

        private static void WriteSiData(XmlWriter xmlWriter, string name, string data)
        {
            xmlWriter.WriteStartElement("SI_DATA");
            xmlWriter.WriteElementString("SID_NAME", name);
            if (data != string.Empty)
            { xmlWriter.WriteElementString("SID_DATA", Clean(data)); }
            xmlWriter.WriteEndElement();
        }

        private static void WriteStigData(XmlWriter xmlWriter, string attribute, string data)
        {
            xmlWriter.WriteStartElement("STIG_DATA");
            xmlWriter.WriteElementString("VULN_ATTRIBUTE", attribute);
            xmlWriter.WriteElementString("ATTRIBUTE_DATA", Clean(data));
            xmlWriter.WriteEndElement();
        }

        private static string Text(object value)
        { return value == null || value == DBNull.Value ? string.Empty : value.ToString().Trim(); }

        private static string Value(Dictionary<string, string> row, string key, string fallback)
        {
            string value;
            return row.TryGetValue(key, out value) && !string.IsNullOrWhiteSpace(value) ? value : fallback;
        }

        private static string FirstOf(string list)
        { return list.Split(',').Select(v => v.Trim()).FirstOrDefault(v => v != string.Empty) ?? string.Empty; }

        private static int Revision(string revision)
        {
            int value;
            return int.TryParse(revision, out value) ? value : -1;
        }

        private static long GroupNumber(string groupId)
        {
            long value;
            return long.TryParse(new string(groupId.Where(char.IsDigit).ToArray()), out value) ? value : long.MaxValue;
        }

        private static string Clean(string value)
        { return new string((value ?? string.Empty).Where(c => XmlConvert.IsXmlChar(c) || char.IsSurrogate(c)).ToArray()); }

        private static string SafeFileName(string name)
        {
            char[] invalid = Path.GetInvalidFileNameChars();
            return new string(name.Select(c => invalid.Contains(c) || c == ' ' ? '_' : c).ToArray());
        }

        private static XmlWriterSettings GenerateXmlWriterSettings()
        {
            return new XmlWriterSettings
            {
                Encoding = new UTF8Encoding(false),
                Indent = true,
                IndentChars = "\t",
                NewLineChars = "\r\n",
                NewLineHandling = NewLineHandling.Entitize
            };
        }
    }
}
