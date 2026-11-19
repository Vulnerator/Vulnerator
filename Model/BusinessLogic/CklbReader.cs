using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Web.Script.Serialization;
using System.Xml;
using Vulnerator.Helper;

namespace Vulnerator.Model.BusinessLogic
{
    /// <summary>
    /// Reads DISA STIG Viewer 3 checklists (*.cklb, JSON).
    /// Each CKLB is converted to an equivalent STIG Viewer 2 checklist (*.ckl) and imported through
    /// <see cref="CklReader"/>, so both formats share one import path and one set of database rules.
    /// Field mapping follows STIG Viewer's own CKLB-to-CKL export and the CKL-CKLB-Processor reader.
    /// </summary>
    public class CklbReader
    {
        // CKLB rule property -> CKL VULN_ATTRIBUTE, in STIG Viewer 2 order.
        private static readonly string[][] RuleAttributeMap =
        {
            new[] { "group_id", "Vuln_Num" },
            new[] { "severity", "Severity" },
            new[] { "group_title", "Group_Title" },
            new[] { "rule_id_src", "Rule_ID" },
            new[] { "rule_version", "Rule_Ver" },
            new[] { "rule_title", "Rule_Title" },
            new[] { "discussion", "Vuln_Discuss" },
            new[] { "ia_controls", "IA_Controls" },
            new[] { "check_content", "Check_Content" },
            new[] { "fix_text", "Fix_Text" },
            new[] { "false_positives", "False_Positives" },
            new[] { "false_negatives", "False_Negatives" },
            new[] { "documentable", "Documentable" },
            new[] { "mitigations", "Mitigations" },
            new[] { "potential_impacts", "Potential_Impact" },
            new[] { "third_party_tools", "Third_Party_Tools" },
            new[] { "mitigation_control", "Mitigation_Control" },
            new[] { "responsibility", "Responsibility" },
            new[] { "security_override_guidance", "Security_Override_Guidance" },
            new[] { "check_content_ref", "Check_Content_Ref" },
            new[] { "weight", "Weight" },
            new[] { "classification", "Class" },
            new[] { "uuid", "STIG_UUID" }
        };

        private static readonly Dictionary<string, string> StatusMap =
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                { "open", "Open" },
                { "not_a_finding", "NotAFinding" },
                { "notafinding", "NotAFinding" },
                { "not_applicable", "Not_Applicable" },
                { "not_reviewed", "Not_Reviewed" }
            };

        /// <summary>Imports a *.cklb file. Returns the same status strings as <see cref="CklReader.ReadCklFile"/>.</summary>
        public string ReadCklbFile(Model.Object.File file, string groupName)
        {
            string tempCkl = null;
            try
            {
                if (file.FilePath.IsFileInUse())
                {
                    LogWriter.LogError($"'{file.FileName}' is in use; please close any open instances and try again.");
                    return "Failed; File In Use";
                }
                tempCkl = Path.Combine(Path.GetTempPath(), $"Vulnerator_{Guid.NewGuid():N}.ckl");
                ConvertToCkl(file.FilePath, tempCkl);

                // Import the converted checklist, but keep the original file's name and path as the finding source.
                string originalPath = file.FilePath;
                file.FilePath = tempCkl;
                try
                { return new CklReader().ReadCklFile(file, groupName); }
                finally
                { file.FilePath = originalPath; }
            }
            catch (Exception exception)
            {
                LogWriter.LogErrorWithDebug($"Unable to process CKLB file '{file.FileName}'.", exception);
                return "Failed; See Log";
            }
            finally
            {
                if (tempCkl != null)
                {
                    try { System.IO.File.Delete(tempCkl); }
                    catch (Exception) { /* best effort: %TEMP% is cleaned by Windows */ }
                }
            }
        }

        /// <summary>Reads host name, IP and MAC so the import list can flag missing identifiers, as for CKL.</summary>
        public Model.Object.File ObtainIdentifiers(Model.Object.File file)
        {
            try
            {
                Dictionary<string, object> target = AsObject(Get(Load(file.FilePath), "target_data"));
                file.SetFileHostName(Text(Get(target, "host_name")));
                file.SetFileIpAddress(Text(Get(target, "ip_address")));
                file.SetFileMacAddress(Text(Get(target, "mac_address")));
                if ((Properties.Settings.Default.CklRequiresHostName && string.IsNullOrWhiteSpace(file.FileHostName)) ||
                    (Properties.Settings.Default.CklRequiresIpAddress && string.IsNullOrWhiteSpace(file.FileIpAddress)) ||
                    (Properties.Settings.Default.CklrequiresMacAddress && string.IsNullOrWhiteSpace(file.FileMacAddress)))
                { file.IdentifiersProvided = "False"; }
                return file;
            }
            catch (Exception exception)
            {
                LogWriter.LogErrorWithDebug($"Unable to read host identifiers from CKLB file '{file.FileName}'.", exception);
                return file;
            }
        }

        /// <summary>Writes a STIG Viewer 2 compatible *.ckl equivalent of a *.cklb file.</summary>
        public static void ConvertToCkl(string cklbPath, string cklPath)
        {
            Dictionary<string, object> root = Load(cklbPath);
            object stigsValue = Get(root, "stigs");
            if (!(stigsValue is IEnumerable) || stigsValue is string)
            { throw new InvalidDataException("Not a CKLB file: missing \"stigs\" array."); }
            Dictionary<string, object> target = AsObject(Get(root, "target_data"));

            XmlWriterSettings settings = new XmlWriterSettings
            {
                Encoding = new UTF8Encoding(false),
                Indent = true,
                IndentChars = "\t"
            };
            using (XmlWriter writer = XmlWriter.Create(cklPath, settings))
            {
                writer.WriteStartDocument();
                writer.WriteComment($"Converted by Vulnerator from {Path.GetFileName(cklbPath)}");
                writer.WriteStartElement("CHECKLIST");

                writer.WriteStartElement("ASSET");
                writer.WriteElementString("ROLE", Text(Get(target, "role"), "None"));
                writer.WriteElementString("ASSET_TYPE", Text(Get(target, "target_type"), "Computing"));
                writer.WriteElementString("MARKING", Text(Get(target, "marking")));
                writer.WriteElementString("HOST_NAME", Text(Get(target, "host_name")));
                writer.WriteElementString("HOST_IP", Text(Get(target, "ip_address")));
                writer.WriteElementString("HOST_MAC", Text(Get(target, "mac_address")));
                writer.WriteElementString("HOST_FQDN", Text(Get(target, "fqdn")));
                writer.WriteElementString("TARGET_COMMENT", Text(Get(target, "comments")));
                writer.WriteElementString("TECH_AREA", Text(Get(target, "technology_area")));
                writer.WriteElementString("TARGET_KEY", Text(Get(target, "target_key")));
                writer.WriteElementString("WEB_OR_DATABASE", Text(Get(target, "is_web_database"), "false").ToLowerInvariant());
                writer.WriteElementString("WEB_DB_SITE", Text(Get(target, "web_db_site")));
                writer.WriteElementString("WEB_DB_INSTANCE", Text(Get(target, "web_db_instance")));
                writer.WriteEndElement();

                writer.WriteStartElement("STIGS");
                foreach (object stigValue in (IEnumerable)stigsValue)
                {
                    Dictionary<string, object> stig = AsObject(stigValue);
                    if (stig.Count == 0)
                    { continue; }
                    writer.WriteStartElement("iSTIG");
                    writer.WriteStartElement("STIG_INFO");
                    string title = Text(Get(stig, "stig_name"));
                    if (string.IsNullOrWhiteSpace(title))
                    { title = Text(Get(stig, "display_name")); }
                    WriteStigInfo(writer, "version", Text(Get(stig, "version")));
                    WriteStigInfo(writer, "classification", Text(Get(stig, "classification")));
                    WriteStigInfo(writer, "stigid", Text(Get(stig, "stig_id")));
                    WriteStigInfo(writer, "description", Text(Get(stig, "description")));
                    WriteStigInfo(writer, "filename", Text(Get(stig, "filename")));
                    WriteStigInfo(writer, "releaseinfo", Text(Get(stig, "release_info")));
                    WriteStigInfo(writer, "title", title);
                    WriteStigInfo(writer, "uuid", Text(Get(stig, "uuid")));
                    writer.WriteEndElement();

                    object rules = Get(stig, "rules");
                    if (rules is IEnumerable && !(rules is string))
                    {
                        foreach (object ruleValue in (IEnumerable)rules)
                        {
                            Dictionary<string, object> rule = AsObject(ruleValue);
                            if (rule.Count > 0)
                            { WriteVuln(writer, rule); }
                        }
                    }
                    writer.WriteEndElement();
                }
                writer.WriteEndElement();

                writer.WriteEndElement();
                writer.WriteEndDocument();
            }
        }

        private static void WriteVuln(XmlWriter writer, Dictionary<string, object> rule)
        {
            writer.WriteStartElement("VULN");
            foreach (string[] pair in RuleAttributeMap)
            {
                string value = Text(Get(rule, pair[0]));
                // rule_id_src carries the full "SV-xxxxx_rule" form; rule_id may be truncated.
                if (pair[0] == "rule_id_src" && string.IsNullOrWhiteSpace(value))
                { value = Text(Get(rule, "rule_id")); }
                WriteStigData(writer, pair[1], value);
            }
            foreach (string legacyId in List(Get(rule, "legacy_ids")))
            { WriteStigData(writer, "LEGACY_ID", legacyId); }
            // The rule's own date (CKL has none): the earlier of createdAt / updatedAt as a local calendar date.
            // CklReader uses it as the finding's first-discovered date (CKL-CKLB-Processor AD-916 / R-17).
            DateTime? ruleDate = EarliestDate(Get(rule, "createdAt"), Get(rule, "updatedAt"));
            if (ruleDate.HasValue)
            { WriteStigData(writer, CklReader.RuleDateAttribute, ruleDate.Value.ToString("yyyy-MM-dd", System.Globalization.CultureInfo.InvariantCulture)); }
            foreach (string cci in List(Get(rule, "ccis")))
            { WriteStigData(writer, "CCI_REF", cci); }

            string rawStatus = Text(Get(rule, "status")).Trim();
            string status;
            if (!StatusMap.TryGetValue(rawStatus, out status))
            { status = string.IsNullOrEmpty(rawStatus) ? "Not_Reviewed" : rawStatus; }
            writer.WriteElementString("STATUS", status);
            writer.WriteElementString("FINDING_DETAILS", Text(Get(rule, "finding_details")));
            writer.WriteElementString("COMMENTS", Text(Get(rule, "comments")));

            // overrides: { "severity": { "severity": "low", "reason": "..." } }
            Dictionary<string, object> severityOverride = AsObject(Get(AsObject(Get(rule, "overrides")), "severity"));
            writer.WriteElementString("SEVERITY_OVERRIDE", Text(Get(severityOverride, "severity")));
            writer.WriteElementString("SEVERITY_JUSTIFICATION", Text(Get(severityOverride, "reason")));
            writer.WriteEndElement();
        }

        private static void WriteStigInfo(XmlWriter writer, string name, string value)
        {
            writer.WriteStartElement("SI_DATA");
            writer.WriteElementString("SID_NAME", name);
            if (!string.IsNullOrEmpty(value))
            { writer.WriteElementString("SID_DATA", value); }
            writer.WriteEndElement();
        }

        private static void WriteStigData(XmlWriter writer, string attribute, string value)
        {
            writer.WriteStartElement("STIG_DATA");
            writer.WriteElementString("VULN_ATTRIBUTE", attribute);
            writer.WriteElementString("ATTRIBUTE_DATA", value ?? string.Empty);
            writer.WriteEndElement();
        }

        private static DateTime? EarliestDate(params object[] values)
        {
            DateTime? earliest = null;
            foreach (object value in values)
            {
                string text = Text(value).Trim();
                DateTimeOffset parsed;
                if (text.Length > 0 && DateTimeOffset.TryParse(text, System.Globalization.CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.AssumeLocal, out parsed))
                {
                    DateTime local = parsed.LocalDateTime.Date;
                    if (!earliest.HasValue || local < earliest.Value)
                    { earliest = local; }
                }
            }
            return earliest;
        }

        private static Dictionary<string, object> Load(string path)
        {
            string json = System.IO.File.ReadAllText(path, Encoding.UTF8);
            JavaScriptSerializer serializer = new JavaScriptSerializer { MaxJsonLength = int.MaxValue, RecursionLimit = 256 };
            Dictionary<string, object> root = serializer.DeserializeObject(json) as Dictionary<string, object>;
            if (root == null)
            { throw new InvalidDataException("Not a CKLB file: the top level is not a JSON object."); }
            return root;
        }

        private static object Get(Dictionary<string, object> obj, string key)
        {
            object value;
            return obj != null && obj.TryGetValue(key, out value) ? value : null;
        }

        private static Dictionary<string, object> AsObject(object value)
        { return value as Dictionary<string, object> ?? new Dictionary<string, object>(); }

        private static string Text(object value, string fallback = "")
        {
            if (value == null)
            { return fallback; }
            if (value is bool)
            { return (bool)value ? "true" : "false"; }
            // check_content_ref is an object, e.g. { "href": "X_STIG.xml", "name": "M" }; CKL carries its name.
            Dictionary<string, object> obj = value as Dictionary<string, object>;
            if (obj != null)
            { return Text(Get(obj, "name"), fallback); }
            if (value is IFormattable)
            { return ((IFormattable)value).ToString(null, System.Globalization.CultureInfo.InvariantCulture); }
            string text = value.ToString();
            return string.IsNullOrEmpty(text) ? fallback : text;
        }

        private static IEnumerable<string> List(object value)
        {
            if (value is string)
            {
                if (!string.IsNullOrWhiteSpace((string)value))
                { yield return ((string)value).Trim(); }
                yield break;
            }
            if (!(value is IEnumerable))
            { yield break; }
            foreach (object item in (IEnumerable)value)
            {
                string text = Text(item).Trim();
                if (text.Length > 0)
                { yield return text; }
            }
        }
    }
}
