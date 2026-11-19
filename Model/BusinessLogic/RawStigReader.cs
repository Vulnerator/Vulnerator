using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;
using Vulnerator.Helper;
using Vulnerator.Model.DataAccess;

namespace Vulnerator.Model.BusinessLogic
{
    /// <summary>
    /// Loads DISA STIG benchmarks (XCCDF 1.1 or 1.2: a manual "-xccdf.xml", or a SCAP 1.2/1.3 data stream holding one)
    /// into the vulnerability library, so rules and their CCIs are known before any checklist or scan is imported.
    /// Adds no hosts and no findings.
    /// </summary>
    public class RawStigReader
    {
        public const string Parsed = "Parsed";
        public const string Skipped = "Skipped";
        public const string Failed = "Failed";
        public const string Older = "Skipped; older than the release already loaded";

        private static readonly string[] DescriptionTags =
        {
            "VulnDiscussion", "FalsePositives", "FalseNegatives", "Documentable", "Mitigations", "SeverityOverrideGuidance",
            "PotentialImpacts", "ThirdPartyTools", "MitigationControl", "Responsibility", "IAControls"
        };

        private static readonly string[] SourceParameters =
        {
            "SourceName", "SourceVersion", "SourceRelease", "SourceSecondaryIdentifier", "SourceDescription",
            "VulnerabilitySourceFileName", "PublishedDate", "VulnerabilityRelease", "FindingType", "ModifiedDate"
        };

        private readonly DatabaseInterface databaseInterface = new DatabaseInterface();

        /// <summary>Last rule-level result, for callers that report counts.</summary>
        public int RulesRead { get; private set; }

        public string ReadRawStig(ZipArchiveEntry rawStig)
        {
            using (Stream stream = rawStig.Open())
            { return ReadRawStig(stream, rawStig.Name); }
        }

        /// <summary>Loads one benchmark file; returns <see cref="Parsed"/>, <see cref="Skipped"/> (not a benchmark), <see cref="Older"/> or <see cref="Failed"/>.</summary>
        public string ReadRawStig(Stream stream, string fileName)
        {
            RulesRead = 0;
            XElement benchmark;
            try
            {
                XmlReaderSettings settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Ignore, XmlResolver = null, IgnoreComments = true };
                using (XmlReader xmlReader = XmlReader.Create(stream, settings))
                { benchmark = XDocument.Load(xmlReader).Descendants().FirstOrDefault(e => e.Name.LocalName == "Benchmark"); }
            }
            catch (Exception exception)
            {
                LogWriter.LogErrorWithDebug($"Unable to read STIG file '{fileName}' as XML.", exception);
                return Failed;
            }
            if (benchmark == null)
            { return Skipped; }

            try
            {
                LogWriter.LogStatusUpdate($"Begin ingestion of raw STIG file '{fileName}'.");
                if (DatabaseBuilder.sqliteConnection.State.ToString().Equals("Closed"))
                { DatabaseBuilder.sqliteConnection.Open(); }
                using (SQLiteTransaction sqliteTransaction = DatabaseBuilder.sqliteConnection.BeginTransaction())
                using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                {
                    databaseInterface.InsertParameterPlaceholders(sqliteCommand);
                    if (!LoadBenchmark(sqliteCommand, benchmark, fileName, "CKL", true))
                    {
                        LogWriter.LogStatusUpdate($"Skipped '{fileName}': a newer release of this STIG is already loaded.");
                        return Older;
                    }
                    sqliteTransaction.Commit();
                }
                LogWriter.LogStatusUpdate($"Ingested {RulesRead} rule(s) from '{fileName}'.");
                return Parsed;
            }
            catch (Exception exception)
            {
                LogWriter.LogErrorWithDebug($"Unable to process STIG file '{fileName}'.", exception);
                return Failed;
            }
            finally
            { DatabaseBuilder.sqliteConnection.Close(); }
        }

        /// <summary>Rule id ("SV-254239") to the library revision its findings attach to, filled by <see cref="LoadBenchmark"/>.</summary>
        public Dictionary<string, string> Revisions { get; } = new Dictionary<string, string>();

        /// <summary>The benchmark's name, version, release and date as the file has them (before an older release is
        /// moved onto the loaded one), filled by <see cref="LoadBenchmark"/>.</summary>
        public string SubmittedSourceName { get; private set; }
        public string SubmittedVersion { get; private set; }
        public string SubmittedRelease { get; private set; }
        public object SubmittedBenchmarkDate { get; private set; }

        /// <summary>
        /// Writes the benchmark's source and rules using an open command (placeholders inserted). As the library
        /// (<paramref name="isLibrary"/>), an older release is refused (returns false) and superseded rules are pruned;
        /// for scan results the rules are only added or refreshed.
        /// </summary>
        public bool LoadBenchmark(SQLiteCommand sqliteCommand, XElement benchmark, string fileName, string findingType, bool isLibrary)
        {
            RulesRead = 0;
            Revisions.Clear();
            SetSource(sqliteCommand, benchmark, fileName);
            SubmittedSourceName = sqliteCommand.Parameters["SourceName"].Value?.ToString() ?? string.Empty;
            SubmittedVersion = sqliteCommand.Parameters["SourceVersion"].Value?.ToString() ?? string.Empty;
            SubmittedRelease = sqliteCommand.Parameters["SourceRelease"].Value?.ToString() ?? string.Empty;
            SubmittedBenchmarkDate = sqliteCommand.Parameters["PublishedDate"].Value;
            sqliteCommand.Parameters["FindingType"].Value = findingType;
            if (databaseInterface.SourceHasNewerRelease(sqliteCommand))
            {
                if (isLibrary)
                { return false; }
                // Older scan results: keep the newer release; findings attach to its rules.
                databaseInterface.UseLoadedSourceRelease(sqliteCommand);
            }
            else
            {
                databaseInterface.UpdateVulnerabilitySource(sqliteCommand);
                databaseInterface.InsertVulnerabilitySource(sqliteCommand);
            }
            foreach (XElement group in Children(benchmark, "Group").SelectMany(SelfAndNestedGroups))
            {
                foreach (XElement rule in Children(group, "Rule"))
                {
                    ReadRule(sqliteCommand, group, rule);
                    RulesRead++;
                }
            }
            if (isLibrary)
            { databaseInterface.DeleteRemovedVulnerabilities(sqliteCommand); }
            return true;
        }

        private static IEnumerable<XElement> SelfAndNestedGroups(XElement group)
        { return new[] { group }.Concat(Children(group, "Group").SelectMany(SelfAndNestedGroups)); }

        public static IEnumerable<XElement> Children(XElement parent, string localName)
        { return parent.Elements().Where(e => e.Name.LocalName == localName); }

        public static string ChildText(XElement parent, string localName)
        { return Children(parent, localName).FirstOrDefault()?.Value.Trim() ?? string.Empty; }

        private static void SetSource(SQLiteCommand sqliteCommand, XElement benchmark, string fileName)
        {
            // A parameter keeps the type of the first value it is given: the date is cleared with null, never "", or
            // every later date would be stored as text instead of the ticks used everywhere else.
            foreach (string parameter in SourceParameters.Where(p => p != "PublishedDate"))
            { sqliteCommand.Parameters[parameter].Value = string.Empty; }
            sqliteCommand.Parameters["PublishedDate"].DbType = System.Data.DbType.DateTime;
            sqliteCommand.Parameters["PublishedDate"].Value = DBNull.Value;
            sqliteCommand.Parameters["FindingType"].Value = "CKL";
            sqliteCommand.Parameters["ModifiedDate"].Value = DateTime.Now.ToShortDateString();
            sqliteCommand.Parameters["SourceName"].Value = ChildText(benchmark, "title").Replace('_', ' ').ToSanitizedSource();
            sqliteCommand.Parameters["SourceDescription"].Value = ChildText(benchmark, "description");
            sqliteCommand.Parameters["SourceVersion"].Value = ChildText(benchmark, "version");
            sqliteCommand.Parameters["SourceSecondaryIdentifier"].Value =
                Regex.Replace(benchmark.Attribute("id")?.Value ?? string.Empty, @"^xccdf_[^_]+_benchmark_", string.Empty);
            sqliteCommand.Parameters["VulnerabilitySourceFileName"].Value = fileName;

            // DISA puts "Release: 5 Benchmark Date: 04 Jan 2026" in plain-text id="release-info"; other plain-text
            // elements (generator, conventionsVersion) must not be read as the release.
            XElement releaseInfo = Children(benchmark, "plain-text").FirstOrDefault(p => (string)p.Attribute("id") == "release-info")
                                   ?? Children(benchmark, "plain-text").FirstOrDefault(p => p.Value.Contains("Release:"));
            string release = releaseInfo?.Value.Trim() ?? string.Empty;
            Match releaseNumber = Regex.Match(release, @"Release:\s*(\d+)", RegexOptions.IgnoreCase);
            sqliteCommand.Parameters["SourceRelease"].Value = releaseNumber.Success ? releaseNumber.Groups[1].Value : release;
            sqliteCommand.Parameters["PublishedDate"].Value = release.ToStigBenchmarkDate();
        }

        private void ReadRule(SQLiteCommand sqliteCommand, XElement group, XElement rule)
        {
            foreach (SQLiteParameter parameter in sqliteCommand.Parameters)
            {
                if (!SourceParameters.Contains(parameter.ParameterName))
                { parameter.Value = DBNull.Value; }
            }

            string groupId = group.Attribute("id")?.Value ?? string.Empty;
            Match vulnId = Regex.Match(groupId, @"V-\d+");
            sqliteCommand.Parameters["VulnerabilityGroupIdentifier"].Value = vulnId.Success ? vulnId.Value : groupId;
            sqliteCommand.Parameters["VulnerabilityGroupTitle"].Value = ChildText(group, "title");

            string ruleId;
            string ruleRevision;
            SplitRuleId(rule.Attribute("id")?.Value, out ruleId, out ruleRevision);
            sqliteCommand.Parameters["UniqueVulnerabilityIdentifier"].Value = ruleId;
            sqliteCommand.Parameters["VulnerabilityVersion"].Value = ruleRevision;
            sqliteCommand.Parameters["PrimaryRawRiskIndicator"].Value = (rule.Attribute("severity")?.Value ?? string.Empty).ToRawRisk();
            sqliteCommand.Parameters["SecondaryVulnerabilityIdentifier"].Value = ChildText(rule, "version");
            sqliteCommand.Parameters["VulnerabilityTitle"].Value = ChildText(rule, "title");
            sqliteCommand.Parameters["FixText"].Value = ChildText(rule, "fixtext");
            sqliteCommand.Parameters["CheckContent"].Value =
                Children(rule, "check").SelectMany(c => Children(c, "check-content")).FirstOrDefault()?.Value.Trim() ?? string.Empty;
            sqliteCommand.Parameters["IsActive"].Value = "True";

            Dictionary<string, string> description = ParseDescription(ChildText(rule, "description"));
            sqliteCommand.Parameters["VulnerabilityDescription"].Value = description["VulnDiscussion"];
            sqliteCommand.Parameters["FalsePositives"].Value = description["FalsePositives"];
            sqliteCommand.Parameters["FalseNegatives"].Value = description["FalseNegatives"];
            sqliteCommand.Parameters["IsDocumentable"].Value = description["Documentable"];
            sqliteCommand.Parameters["Mitigations"].Value = description["Mitigations"];
            sqliteCommand.Parameters["SeverityOverrideGuidance"].Value = description["SeverityOverrideGuidance"];
            sqliteCommand.Parameters["PotentialImpacts"].Value = description["PotentialImpacts"];
            sqliteCommand.Parameters["ThirdPartyTools"].Value = description["ThirdPartyTools"];
            sqliteCommand.Parameters["MitigationControl"].Value = description["MitigationControl"];

            switch (databaseInterface.CompareVulnerabilityVersions(sqliteCommand))
            {
                case "Record Not Found":
                case "Ingested Version Is Newer":
                    {
                        // A revised rule is a new library row; the old one stays while findings still point to it.
                        databaseInterface.InsertVulnerability(sqliteCommand);
                        databaseInterface.MapVulnerabilityToSource(sqliteCommand);
                        break;
                    }
                case "Identical Versions":
                    {
                        databaseInterface.UpdateVulnerabilityDates(sqliteCommand);
                        databaseInterface.MapVulnerabilityToSource(sqliteCommand);
                        break;
                    }
                default:
                    { break; } // the library already holds a newer revision of this rule
            }

            Revisions[ruleId] = sqliteCommand.Parameters["VulnerabilityVersion"].Value?.ToString() ?? string.Empty;

            List<string> ccis = Children(rule, "ident")
                .Where(i => ExtensionMethods.IsCciIdentSystem(i.Attribute("system")?.Value))
                .Select(i => i.Value.Trim().Replace("CCI-", string.Empty))
                .Where(c => !string.IsNullOrWhiteSpace(c))
                .Distinct()
                .ToList();
            foreach (string cci in ccis)
            {
                sqliteCommand.Parameters["CCI_Number"].Value = cci;
                databaseInterface.MapVulnerabilityToCci(sqliteCommand);
            }
            sqliteCommand.Parameters["CCI_Number"].Value = DBNull.Value;
        }

        /// <summary>
        /// "SV-254239r958396_rule" (manual) or "xccdf_mil.disa.stig_rule_SV-254239r958396_rule" (SCAP) becomes
        /// "SV-254239" and "958396", matching how checklists record the same rule.
        /// </summary>
        public static void SplitRuleId(string id, out string ruleId, out string revision)
        {
            id = id ?? string.Empty;
            Match match = Regex.Match(id, @"(SV-\d+)r(\d+)");
            if (match.Success)
            {
                ruleId = match.Groups[1].Value;
                revision = match.Groups[2].Value;
                return;
            }
            string stripped = Regex.Replace(Regex.Replace(id, @"^xccdf_[^_]+_rule_", string.Empty), @"_rule$", string.Empty);
            match = Regex.Match(stripped, @"^(.+?)r(\d+)$");
            ruleId = match.Success ? match.Groups[1].Value : stripped;
            revision = match.Success ? match.Groups[2].Value : string.Empty;
        }

        /// <summary>The DISA rule description is escaped markup: &lt;VulnDiscussion&gt;...&lt;/VulnDiscussion&gt;&lt;FalsePositives&gt;... .</summary>
        public static Dictionary<string, string> ParseDescription(string text)
        {
            Dictionary<string, string> values = DescriptionTags.ToDictionary(t => t, t => string.Empty);
            bool tagged = false;
            foreach (string tag in DescriptionTags)
            {
                Match match = Regex.Match(text ?? string.Empty, $"<{tag}>(.*?)</{tag}>", RegexOptions.Singleline);
                if (match.Success)
                {
                    values[tag] = System.Net.WebUtility.HtmlDecode(match.Groups[1].Value).Trim();
                    tagged = true;
                }
            }
            if (!tagged)
            { values["VulnDiscussion"] = System.Net.WebUtility.HtmlDecode(text ?? string.Empty).Trim(); }
            return values;
        }
    }
}
