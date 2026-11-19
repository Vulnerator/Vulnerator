using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;
using Vulnerator.Helper;
using Vulnerator.Model.DataAccess;

namespace Vulnerator.Model.BusinessLogic
{
    /// <summary>
    /// Reads XCCDF result files (DISA SCC and other SCAP scanners; XCCDF 1.1 or 1.2, any namespace prefix): the
    /// benchmark's rules go to the library, each TestResult becomes a host and its rule results become findings.
    /// </summary>
    public class XccdfReader
    {
        private readonly DatabaseInterface databaseInterface = new DatabaseInterface();
        private RawStigReader submitted;

        /// <summary>Rule results that could not be matched to a library rule in the last file read.</summary>
        public int UnmatchedResults { get; private set; }

        /// <summary>Findings written by the last file read.</summary>
        public int FindingsRead { get; private set; }

        public string ReadXccdfFile(Object.File file, string groupName)
        {
            UnmatchedResults = FindingsRead = 0;
            try
            {
                if (file.FilePath.IsFileInUse())
                {
                    LogWriter.LogError($"'{file.FileName}' is in use; please close any open instances and try again.");
                    return "Failed; File In Use";
                }

                XDocument document;
                XmlReaderSettings settings = new XmlReaderSettings { DtdProcessing = DtdProcessing.Ignore, XmlResolver = null, IgnoreComments = true };
                using (XmlReader xmlReader = XmlReader.Create(file.FilePath, settings))
                { document = XDocument.Load(xmlReader); }

                List<XElement> testResults = document.Descendants().Where(e => e.Name.LocalName == "TestResult").ToList();
                XElement benchmark = document.Descendants().FirstOrDefault(e => e.Name.LocalName == "Benchmark");
                if (testResults.Count == 0)
                {
                    if (document.Root != null && document.Root.Name.NamespaceName.Contains("oval"))
                    { return "Report Type (OVAL) Not Supported"; }
                    LogWriter.LogError($"'{file.FileName}' has no XCCDF TestResult. A benchmark without results belongs in the STIG library (Settings).");
                    return "Failed; No XCCDF Results";
                }
                if (benchmark == null)
                {
                    LogWriter.LogError($"'{file.FileName}' has XCCDF results but no benchmark to identify the STIG.");
                    return "Failed; No Benchmark In File";
                }

                if (DatabaseBuilder.sqliteConnection.State.ToString().Equals("Closed"))
                { DatabaseBuilder.sqliteConnection.Open(); }
                using (SQLiteTransaction sqliteTransaction = DatabaseBuilder.sqliteConnection.BeginTransaction())
                using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                {
                    databaseInterface.InsertParameterPlaceholders(sqliteCommand);
                    databaseInterface.InsertParsedFileSource(sqliteCommand, file);
                    RawStigReader stigReader = new RawStigReader();
                    stigReader.LoadBenchmark(sqliteCommand, benchmark, file.FileName, "XCCDF", false);
                    submitted = stigReader;
                    foreach (XElement testResult in testResults)
                    { ReadTestResult(sqliteCommand, testResult, stigReader.Revisions, file, groupName); }
                    sqliteTransaction.Commit();
                }
                if (UnmatchedResults > 0)
                { LogWriter.LogStatusUpdate($"'{file.FileName}': {UnmatchedResults} rule result(s) name rules that are not in the file's benchmark; skipped."); }
                return "Processed";
            }
            catch (Exception exception)
            {
                LogWriter.LogErrorWithDebug($"Unable to process XCCDF file '{file.FileName}'.", exception);
                return "Failed; See Log";
            }
            finally
            { DatabaseBuilder.sqliteConnection.Close(); }
        }

        private void ReadTestResult(SQLiteCommand sqliteCommand, XElement testResult, Dictionary<string, string> revisions,
            Object.File file, string groupName)
        {
            DateTime scanTime;
            if (!DateTime.TryParse(testResult.Attribute("end-time")?.Value ?? testResult.Attribute("start-time")?.Value,
                CultureInfo.InvariantCulture, DateTimeStyles.AssumeLocal, out scanTime))
            { scanTime = DateTime.Now; }
            string tool = testResult.Attribute("test-system")?.Value ?? string.Empty;

            // Asset: target-facts (urn:xccdf:fact:... or SCC's urn:scap:fact:...), then <target> / <target-address>.
            Dictionary<string, List<string>> facts = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
            foreach (XElement fact in RawStigReader.Children(testResult, "target-facts").SelectMany(f => RawStigReader.Children(f, "fact")))
            {
                string name = (fact.Attribute("name")?.Value ?? string.Empty).Split(':').Last();
                string value = fact.Value.Trim();
                if (string.IsNullOrWhiteSpace(value))
                { continue; }
                if (!facts.ContainsKey(name))
                { facts[name] = new List<string>(); }
                if (!facts[name].Contains(value))
                { facts[name].Add(value); }
            }
            List<string> ips = Fact(facts, "ipv4").Concat(Fact(facts, "ipv6"))
                .Concat(RawStigReader.Children(testResult, "target-address").Select(a => a.Value.Trim()))
                .Where(ip => !ExtensionMethods.IsAssetPlaceholder(ip) && ip != "127.0.0.1" && ip != "::1")
                .Distinct().ToList();
            List<string> macs = Fact(facts, "mac").Where(m => !ExtensionMethods.IsAssetPlaceholder(m)).Distinct().ToList();
            string fqdn = Fact(facts, "fqdn").FirstOrDefault(f => !ExtensionMethods.IsAssetPlaceholder(f));
            string hostName = new[] { Fact(facts, "host_name").FirstOrDefault(), RawStigReader.ChildText(testResult, "target"),
                    fqdn?.Split('.').First(), ips.FirstOrDefault() }
                .FirstOrDefault(h => !ExtensionMethods.IsAssetPlaceholder(h));
            if (hostName == null)
            {
                LogWriter.LogError($"'{file.FileName}': a TestResult has no host name, FQDN or IP address; its results were skipped.");
                return;
            }

            ResetHostParameters(sqliteCommand, file, groupName);
            sqliteCommand.Parameters["DiscoveredHostName"].Value = hostName.Trim();
            sqliteCommand.Parameters["DisplayedHostName"].Value = hostName.Trim();
            sqliteCommand.Parameters["FQDN"].Value = (object)fqdn ?? DBNull.Value;
            sqliteCommand.Parameters["ScanIP"].Value = (object)ips.FirstOrDefault() ?? DBNull.Value;
            sqliteCommand.Parameters["IsVirtualServer"].Value = "False";
            databaseInterface.InsertHardware(sqliteCommand);
            databaseInterface.MapHardwareToGroup(sqliteCommand);
            if (submitted != null)
            {
                // The benchmark release as the result file has it (interface version 3), per host.
                ImportFacts.RecordStigSubmission(sqliteCommand, "XCCDF", submitted.SubmittedSourceName, submitted.SubmittedVersion,
                    submitted.SubmittedRelease, submitted.SubmittedBenchmarkDate, hostName.Trim(), file.FileName);
            }
            foreach (string ip in ips)
            {
                sqliteCommand.Parameters["IP_Address"].Value = ip;
                databaseInterface.InsertAndMapIpAddress(sqliteCommand);
            }
            foreach (string mac in macs)
            {
                sqliteCommand.Parameters["MAC_Address"].Value = mac;
                databaseInterface.InsertAndMapMacAddress(sqliteCommand);
            }

            foreach (XElement ruleResult in RawStigReader.Children(testResult, "rule-result"))
            { ReadRuleResult(sqliteCommand, ruleResult, revisions, tool, scanTime); }

            // Score (SCC's default model), with who ran the scan.
            XElement identity = RawStigReader.Children(testResult, "identity").FirstOrDefault();
            XElement score = RawStigReader.Children(testResult, "score")
                .OrderByDescending(s => (s.Attribute("system")?.Value ?? string.Empty).EndsWith(":default")).FirstOrDefault();
            double scoreValue;
            if (score != null && double.TryParse(score.Value.Trim(), NumberStyles.Float, CultureInfo.InvariantCulture, out scoreValue))
            {
                string profile = RawStigReader.Children(testResult, "profile").FirstOrDefault()?.Attribute("idref")?.Value ?? string.Empty;
                sqliteCommand.Parameters["Score"].Value = (int)Math.Round(scoreValue);
                sqliteCommand.Parameters["ScanDate"].Value = scanTime;
                sqliteCommand.Parameters["ScanProfile"].Value = Regex.Replace(profile, @"^xccdf_[^_]+_profile_", string.Empty);
                sqliteCommand.Parameters["ScanUser"].Value = identity?.Value.Trim() ?? string.Empty;
                sqliteCommand.Parameters["UserIsPrivileged"].Value = identity?.Attribute("privileged")?.Value ?? string.Empty;
                sqliteCommand.Parameters["UserIsAuthenticated"].Value = identity?.Attribute("authenticated")?.Value ?? string.Empty;
                databaseInterface.InsertScapScore(sqliteCommand);
            }
        }

        private void ReadRuleResult(SQLiteCommand sqliteCommand, XElement ruleResult, Dictionary<string, string> revisions,
            string tool, DateTime scanTime)
        {
            string rawStatus = RawStigReader.ChildText(ruleResult, "result");
            if (rawStatus.Equals("notselected", StringComparison.OrdinalIgnoreCase))
            { return; } // not part of the profile that was scanned

            string ruleId;
            string revision;
            RawStigReader.SplitRuleId(ruleResult.Attribute("idref")?.Value, out ruleId, out revision);
            string libraryRevision;
            if (revisions.TryGetValue(ruleId, out libraryRevision))
            { revision = libraryRevision; }
            sqliteCommand.Parameters["UniqueVulnerabilityIdentifier"].Value = ruleId;
            sqliteCommand.Parameters["VulnerabilityVersion"].Value = revision;
            if (!RuleExists(sqliteCommand))
            {
                UnmatchedResults++;
                return;
            }

            StringBuilder output = new StringBuilder();
            output.AppendLine($"Tool: {tool}");
            output.AppendLine($"Time: {ruleResult.Attribute("time")?.Value ?? scanTime.ToString("s")}");
            output.Append($"Result: {rawStatus}");
            foreach (XElement message in RawStigReader.Children(ruleResult, "message"))
            {
                output.AppendLine();
                output.Append($"Message: {message.Value.Trim()}");
            }

            foreach (string name in new[] { "Comments", "FindingDetails", "SeverityOverride", "SeverityOverrideJustification",
                "TechnologyArea", "WebDB_Site", "WebDB_Instance", "Classification", "CVSS_EnvironmentalScore", "CVSS_EnvironmentalVector" })
            { sqliteCommand.Parameters[name].Value = DBNull.Value; }
            sqliteCommand.Parameters["Status"].Value = rawStatus.ToVulneratorStatus();
            sqliteCommand.Parameters["ToolGeneratedOutput"].Value = output.ToString();
            sqliteCommand.Parameters["FirstDiscovered"].Value = scanTime;
            sqliteCommand.Parameters["LastObserved"].Value = scanTime;
            sqliteCommand.Parameters["DeltaAnalysisIsRequired"].Value = "False";
            sqliteCommand.Parameters["FindingType"].Value = "XCCDF";
            sqliteCommand.Parameters["InstanceIdentifier"].Value =
                $"{sqliteCommand.Parameters["DiscoveredHostName"].Value}_{ruleId}r{revision}_XCCDF";

            // A newer revision of the rule closes this host's findings on the older revisions.
            List<string> outdated = databaseInterface.SelectOutdatedVulnerabilities(sqliteCommand, false);
            if (outdated.Count > 0)
            {
                SQLiteParameter updatedStatus = new SQLiteParameter("UpdatedStatus", "Completed");
                sqliteCommand.Parameters.Add(updatedStatus);
                SQLiteParameter findingId = sqliteCommand.Parameters["UniqueFinding_ID"];
                object previous = findingId.Value;
                foreach (string id in outdated)
                {
                    findingId.Value = id;
                    databaseInterface.UpdateUniqueFindingStatusById(sqliteCommand);
                }
                findingId.Value = previous;
                sqliteCommand.Parameters.Remove(updatedStatus);
            }
            databaseInterface.UpdateUniqueFinding(sqliteCommand);
            databaseInterface.InsertUniqueFinding(sqliteCommand);
            FindingsRead++;
        }

        private static bool RuleExists(SQLiteCommand sqliteCommand)
        {
            using (SQLiteCommand check = DatabaseBuilder.sqliteConnection.CreateCommand())
            {
                check.CommandText = "SELECT COUNT(*) FROM Vulnerabilities WHERE UniqueVulnerabilityIdentifier = @Id " +
                                    "AND VulnerabilityVersion IS @Version AND VulnerabilityRelease IS @Release;";
                check.Parameters.AddWithValue("@Id", sqliteCommand.Parameters["UniqueVulnerabilityIdentifier"].Value);
                check.Parameters.AddWithValue("@Version", sqliteCommand.Parameters["VulnerabilityVersion"].Value);
                check.Parameters.AddWithValue("@Release", sqliteCommand.Parameters["VulnerabilityRelease"].Value);
                return Convert.ToInt32(check.ExecuteScalar()) > 0;
            }
        }

        private static void ResetHostParameters(SQLiteCommand sqliteCommand, Object.File file, string groupName)
        {
            foreach (string name in new[] { "DiscoveredHostName", "DisplayedHostName", "FQDN", "NetBIOS", "ScanIP", "IP_Address", "MAC_Address",
                "Role", "OperatingSystem", "Score", "ScanDate", "ScanProfile", "ScanUser", "UserIsPrivileged", "UserIsAuthenticated" })
            { sqliteCommand.Parameters[name].Value = DBNull.Value; }
            sqliteCommand.Parameters["GroupName"].Value = string.IsNullOrWhiteSpace(groupName) ? "All" : groupName;
            sqliteCommand.Parameters["VulnerabilityRelease"].Value = string.Empty;
            // InsertParsedFileSource adds a second FindingSourceFileName parameter; both must carry the file name.
            foreach (SQLiteParameter parameter in sqliteCommand.Parameters)
            {
                if (parameter.ParameterName == "FindingSourceFileName")
                { parameter.Value = file.FileName; }
            }
        }

        private static IEnumerable<string> Fact(Dictionary<string, List<string>> facts, string name)
        {
            List<string> values;
            return facts.TryGetValue(name, out values) ? values : Enumerable.Empty<string>();
        }
    }
}
