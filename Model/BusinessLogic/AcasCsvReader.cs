using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using Vulnerator.Helper;

namespace Vulnerator.Model.BusinessLogic
{
    /// <summary>
    /// Reads vulnerability CSV exports (ACAS / Tenable.sc "Vulnerability Detail List", Nessus CSV). Columns are found by
    /// header name in any order. The rows are converted to .nessus content and read by <see cref="AcasNessusReader"/>,
    /// so CSV and .nessus imports treat hosts, statuses and software the same way.
    /// </summary>
    public class AcasCsvReader
    {
        private static readonly string[] PluginHeaders = { "Plugin", "Plugin ID", "PluginID" };
        private static readonly string[] IpHeaders = { "IP Address", "IP", "Host IP", "Host" };
        private static readonly string[] DnsHeaders = { "DNS Name", "FQDN", "Host FQDN", "DNS" };
        private static readonly string[] NetBiosHeaders = { "NetBIOS Name", "NetBIOS" };
        private static readonly string[] MacHeaders = { "MAC Address", "MAC" };
        private static readonly string[] NameHeaders = { "Plugin Name", "Name" };
        private static readonly string[] FamilyHeaders = { "Family", "Plugin Family" };
        private static readonly string[] ProtocolHeaders = { "Protocol" };
        private static readonly string[] PortHeaders = { "Port" };
        private static readonly string[] OutputHeaders = { "Plugin Text", "Plugin Output", "Output" };
        private static readonly string[] SynopsisHeaders = { "Synopsis" };
        private static readonly string[] DescriptionHeaders = { "Description" };
        private static readonly string[] SolutionHeaders = { "Solution" };
        private static readonly string[] RiskHeaders = { "Risk Factor", "Risk", "Severity" };
        private static readonly string[] StigSeverityHeaders = { "STIG Severity" };
        private static readonly string[] CvssBaseHeaders = { "CVSS V2 Base Score", "CVSS Base Score", "CVSS v2.0 Base Score" };
        private static readonly string[] CvssTemporalHeaders = { "CVSS V2 Temporal Score", "CVSS Temporal Score", "CVSS v2.0 Temporal Score" };
        private static readonly string[] CvssVectorHeaders = { "CVSS V2 Vector", "CVSS Vector", "CVSS v2.0 Vector" };
        private static readonly string[] CveHeaders = { "CVE" };
        private static readonly string[] BidHeaders = { "BID" };
        private static readonly string[] CpeHeaders = { "CPE" };
        private static readonly string[] CrossReferenceHeaders = { "Cross References", "XREF" };
        private static readonly string[] LastObservedHeaders = { "Last Observed", "Last Seen" };
        private static readonly string[] PluginPublishedHeaders = { "Plugin Publication Date" };
        private static readonly string[] PluginModifiedHeaders = { "Plugin Modification Date" };
        private static readonly string[] PatchPublishedHeaders = { "Patch Publication Date" };
        private static readonly string[] VersionHeaders = { "Version", "Plugin Version", "Script Version" };

        /// <summary>Rows read from the last file (excluding the header).</summary>
        public int RowsRead { get; private set; }

        public string ReadAcasCsvFile(Object.File file, string groupName)
        {
            RowsRead = 0;
            try
            {
                if (file.FilePath.IsFileInUse())
                {
                    LogWriter.LogError($"'{file.FileName}' is in use; please close any open instances and try again.");
                    return "Failed; File In Use";
                }
                List<string[]> rows = null;
                int header = -1;
                foreach (List<string[]> candidate in DelimitedText.ParseCandidates(DelimitedText.ReadAllText(file.FilePath)))
                {
                    header = candidate.FindIndex(r => DelimitedText.Find(r, PluginHeaders) >= 0 &&
                        (DelimitedText.Find(r, IpHeaders) >= 0 || DelimitedText.Find(r, DnsHeaders) >= 0));
                    if (header >= 0)
                    {
                        rows = candidate;
                        break;
                    }
                }
                if (rows == null)
                {
                    LogWriter.LogError($"'{file.FileName}' has no header row with a plugin column (\"Plugin\" or \"Plugin ID\") and a host column " +
                                       "(\"IP Address\", \"Host\" or \"DNS Name\").");
                    return "Failed; Not An ACAS CSV";
                }

                byte[] nessus = ConvertToNessus(rows, header);
                return new AcasNessusReader().ReadAcasNessus(file, groupName, () => new MemoryStream(nessus));
            }
            catch (Exception exception)
            {
                LogWriter.LogErrorWithDebug($"Unable to process ACAS CSV file '{file.FileName}'", exception);
                return "Failed; See Log";
            }
        }

        private byte[] ConvertToNessus(List<string[]> rows, int header)
        {
            string[] columns = rows[header];
            Func<string[], string[], string> get = (row, names) => DelimitedText.Cell(row, DelimitedText.Find(columns, names)).Trim();

            // One ReportHost per host, in file order.
            Dictionary<string, List<string[]>> hosts = new Dictionary<string, List<string[]>>();
            List<string> order = new List<string>();
            for (int i = header + 1; i < rows.Count; i++)
            {
                string[] row = rows[i];
                if (string.IsNullOrWhiteSpace(get(row, PluginHeaders)))
                { continue; }
                string key = string.Join("|", get(row, IpHeaders), get(row, DnsHeaders), get(row, NetBiosHeaders)).ToLowerInvariant();
                if (!hosts.ContainsKey(key))
                {
                    hosts[key] = new List<string[]>();
                    order.Add(key);
                }
                hosts[key].Add(row);
                RowsRead++;
            }

            using (MemoryStream buffer = new MemoryStream())
            {
                XmlWriterSettings settings = new XmlWriterSettings { Encoding = new UTF8Encoding(false), Indent = false };
                using (XmlWriter writer = XmlWriter.Create(buffer, settings))
                {
                    writer.WriteStartElement("NessusClientData_v2");
                    writer.WriteStartElement("Report");
                    writer.WriteAttributeString("name", "ACAS CSV");
                    foreach (string key in order)
                    {
                        List<string[]> hostRows = hosts[key];
                        string[] first = hostRows[0];
                        string ip = get(first, IpHeaders);
                        string dns = get(first, DnsHeaders);
                        string netBios = get(first, NetBiosHeaders);
                        // "NetBIOS Name" is often DOMAIN\HOST.
                        if (netBios.Contains("\\"))
                        { netBios = netBios.Split('\\').Last(); }
                        DateTime lastObserved = hostRows.Select(r => ParseDate(get(r, LastObservedHeaders))).Where(d => d.HasValue)
                            .Select(d => d.Value).DefaultIfEmpty(DateTime.Now).Max();

                        writer.WriteStartElement("ReportHost");
                        writer.WriteAttributeString("name", Clean(!string.IsNullOrWhiteSpace(ip) ? ip : dns));
                        writer.WriteStartElement("HostProperties");
                        Tag(writer, "HOST_END", lastObserved.ToString("ddd MMM d HH:mm:ss yyyy", CultureInfo.InvariantCulture));
                        Tag(writer, "host-ip", ip);
                        Tag(writer, "host-fqdn", dns);
                        Tag(writer, "netbios-name", netBios);
                        Tag(writer, "mac-address", string.Join("\n", hostRows.Select(r => get(r, MacHeaders))
                            .SelectMany(m => m.Split(new[] { ',', ';', ' ', '\n' }, StringSplitOptions.RemoveEmptyEntries)).Distinct()));
                        writer.WriteEndElement();

                        foreach (string[] row in hostRows)
                        { WriteReportItem(writer, row, get); }
                        writer.WriteEndElement();
                    }
                    writer.WriteEndElement();
                    writer.WriteEndElement();
                }
                return buffer.ToArray();
            }
        }

        private static void WriteReportItem(XmlWriter writer, string[] row, Func<string[], string[], string> get)
        {
            string risk = get(row, RiskHeaders);
            if (risk.Equals("Info", StringComparison.OrdinalIgnoreCase) || risk.Equals("Informational", StringComparison.OrdinalIgnoreCase) || risk == string.Empty)
            { risk = "None"; }
            writer.WriteStartElement("ReportItem");
            writer.WriteAttributeString("port", Clean(DefaultIfBlank(get(row, PortHeaders), "0")));
            writer.WriteAttributeString("svc_name", string.Empty);
            writer.WriteAttributeString("protocol", Clean(DefaultIfBlank(get(row, ProtocolHeaders), "tcp").ToLowerInvariant()));
            writer.WriteAttributeString("pluginID", Clean(get(row, PluginHeaders)));
            writer.WriteAttributeString("pluginName", Clean(get(row, NameHeaders)));
            writer.WriteAttributeString("pluginFamily", Clean(get(row, FamilyHeaders)));

            Tag(writer, "description", get(row, DescriptionHeaders));
            Tag(writer, "synopsis", get(row, SynopsisHeaders));
            Tag(writer, "solution", get(row, SolutionHeaders));
            Tag(writer, "risk_factor", risk);
            Tag(writer, "stig_severity", get(row, StigSeverityHeaders));
            Tag(writer, "cvss_base_score", get(row, CvssBaseHeaders));
            Tag(writer, "cvss_temporal_score", get(row, CvssTemporalHeaders));
            Tag(writer, "cvss_vector", get(row, CvssVectorHeaders));
            Tag(writer, "plugin_publication_date", NessusDate(get(row, PluginPublishedHeaders)));
            Tag(writer, "plugin_modification_date", NessusDate(get(row, PluginModifiedHeaders)));
            Tag(writer, "patch_publication_date", NessusDate(get(row, PatchPublishedHeaders)));
            // Tenable.sc writes "$Revision: 1.23 $" or "1.23"; the .nessus reader expects the number.
            Match version = Regex.Match(get(row, VersionHeaders), @"\d+(\.\d+)*");
            Tag(writer, "script_version", version.Success ? version.Value : string.Empty);
            foreach (string cve in Split(get(row, CveHeaders)))
            { Tag(writer, "cve", cve); }
            foreach (string bid in Split(get(row, BidHeaders)))
            { Tag(writer, "bid", bid); }
            foreach (string cpe in Split(get(row, CpeHeaders)))
            { Tag(writer, "cpe", cpe); }
            // "IAVA #2020-A-0001, CWE #79" becomes xref "IAVA:2020-A-0001", as in .nessus.
            foreach (string reference in get(row, CrossReferenceHeaders).Split(new[] { ',', '\n' }, StringSplitOptions.RemoveEmptyEntries))
            {
                string[] parts = reference.Split(new[] { '#', ':' }, 2);
                if (parts.Length == 2 && !string.IsNullOrWhiteSpace(parts[0]) && !string.IsNullOrWhiteSpace(parts[1]))
                { Tag(writer, "xref", $"{parts[0].Trim()}:{parts[1].Trim()}"); }
            }
            // Tenable.sc prefixes the output with "Plugin Output: ".
            string output = get(row, OutputHeaders);
            if (output.StartsWith("Plugin Output:", StringComparison.OrdinalIgnoreCase))
            { output = output.Substring("Plugin Output:".Length).TrimStart(); }
            Tag(writer, "plugin_output", output);
            writer.WriteEndElement();
        }

        private static void Tag(XmlWriter writer, string name, string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            { return; }
            if (name == "HOST_END" || name.Contains("-") || name == "mac-address")
            {
                writer.WriteStartElement("tag");
                writer.WriteAttributeString("name", name);
                writer.WriteString(Clean(value));
                writer.WriteEndElement();
                return;
            }
            writer.WriteElementString(name, Clean(value));
        }

        private static IEnumerable<string> Split(string value)
        { return value.Split(new[] { ',', ';', ' ', '\n' }, StringSplitOptions.RemoveEmptyEntries).Select(v => v.Trim()).Distinct(); }

        private static string DefaultIfBlank(string value, string fallback)
        { return string.IsNullOrWhiteSpace(value) ? fallback : value; }

        /// <summary>Drops characters XML cannot carry (control characters in plugin output).</summary>
        private static string Clean(string value)
        { return new string((value ?? string.Empty).Where(c => XmlConvert.IsXmlChar(c) || char.IsSurrogate(c)).ToArray()); }

        /// <summary>"Sep 15, 2026 10:00:00 UTC", "2026/09/15" or "2026-09-15"; the time zone suffix is ignored.</summary>
        private static DateTime? ParseDate(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
            { return null; }
            string trimmed = Regex.Replace(value.Trim(), @"\s+[A-Z]{2,5}$", string.Empty);
            DateTime parsed;
            string[] formats = { "MMM d, yyyy HH:mm:ss", "MMM d, yyyy", "yyyy/MM/dd", "yyyy-MM-dd", "yyyy-MM-dd HH:mm:ss", "M/d/yyyy", "M/d/yyyy H:mm", "M/d/yyyy h:mm:ss tt" };
            if (DateTime.TryParseExact(trimmed, formats, CultureInfo.InvariantCulture, DateTimeStyles.AllowWhiteSpaces, out parsed) ||
                DateTime.TryParse(trimmed, CultureInfo.InvariantCulture, DateTimeStyles.AllowWhiteSpaces, out parsed))
            { return parsed; }
            return null;
        }

        private static string NessusDate(string value)
        {
            DateTime? parsed = ParseDate(value);
            return parsed.HasValue ? parsed.Value.ToString("yyyy/MM/dd", CultureInfo.InvariantCulture) : string.Empty;
        }
    }
}
