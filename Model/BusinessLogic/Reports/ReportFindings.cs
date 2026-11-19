using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.Globalization;
using System.Linq;
using Vulnerator.Helper;
using Vulnerator.Model.DataAccess;

namespace Vulnerator.Model.BusinessLogic.Reports
{
    /// <summary>One finding (one host or software item and one rule / plugin) as the summary reports use it.</summary>
    public class ReportFinding
    {
        public string FindingType { get; set; }
        public string SourceName { get; set; }
        public string SourceVersion { get; set; }
        public string SourceRelease { get; set; }
        public string HostName { get; set; }
        public string IpAddress { get; set; }
        public string SoftwareName { get; set; }
        public string GroupIdentifier { get; set; }
        public string RuleIdentifier { get; set; }
        public string RuleVersion { get; set; }
        public string SecondaryIdentifier { get; set; }
        public string Title { get; set; }
        public string RawSeverity { get; set; }
        public string SeverityOverride { get; set; }
        public string Status { get; set; }
        public string MitigatedStatus { get; set; }
        public string Description { get; set; }
        public string CheckContent { get; set; }
        public string FixText { get; set; }
        public string FindingDetails { get; set; }
        public string Comments { get; set; }
        public string SourceFile { get; set; }
        public string Groups { get; set; }
        public string NistControls { get; set; }
        public string Ccis { get; set; }
        public DateTime? LastObserved { get; set; }
        public DateTime? FirstDiscovered { get; set; }
        public long? HardwareId { get; set; }
        public long? SoftwareId { get; set; }

        /// <summary>The Nessus risk factor (Critical, High, Medium, Low, None) when the scan was imported by 7.4.0-beta.3 or later.</summary>
        public string RiskFactor { get; set; }

        /// <summary>The second severity the source gives (Nessus: DISA's stig_severity, for example for IAVMs).</summary>
        public string SecondarySeverity { get; set; }

        /// <summary>"TYPE:value" references such as "IAVA:2026-A-0001" or "CVE:CVE-2026-0001", comma-separated.</summary>
        public string References { get; set; }

        /// <summary>The asset name shown in reports: the host, or the software item for software-only findings.</summary>
        public string Asset => !string.IsNullOrWhiteSpace(HostName) ? HostName : (SoftwareName ?? string.Empty);

        /// <summary>The severity used for counting: the override when one is set (I, II, III or IV), else the raw value.</summary>
        public string Severity
        {
            get
            {
                string over = NormalizeSeverity(SeverityOverride);
                return !string.IsNullOrEmpty(over) ? over : NormalizeSeverity(RawSeverity);
            }
        }

        /// <summary>The rule ID with its revision as DISA writes it (SV-12345r2_rule).</summary>
        public string FullRuleIdentifier
        {
            get
            {
                if (string.IsNullOrWhiteSpace(RuleVersion) || string.IsNullOrWhiteSpace(RuleIdentifier) || RuleIdentifier.Contains("r" + RuleVersion))
                { return RuleIdentifier ?? string.Empty; }
                return RuleIdentifier.EndsWith("_rule", StringComparison.Ordinal)
                    ? RuleIdentifier.Substring(0, RuleIdentifier.Length - 5) + "r" + RuleVersion + "_rule"
                    : RuleIdentifier + "r" + RuleVersion + "_rule";
            }
        }

        /// <summary>"V2R3" style STIG version, when the source has one.</summary>
        public string SourceVersionRelease
        {
            get
            {
                string version = (SourceVersion ?? string.Empty).Trim();
                string release = (SourceRelease ?? string.Empty).Trim();
                if (version.Length == 0 && release.Length == 0) return string.Empty;
                if (release.StartsWith("Release:", StringComparison.OrdinalIgnoreCase))
                { release = release.Substring(8).Trim().Split(' ')[0]; }
                return "V" + version.TrimStart('V', 'v') + (release.Length > 0 ? "R" + release.TrimStart('R', 'r') : string.Empty);
            }
        }

        /// <summary>
        /// The eMASS five-level severity: Very High, High, Moderate, Low or Very Low. A severity override wins (by CAT);
        /// else the Nessus risk factor (Critical = Very High); else the CAT (I = High, II = Moderate, III = Low, IV = Very Low).
        /// </summary>
        public string SeverityLevel
        {
            get
            {
                string over = NormalizeSeverity(SeverityOverride);
                if (!string.IsNullOrEmpty(over)) return CatToLevel(over);
                switch ((RiskFactor ?? string.Empty).Trim().ToUpperInvariant())
                {
                    case "CRITICAL": return "Very High";
                    case "HIGH": return "High";
                    case "MEDIUM": return "Moderate";
                    case "LOW": return "Low";
                    case "NONE": case "INFO": case "INFORMATIONAL": return "Very Low";
                }
                return CatToLevel(NormalizeSeverity(RawSeverity));
            }
        }

        public static string CatToLevel(string cat)
        {
            switch (cat)
            {
                case "I": return "High";
                case "II": return "Moderate";
                case "III": return "Low";
                case "IV": return "Very Low";
                default: return string.Empty;
            }
        }

        public bool IsOpen => Status == "Ongoing";

        /// <summary>The checklist wording for a stored status.</summary>
        public static string DisplayStatus(string status)
        {
            switch (status)
            {
                case "Ongoing": return "Open";
                case "Completed": return "Not a Finding";
                case null: return string.Empty;
                default: return status;
            }
        }

        public static string NormalizeSeverity(string value)
        {
            if (string.IsNullOrWhiteSpace(value)) return string.Empty;
            string v = value.Trim().ToUpperInvariant();
            if (v.StartsWith("CAT ", StringComparison.Ordinal)) v = v.Substring(4).Trim();
            switch (v)
            {
                case "I": case "HIGH": case "CRITICAL": return "I";
                case "II": case "MEDIUM": return "II";
                case "III": case "LOW": return "III";
                case "IV": case "INFO": case "INFORMATIONAL": case "NONE": return "IV";
                default: return v;
            }
        }
    }

    /// <summary>
    /// Loads the findings a report covers, one row per finding, with the report's filters from the Reporting page
    /// (finding type, group, severity, status; each can follow the Global values). The group RMF override is not applied.
    /// </summary>
    public static class ReportFindings
    {
        private const string Query = @"
SELECT FT.FindingType,
       VS.SourceName, VS.SourceVersion, VS.SourceRelease,
       H.DisplayedHostName, H.ScanIP,
       S.DisplayedSoftwareName,
       V.VulnerabilityGroupIdentifier, V.UniqueVulnerabilityIdentifier, V.VulnerabilityVersion,
       V.SecondaryVulnerabilityIdentifier, V.VulnerabilityTitle, V.PrimaryRawRiskIndicator,
       UF.SeverityOverride, UF.Status, MOC.MitigatedStatus,
       V.VulnerabilityDescription, V.CheckContent, V.FixText,
       UF.FindingDetails, UF.Comments, UFSF.FindingSourceFileName, UF.LastObserved,
       (SELECT GROUP_CONCAT(GroupName, ', ') FROM (SELECT DISTINCT G.GroupName FROM HardwareGroups HG2
            JOIN Groups G ON HG2.Group_ID = G.Group_ID WHERE HG2.Hardware_ID = UF.Hardware_ID ORDER BY G.GroupName)) AS GroupNames,
       (SELECT GROUP_CONCAT(Control, ', ') FROM (SELECT DISTINCT NC.ControlFamily || '-' || NC.ControlNumber ||
            COALESCE('(' || NC.ControlEnhancement || ')', '') AS Control
            FROM VulnerabilitiesCCIs VC JOIN NIST_ControlsCCIs NCC ON VC.CCI_ID = NCC.CCI_ID
            JOIN NIST_Controls NC ON NCC.NIST_Control_ID = NC.NIST_Control_ID
            WHERE VC.Vulnerability_ID = UF.Vulnerability_ID ORDER BY 1)) AS NistControls,
       (SELECT GROUP_CONCAT(CCI_Number, ', ') FROM (SELECT DISTINCT CI.CCI_Number FROM VulnerabilitiesCCIs VC
            JOIN CCIs CI ON VC.CCI_ID = CI.CCI_ID WHERE VC.Vulnerability_ID = UF.Vulnerability_ID ORDER BY 1)) AS CCIs,
       UF.FirstDiscovered, UF.Hardware_ID, UF.Software_ID, ARF.RiskFactor, V.SecondaryRawRiskIndicator,
       (SELECT GROUP_CONCAT(Ref, ', ') FROM (SELECT DISTINCT VR.ReferenceType || ':' || VR.Reference AS Ref
            FROM VulnerabilitiesVulnerabilityReferences VVR JOIN VulnerabilityReferences VR ON VVR.Reference_ID = VR.Reference_ID
            WHERE VVR.Vulnerability_ID = UF.Vulnerability_ID AND VR.Reference IS NOT NULL ORDER BY 1)) AS Refs
FROM UniqueFindings UF
         LEFT JOIN FindingTypes FT ON UF.FindingType_ID = FT.FindingType_ID
         LEFT JOIN Vulnerabilities V ON UF.Vulnerability_ID = V.Vulnerability_ID
         LEFT JOIN VulnerabilitySources VS ON UF.VulnerabilitySource_ID = VS.VulnerabilitySource_ID
         LEFT JOIN Hardware H ON UF.Hardware_ID = H.Hardware_ID
         LEFT JOIN Software S ON UF.Software_ID = S.Software_ID
         LEFT JOIN UniqueFindingsSourceFiles UFSF ON UF.FindingSourceFile_ID = UFSF.FindingSourceFile_ID
         LEFT JOIN MitigationsOrConditions MOC ON UF.MitigationOrCondition_ID = MOC.MitigationOrCondition_ID
         LEFT JOIN AcasRiskFactors ARF ON FT.FindingType = 'ACAS' AND ARF.UniqueVulnerabilityIdentifier = V.UniqueVulnerabilityIdentifier
/*WHERE*/
ORDER BY VS.SourceName, H.DisplayedHostName, V.VulnerabilityGroupIdentifier, V.UniqueVulnerabilityIdentifier";

        /// <summary>The findings for a report, optionally limited to some finding types (for example CKL and XCCDF).</summary>
        public static List<ReportFinding> Load(string displayedReportName, params string[] onlyFindingTypes)
        {
            bool wasOpen = DatabaseBuilder.sqliteConnection.State == System.Data.ConnectionState.Open;
            if (!wasOpen)
            { DatabaseBuilder.sqliteConnection.Open(); }
            try
            {
                List<string> conditions = new List<string>();
                string findingTypes = Filter(displayedReportName, (f, c, n) => f.FindingType(c, n));
                if (!string.IsNullOrWhiteSpace(findingTypes)) conditions.Add(findingTypes.Trim());
                string groups = Filter(displayedReportName, (f, c, n) => f.Group(c, n));
                if (!string.IsNullOrWhiteSpace(groups))
                { conditions.Add("EXISTS (SELECT 1 FROM HardwareGroups HG WHERE HG.Hardware_ID = UF.Hardware_ID AND " + groups.Trim() + ")"); }
                string severities = Filter(displayedReportName, (f, c, n) => f.Severity(c, n));
                if (!string.IsNullOrWhiteSpace(severities)) conditions.Add("(V.PrimaryRawRiskIndicator " + severities + ")");
                string statuses = Filter(displayedReportName, (f, c, n) => f.Status(c, n));
                if (!string.IsNullOrWhiteSpace(statuses)) conditions.Add("(UF.Status " + statuses + " OR MOC.MitigatedStatus " + statuses + ")");

                List<ReportFinding> findings;
                using (SQLiteCommand command = DatabaseBuilder.sqliteConnection.CreateCommand())
                {
                    if (onlyFindingTypes != null && onlyFindingTypes.Length > 0)
                    {
                        List<string> names = new List<string>();
                        for (int i = 0; i < onlyFindingTypes.Length; i++)
                        {
                            names.Add("@OnlyType" + i);
                            command.Parameters.AddWithValue("@OnlyType" + i, onlyFindingTypes[i]);
                        }
                        conditions.Add("FT.FindingType IN (" + string.Join(", ", names) + ")");
                    }
                    command.CommandText = Query.Replace("/*WHERE*/", conditions.Count == 0 ? string.Empty : "WHERE " + string.Join(Environment.NewLine + "  AND ", conditions));
                    findings = Read(command);
                }
                LogWriter.LogStatusUpdate($"{displayedReportName}: {findings.Count} finding(s) after the report filters.");
                return findings;
            }
            finally
            {
                if (!wasOpen)
                { DatabaseBuilder.sqliteConnection.Close(); }
            }
        }

        /// <summary>
        /// Every finding without the Reporting filters, read through the given connection (add-ons use a separate
        /// read-only connection).
        /// </summary>
        public static List<ReportFinding> LoadAll(SQLiteConnection connection)
        {
            using (SQLiteCommand command = connection.CreateCommand())
            {
                command.CommandText = Query.Replace("/*WHERE*/", string.Empty);
                return Read(command);
            }
        }

        private static List<ReportFinding> Read(SQLiteCommand command)
        {
            List<ReportFinding> findings = new List<ReportFinding>();
            using (SQLiteDataReader reader = command.ExecuteReader())
            {
                while (reader.Read())
                {
                    findings.Add(new ReportFinding
                    {
                        FindingType = Text(reader, 0),
                        SourceName = Text(reader, 1),
                        SourceVersion = Text(reader, 2),
                        SourceRelease = Text(reader, 3),
                        HostName = Text(reader, 4),
                        IpAddress = Text(reader, 5),
                        SoftwareName = Text(reader, 6),
                        GroupIdentifier = Text(reader, 7),
                        RuleIdentifier = Text(reader, 8),
                        RuleVersion = Text(reader, 9),
                        SecondaryIdentifier = Text(reader, 10),
                        Title = Text(reader, 11),
                        RawSeverity = Text(reader, 12),
                        SeverityOverride = Text(reader, 13),
                        Status = Text(reader, 14),
                        MitigatedStatus = Text(reader, 15),
                        Description = Text(reader, 16),
                        CheckContent = Text(reader, 17),
                        FixText = Text(reader, 18),
                        FindingDetails = Text(reader, 19),
                        Comments = Text(reader, 20),
                        SourceFile = Text(reader, 21),
                        LastObserved = DateValue(reader, 22),
                        Groups = Text(reader, 23),
                        NistControls = Text(reader, 24),
                        Ccis = Text(reader, 25),
                        FirstDiscovered = DateValue(reader, 26),
                        HardwareId = LongValue(reader, 27),
                        SoftwareId = LongValue(reader, 28),
                        RiskFactor = Text(reader, 29),
                        SecondarySeverity = Text(reader, 30),
                        References = Text(reader, 31)
                    });
                }
            }
            return findings;
        }

        // Each filter on its own command: FilterTextCreator adds a @DisplayedReportName parameter on every call.
        private static string Filter(string reportName, Func<FilterTextCreator, SQLiteCommand, string, string> filter)
        {
            using (SQLiteCommand command = DatabaseBuilder.sqliteConnection.CreateCommand())
            {
                command.Parameters.Add(new SQLiteParameter("UserName", DatabaseBuilder.CurrentUser()));
                return filter(new FilterTextCreator(), command, reportName);
            }
        }

        private static string Text(SQLiteDataReader reader, int ordinal)
        {
            return reader.IsDBNull(ordinal) ? string.Empty : Convert.ToString(reader.GetValue(ordinal), CultureInfo.InvariantCulture);
        }

        private static long? LongValue(SQLiteDataReader reader, int ordinal)
        {
            if (reader.IsDBNull(ordinal)) return null;
            long value;
            return long.TryParse(Convert.ToString(reader.GetValue(ordinal), CultureInfo.InvariantCulture), NumberStyles.Integer,
                CultureInfo.InvariantCulture, out value) ? value : (long?)null;
        }

        private static DateTime? DateValue(SQLiteDataReader reader, int ordinal)
        {
            if (reader.IsDBNull(ordinal)) return null;
            object value = reader.GetValue(ordinal);
            if (value is DateTime) return (DateTime)value;
            if (value is long) return new DateTime((long)value);
            DateTime parsed;
            return DateTime.TryParse(Convert.ToString(value, CultureInfo.InvariantCulture), CultureInfo.InvariantCulture, DateTimeStyles.None, out parsed)
                ? parsed : (DateTime?)null;
        }
    }
}
