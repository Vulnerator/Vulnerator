using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.Globalization;
using System.IO;
using System.Linq;
using Vulnerator.AddOns;
using Vulnerator.Model.BusinessLogic.Reports;
using Vulnerator.Model.DataAccess;

namespace Vulnerator.Model.AddOns
{
    /// <summary>
    /// The add-ons' view of the data: every call opens its own read-only connection (SQLite refuses writes on it), so
    /// add-ons never share or hold Vulnerator's connection and cannot change the database.
    /// </summary>
    internal sealed class AddOnData : IFindingsData
    {
        private const string HardwareQuery = @"
SELECT H.Hardware_ID, H.DisplayedHostName, H.FQDN, H.NetBIOS, H.ScanIP, H.OperatingSystem, H.Manufacturer,
       H.ModelNumber, H.SerialNumber, H.Role, H.IsVirtualServer,
       (SELECT GROUP_CONCAT(GroupName, ', ') FROM (SELECT DISTINCT G.GroupName FROM HardwareGroups HG
            JOIN Groups G ON HG.Group_ID = G.Group_ID WHERE HG.Hardware_ID = H.Hardware_ID ORDER BY G.GroupName)) AS GroupNames
FROM Hardware H
ORDER BY H.DisplayedHostName";

        // Newest loaded release per STIG: VulnerabilitySources keeps one row per name, version and release.
        private const string SubmissionsQuery = @"
SELECT SS.FindingType, SS.SourceName, SS.SourceVersion, SS.SourceRelease, SS.BenchmarkDate, SS.DiscoveredHostName,
       SS.FindingSourceFileName, SS.ImportedOn, H.Hardware_ID
FROM StigSubmissions SS
         LEFT JOIN Hardware H ON H.DiscoveredHostName = SS.DiscoveredHostName
ORDER BY SS.SourceName, SS.DiscoveredHostName, SS.ImportedOn";

        private const string SourceReleasesQuery = "SELECT SourceName, SourceVersion, SourceRelease FROM VulnerabilitySources";

        private const string LibraryImportQuery = "SELECT MAX(ImportedOn) FROM StigLibraryImports";

        private static readonly string[] ListSeparator = { ", " };

        public IReadOnlyList<FindingRecord> GetFindings()
        {
            using (SQLiteConnection connection = OpenReadOnly())
            {
                if (connection == null) return new FindingRecord[0];
                return ReportFindings.LoadAll(connection).Select(ToRecord).ToList().AsReadOnly();
            }
        }

        public IReadOnlyList<HardwareRecord> GetHardware()
        {
            using (SQLiteConnection connection = OpenReadOnly())
            {
                if (connection == null) return new HardwareRecord[0];
                List<HardwareRecord> hardware = new List<HardwareRecord>();
                using (SQLiteCommand command = connection.CreateCommand())
                {
                    command.CommandText = HardwareQuery;
                    using (SQLiteDataReader reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            hardware.Add(new HardwareRecord
                            {
                                Id = reader.IsDBNull(0) ? 0 : Convert.ToInt64(reader.GetValue(0), CultureInfo.InvariantCulture),
                                HostName = Text(reader, 1),
                                Fqdn = Text(reader, 2),
                                NetBios = Text(reader, 3),
                                IpAddress = Text(reader, 4),
                                OperatingSystem = Text(reader, 5),
                                Manufacturer = Text(reader, 6),
                                Model = Text(reader, 7),
                                SerialNumber = Text(reader, 8),
                                Role = Text(reader, 9),
                                IsVirtual = IsTrue(Text(reader, 10)),
                                Groups = List(Text(reader, 11))
                            });
                        }
                    }
                }
                return hardware.AsReadOnly();
            }
        }

        public IReadOnlyList<StigSubmissionRecord> GetStigSubmissions()
        {
            using (SQLiteConnection connection = OpenReadOnly())
            {
                if (connection == null) return new StigSubmissionRecord[0];
                Dictionary<string, StigRelease> latest = new Dictionary<string, StigRelease>(StringComparer.OrdinalIgnoreCase);
                using (SQLiteCommand command = connection.CreateCommand())
                {
                    command.CommandText = SourceReleasesQuery;
                    using (SQLiteDataReader reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            StigRelease release = StigRelease.Parse(Text(reader, 1), Text(reader, 2));
                            StigRelease known;
                            if (release != null && (!latest.TryGetValue(Text(reader, 0), out known) || release.CompareTo(known) > 0))
                            { latest[Text(reader, 0)] = release; }
                        }
                    }
                }

                List<StigSubmissionRecord> submissions = new List<StigSubmissionRecord>();
                using (SQLiteCommand command = connection.CreateCommand())
                {
                    command.CommandText = SubmissionsQuery;
                    using (SQLiteDataReader reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            string name = Text(reader, 1);
                            StigRelease submitted = StigRelease.Parse(Text(reader, 2), Text(reader, 3));
                            StigRelease newest;
                            latest.TryGetValue(name, out newest);
                            submissions.Add(new StigSubmissionRecord
                            {
                                FindingType = Text(reader, 0),
                                StigName = name,
                                SubmittedVersion = submitted != null ? submitted.ToString() : Text(reader, 2) + Text(reader, 3),
                                BenchmarkDate = DateValue(reader, 4),
                                LatestVersion = newest != null ? newest.ToString() : string.Empty,
                                IsOutdated = submitted != null && newest != null && submitted.CompareTo(newest) < 0,
                                HostName = Text(reader, 5),
                                SourceFile = Text(reader, 6),
                                ImportedOn = DateValue(reader, 7) ?? DateTime.MinValue,
                                HardwareId = reader.IsDBNull(8) ? (long?)null : Convert.ToInt64(reader.GetValue(8), CultureInfo.InvariantCulture)
                            });
                        }
                    }
                }
                return submissions.AsReadOnly();
            }
        }

        public IReadOnlyList<PoamItemRecord> GetPoamItems()
        {
            using (SQLiteConnection connection = OpenReadOnly())
            {
                if (connection == null) return new PoamItemRecord[0];
                List<EmassPoamFinding> findings;
                using (SQLiteCommand command = connection.CreateCommand())
                {
                    command.CommandText = OpenXmlEmassPoamReportCreator.UnfilteredQuery();
                    findings = OpenXmlEmassPoamReportCreator.ReadFindings(command);
                }
                return EmassPoamBuilder.Build(findings, OpenXmlEmassPoamReportCreator.CreateOptions())
                    .Select(item => new PoamItemRecord
                    {
                        Status = item.Status,
                        Summary = item.Summary,
                        SecurityChecks = item.SecurityChecks.AsReadOnly(),
                        Controls = item.Controls.AsReadOnly(),
                        RawSeverity = item.RawSeverity,
                        DateIdentified = item.DateIdentified,
                        ScheduledCompletion = item.ScheduledCompletion,
                        CompletionDate = item.CompletionDate,
                        DevicesAffected = item.DevicesAffected.AsReadOnly(),
                        Milestones = item.Milestones.Select(m => new PoamMilestoneRecord
                        {
                            Description = m.Description,
                            Status = m.Status,
                            ScheduledCompletion = m.ScheduledCompletion,
                            CompletionDate = m.CompletionDate
                        }).ToList().AsReadOnly()
                    }).ToList().AsReadOnly();
            }
        }

        public DateTime? GetLastStigLibraryImport()
        {
            using (SQLiteConnection connection = OpenReadOnly())
            {
                if (connection == null) return null;
                using (SQLiteCommand command = connection.CreateCommand())
                {
                    command.CommandText = LibraryImportQuery;
                    using (SQLiteDataReader reader = command.ExecuteReader())
                    { return reader.Read() ? DateValue(reader, 0) : null; }
                }
            }
        }

        /// <summary>A read-only connection to the current database, or null when no database is set up yet.</summary>
        private static SQLiteConnection OpenReadOnly()
        {
            string database = Properties.Settings.Default.Database;
            if (string.IsNullOrWhiteSpace(database) || database == "Undefined" || !File.Exists(database))
            { return null; }
            SQLiteConnection connection = new SQLiteConnection(DatabaseBuilder.ConnectionStringFor(database) + "Read Only=True;");
            connection.Open();
            return connection;
        }

        private static FindingRecord ToRecord(ReportFinding finding)
        {
            return new FindingRecord
            {
                FindingType = finding.FindingType,
                SourceName = finding.SourceName,
                SourceVersion = finding.SourceVersionRelease,
                HostName = finding.HostName,
                IpAddress = finding.IpAddress,
                SoftwareName = finding.SoftwareName,
                Asset = finding.Asset,
                VulnerabilityId = finding.GroupIdentifier,
                RuleId = finding.FullRuleIdentifier,
                Title = finding.Title,
                Severity = finding.Severity,
                RawSeverity = finding.RawSeverity,
                Status = ReportFinding.DisplayStatus(finding.Status),
                IsOpen = finding.IsOpen,
                MitigatedStatus = finding.MitigatedStatus,
                Description = finding.Description,
                CheckContent = finding.CheckContent,
                FixText = finding.FixText,
                FindingDetails = finding.FindingDetails,
                Comments = finding.Comments,
                SourceFile = finding.SourceFile,
                LastObserved = finding.LastObserved,
                Groups = List(finding.Groups),
                NistControls = List(finding.NistControls),
                Ccis = List(finding.Ccis),
                HardwareId = finding.HardwareId,
                FirstDiscovered = finding.FirstDiscovered,
                SeverityLevel = finding.SeverityLevel,
                RiskFactor = finding.RiskFactor,
                SecondarySeverity = finding.SecondarySeverity,
                References = List(finding.References)
            };
        }

        private static IReadOnlyList<string> List(string joined)
        {
            if (string.IsNullOrWhiteSpace(joined)) return new string[0];
            return joined.Split(ListSeparator, StringSplitOptions.RemoveEmptyEntries).Select(x => x.Trim()).ToList().AsReadOnly();
        }

        private static bool IsTrue(string value)
        {
            return value.Equals("true", StringComparison.OrdinalIgnoreCase) || value.Equals("yes", StringComparison.OrdinalIgnoreCase) ||
                   value.Equals("y", StringComparison.OrdinalIgnoreCase) || value == "1";
        }

        private static string Text(SQLiteDataReader reader, int ordinal)
        {
            return reader.IsDBNull(ordinal) ? string.Empty : Convert.ToString(reader.GetValue(ordinal), CultureInfo.InvariantCulture);
        }

        private static DateTime? DateValue(SQLiteDataReader reader, int ordinal)
        {
            if (reader.IsDBNull(ordinal)) return null;
            object value = reader.GetValue(ordinal);
            if (value is DateTime) return (DateTime)value;
            DateTime parsed;
            return DateTime.TryParse(Convert.ToString(value, CultureInfo.InvariantCulture), CultureInfo.InvariantCulture, DateTimeStyles.None, out parsed)
                ? parsed : (DateTime?)null;
        }

        /// <summary>A STIG version and release ("2" and "5", or "Release: 5 ...") that compare numerically.</summary>
        internal sealed class StigRelease : IComparable<StigRelease>
        {
            private StigRelease(int version, int release)
            {
                Version = version;
                Release = release;
            }

            public int Version { get; }
            public int Release { get; }

            public static StigRelease Parse(string version, string release)
            {
                System.Text.RegularExpressions.Match v = System.Text.RegularExpressions.Regex.Match(version ?? string.Empty, @"\d+");
                System.Text.RegularExpressions.Match r = System.Text.RegularExpressions.Regex.Match(release ?? string.Empty, @"\d+");
                // Non-STIG sources (an ACAS plugin feed "202610280000") are not STIG releases: ignore numbers out of range.
                int versionNumber, releaseNumber = 0;
                if (!v.Success || !int.TryParse(v.Value, NumberStyles.None, CultureInfo.InvariantCulture, out versionNumber)) return null;
                if (r.Success && !int.TryParse(r.Value, NumberStyles.None, CultureInfo.InvariantCulture, out releaseNumber)) return null;
                return new StigRelease(versionNumber, releaseNumber);
            }

            public int CompareTo(StigRelease other)
            {
                if (other == null) return 1;
                return Version != other.Version ? Version.CompareTo(other.Version) : Release.CompareTo(other.Release);
            }

            public override string ToString()
            {
                return "V" + Version.ToString(CultureInfo.InvariantCulture) + "R" + Release.ToString(CultureInfo.InvariantCulture);
            }
        }
    }
}
