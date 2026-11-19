using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.Globalization;
using System.Linq;
using System.Reflection;
using System.Text.RegularExpressions;
using Vulnerator.Helper;
using Vulnerator.Model.DataAccess;

namespace Vulnerator.Model.BusinessLogic.Reports
{
    /// <summary>
    /// Writes an eMASS-importable POA&amp;M laid out like the eMASS "POAMImportTemplate_RMF_Standard"
    /// template: header block in rows 2-6, the 32 template columns in row 7 (column A hidden), items from
    /// row 8, with each additional milestone on its own row. Items are built by <see cref="EmassPoamBuilder"/>.
    /// </summary>
    public class OpenXmlEmassPoamReportCreator
    {
        public const string ReportName = "eMASS-Importable POA&M";

        /// <summary>Row 7 headers, columns B through AG, exactly as in the eMASS template.</summary>
        public static readonly string[] ColumnHeaders =
        {
            "POA&M Item ID", "POA&M Status", "Summary", "Vulnerability Description", "Controls / APs",
            "Security Checks", "Date Identified", "POA&M Scheduled Completion Date",
            "POA&M Requested Risk Accepted Expiration Date", "POA&M Completion Date", "Milestone ID",
            "Milestone Status", "Milestone Description", "Milestone Status Comments",
            "Milestone Scheduled Completion Date", "Milestone Completion Date", "Identification Source",
            "Identification Source Details", "Office/Org", "Comments", "Raw Severity", "Devices Affected",
            "Mitigations", "Severity", "Relevance of Threat", "Likelihood", "Impact", "Impact Description",
            "Residual Risk Level", "Recommendations", "Resources", "Actual Cost"
        };

        private const int FirstColumn = 2;   // column B
        private const int HeaderRow = 7;

        private readonly DdlReader _ddlReader = new DdlReader();
        private readonly Assembly _assembly = Assembly.GetExecutingAssembly();
        private const string StoredProcedureBase = "Vulnerator.Resources.DdlFiles.StoredProcedures.";

        public string CreateEmassPoam(string fileName)
        {
            try
            {
                if (!DatabaseBuilder.sqliteConnection.State.ToString().Equals("Open"))
                { DatabaseBuilder.sqliteConnection.Open(); }

                LogWriter.LogStatusUpdate("Reading POA&M findings.");
                List<EmassPoamFinding> findings = ReadFindings();
                List<EmassPoamItem> items = EmassPoamBuilder.Build(findings, CreateOptions());
                LogWriter.LogStatusUpdate($"Writing {items.Count} POA&M item(s) from {findings.Count} finding row(s).");
                Write(fileName, items);
                return "Excel report creation successful";
            }
            catch (Exception exception)
            {
                LogWriter.LogErrorWithDebug($"Unable to create '{fileName}' (eMASS POA&M).", exception);
                return "Excel report creation failed - see log for details";
            }
            finally
            {
                DatabaseBuilder.sqliteConnection.Close();
            }
        }

        public static EmassPoamOptions CreateOptions()
        {
            Properties.Settings settings = Properties.Settings.Default;
            EmassPoamOptions options = new EmassPoamOptions { ExportDate = DateTime.Today };
            // Office/Org: the setting, else "Organization, Name, Phone, Email" from the contact settings,
            // else the processor's placeholder (PD-03).
            string officeOrg = string.IsNullOrWhiteSpace(settings.EmassOfficeOrg)
                ? EmassPoamBuilder.ComposeOfficeOrg(settings.Organization, settings.Name, settings.Phone, settings.Email)
                : settings.EmassOfficeOrg.Trim();
            if (!string.IsNullOrWhiteSpace(officeOrg))
            { options.OfficeOrg = officeOrg; }
            if (!string.IsNullOrWhiteSpace(settings.EmassResourcesRequired))
            { options.Resources = settings.EmassResourcesRequired.Trim(); }
            if (!string.IsNullOrWhiteSpace(settings.EmassIdentificationSource))
            { options.IdentificationSource = settings.EmassIdentificationSource.Trim(); }
            if (!string.IsNullOrWhiteSpace(settings.EmassMitigationPlaceholder))
            { options.MitigationPlaceholder = settings.EmassMitigationPlaceholder.Trim(); }
            options.DefaultMilestone = settings.EmassDefaultMilestone ?? string.Empty;
            options.SetCompletionDays(settings.EmassScheduledCompletionDays);
            return options;
        }

        public static void Write(string fileName, List<EmassPoamItem> items)
        {
            Properties.Settings settings = Properties.Settings.Default;
            double[] widths = new double[33];
            for (int i = 0; i < widths.Length; i++)
            { widths[i] = 18; }
            widths[0] = 2;      // A (hidden)
            widths[3] = 40;     // D Summary
            widths[4] = 60;     // E Vulnerability Description
            widths[13] = 40;    // N Milestone Description
            widths[20] = 50;    // U Comments
            widths[22] = 30;    // W Devices Affected
            widths[23] = 40;    // X Mitigations
            widths[30] = 40;    // AE Recommendations

            using (EmassWorkbookWriter workbook = new EmassWorkbookWriter(fileName, settings.EmassClassificationMarking))
            {
                EmassSheet sheet = workbook.AddSheet("POA&M", widths, new[] { 1 });
                sheet.HideRow(1);
                WriteHeaderBlock(sheet, settings);
                for (int i = 0; i < ColumnHeaders.Length; i++)
                { sheet.Text(HeaderRow, FirstColumn + i, ColumnHeaders[i], EmassWorkbookWriter.StyleColumnHeader); }

                int row = HeaderRow + 1;
                foreach (EmassPoamItem item in items)
                { row = WriteItem(sheet, row, item); }
                sheet.Save();
            }
        }

        private static void WriteHeaderBlock(EmassSheet sheet, Properties.Settings settings)
        {
            // Labels in A:E, values in F:M; right-hand blocks at N/O:P and Q/R:T, as in the template.
            string[,] left =
            {
                { "Date Exported:", DateTime.Today.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) },
                { "Exported By:", settings.Name },
                { "CC/S/A/FA:", settings.EmassCcsafa },
                { "System / Project Name:", settings.EmassSystemName },
                { "DoW IT Registration No:", settings.EmassItRegistrationNumber }
            };
            for (int i = 0; i < left.GetLength(0); i++)
            {
                int row = 2 + i;
                sheet.Text(row, 1, left[i, 0], EmassWorkbookWriter.StyleLabel);
                sheet.Text(row, 6, left[i, 1], EmassWorkbookWriter.StyleHeaderValue);
                sheet.Merge("A" + row + ":E" + row);
                sheet.Merge("F" + row + ":M" + row);
            }

            sheet.Text(2, 14, "System Type:", EmassWorkbookWriter.StyleLabel);
            sheet.Text(2, 15, settings.EmassSystemType, EmassWorkbookWriter.StyleHeaderValue);
            sheet.Merge("O2:P3");
            sheet.Text(2, 17, "OMB Project ID:", EmassWorkbookWriter.StyleLabel);
            sheet.Text(2, 18, settings.EmassOmbProjectId, EmassWorkbookWriter.StyleHeaderValue);
            sheet.Merge("R2:T3");
            sheet.Text(4, 14, "POC Name:", EmassWorkbookWriter.StyleLabel);
            sheet.Text(4, 15, settings.Name, EmassWorkbookWriter.StyleHeaderValue);
            sheet.Merge("O4:P4");
            sheet.Text(5, 14, "POC Phone:", EmassWorkbookWriter.StyleLabel);
            sheet.Text(5, 15, settings.Phone, EmassWorkbookWriter.StyleHeaderValue);
            sheet.Merge("O5:P5");
            sheet.Text(6, 14, "POC E-Mail:", EmassWorkbookWriter.StyleLabel);
            sheet.Text(6, 15, settings.Email, EmassWorkbookWriter.StyleHeaderValue);
            sheet.Merge("O6:P6");
            sheet.Text(5, 17, "Security Costs:", EmassWorkbookWriter.StyleLabel);
            sheet.Text(5, 18, settings.EmassSecurityCosts, EmassWorkbookWriter.StyleHeaderValue);
            sheet.Merge("R5:T5");
        }

        /// <summary>Writes one item and its milestones; returns the next free row.</summary>
        private static int WriteItem(EmassSheet sheet, int row, EmassPoamItem item)
        {
            // Column numbers: B=2 ... AG=33. POA&M Item ID (B) and Milestone ID (L) are left for eMASS.
            sheet.Text(row, 2, string.Empty);
            sheet.Text(row, 3, item.Status);
            sheet.Text(row, 4, item.Summary);
            sheet.Text(row, 5, item.Description);
            sheet.Text(row, 6, string.Join(EmassPoamBuilder.ListSeparator, item.Controls));
            sheet.Text(row, 7, string.Join(EmassPoamBuilder.ListSeparator, item.SecurityChecks));
            sheet.Date(row, 8, item.DateIdentified);
            sheet.Date(row, 9, item.ScheduledCompletion);
            sheet.Date(row, 10, null);
            sheet.Date(row, 11, item.CompletionDate);
            sheet.Text(row, 18, item.IdentificationSource);
            sheet.Text(row, 19, item.IdentificationSourceDetails);
            sheet.Text(row, 20, item.OfficeOrg);
            sheet.Text(row, 21, item.Comments);
            sheet.Text(row, 22, item.RawSeverity);
            sheet.Text(row, 23, string.Join(EmassPoamBuilder.ListSeparator, item.DevicesAffected));
            sheet.Text(row, 24, item.Mitigations);
            sheet.Text(row, 25, item.Severity);
            sheet.Text(row, 26, item.RelevanceOfThreat);
            sheet.Text(row, 27, item.Likelihood);
            sheet.Text(row, 28, item.Impact);
            sheet.Text(row, 29, item.ImpactDescription);
            sheet.Text(row, 30, item.ResidualRiskLevel);
            sheet.Text(row, 31, item.Recommendations);
            sheet.Text(row, 32, item.Resources);
            sheet.Text(row, 33, string.Empty);

            if (item.Milestones.Count == 0)
            {
                for (int column = 12; column <= 17; column++)
                { sheet.Text(row, column, string.Empty); }
                return row + 1;
            }
            foreach (EmassMilestone milestone in item.Milestones)
            {
                sheet.Text(row, 12, string.Empty);
                sheet.Text(row, 13, milestone.Status);
                sheet.Text(row, 14, milestone.Description);
                sheet.Text(row, 15, string.Empty);
                sheet.Date(row, 16, milestone.ScheduledCompletion);
                sheet.Date(row, 17, milestone.CompletionDate);
                row++;
            }
            return row;
        }

        private List<EmassPoamFinding> ReadFindings()
        {
            using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
            {
                BuildFilteredCommand(sqliteCommand);
                return ReadFindings(sqliteCommand);
            }
        }

        /// <summary>The POA&amp;M query without the Reporting filters (add-ons, interface version 3).</summary>
        public static string UnfilteredQuery()
        {
            return new DdlReader().ReadDdl(StoredProcedureBase + "Select.EmassPoamVulnerabilities.dml", Assembly.GetExecutingAssembly());
        }

        /// <summary>Reads the POA&amp;M finding rows of a prepared command (filtered for the export, unfiltered for add-ons).</summary>
        public static List<EmassPoamFinding> ReadFindings(SQLiteCommand sqliteCommand)
        {
            List<EmassPoamFinding> findings = new List<EmassPoamFinding>();
            {
                using (SQLiteDataReader reader = sqliteCommand.ExecuteReader())
                {
                    bool hasGroupColumns = reader.HasColumn("GroupMitigatedStatus");
                    while (reader.Read())
                    {
                        string identifier = Text(reader, "UniqueVulnerabilityIdentifier");
                        if (identifier.Equals("Plugin"))
                        { continue; }
                        EmassPoamFinding finding = new EmassPoamFinding
                        {
                            SourceName = Text(reader, "VulnSourceName"),
                            SourceVersion = Text(reader, "VulnSourceVersion"),
                            SourceRelease = Text(reader, "VulnSourceRelease"),
                            VulnerabilityIdentifier = identifier,
                            VulnerabilityVersion = Text(reader, "VulnVerison"),
                            Title = Text(reader, "VulnerabilityTitle"),
                            Description = Text(reader, "VulnerabilityDescription"),
                            Controls = Text(reader, "NIST_Controls"),
                            RawStatus = Text(reader, "RawStatus"),
                            MitigatedStatus = Prefer(reader, hasGroupColumns, "GroupMitigatedStatus", "UniqueMitigatedStatus"),
                            RawRisk = Text(reader, "PrimaryRawRiskIndicator"),
                            Hosts = Text(reader, "HostName"),
                            Software = Text(reader, "DisplayedSoftwareName"),
                            Comments = Text(reader, "Comments"),
                            FindingDetails = Text(reader, "FindingDetails"),
                            TechnicalMitigation = Combine(Text(reader, "GroupTechnicalMitigations"), Text(reader, "UniqueTechnicalMitigation")),
                            PredisposingConditions = Combine(Text(reader, "GroupPredisposingConditions"), Text(reader, "UniquePredisposingConditions")),
                            Severity = Prefer(reader, hasGroupColumns, "GroupSeverityPervasiveness", "UniqueSeverityPervasiveness"),
                            ThreatRelevance = Prefer(reader, hasGroupColumns, "GroupThreatRelevance", "UniqueThreatRelevance"),
                            ThreatDescription = Combine(Text(reader, "GroupThreatDescription"), Text(reader, "UniqueThreatDescription")),
                            Likelihood = Prefer(reader, hasGroupColumns, "GroupLikelihood", "UniqueLikelihood"),
                            Impact = Prefer(reader, hasGroupColumns, "GroupImpact", "UniqueImpact"),
                            ImpactDescription = Combine(Text(reader, "GroupImpactDescription"), Text(reader, "UniqueImpactDescription")),
                            ResidualRisk = Prefer(reader, hasGroupColumns, "GroupResidualRisk", "UniqueResidualRisk"),
                            ProposedMitigation = Combine(Text(reader, "GroupProposedMitigations"), Text(reader, "UniqueProposedMitigation")),
                            FixText = Text(reader, "FixText"),
                            SeverityOverride = Text(reader, "SeverityOverride"),
                            SeverityJustification = Text(reader, "SeverityOverrideJustification"),
                            FirstDiscovered = EmassPoamBuilder.ToDate(reader["FirstDiscovered"]),
                            LastObserved = EmassPoamBuilder.ToDate(reader["LastObserved"]),
                            EstimatedCompletion = EmassPoamBuilder.ToDate(
                                hasGroupColumns && !string.IsNullOrWhiteSpace(Text(reader, "GroupEstimatedCompletionDate"))
                                    ? reader["GroupEstimatedCompletionDate"]
                                    : reader["UniqueEstimatedCompletionDate"])
                        };
                        findings.Add(finding);
                    }
                }
            }
            return findings;
        }

        private static string Text(SQLiteDataReader reader, string column)
        {
            if (!reader.HasColumn(column))
            { return string.Empty; }
            object value = reader[column];
            return value == null || value == DBNull.Value ? string.Empty : value.ToString();
        }

        private static string Prefer(SQLiteDataReader reader, bool hasGroupColumns, string groupColumn, string uniqueColumn)
        {
            if (hasGroupColumns)
            {
                string group = Text(reader, groupColumn);
                if (!string.IsNullOrWhiteSpace(group))
                { return group; }
            }
            return Text(reader, uniqueColumn);
        }

        private static string Combine(string groupValue, string uniqueValue)
        {
            // Group-level values arrive as a comma-joined GROUP_CONCAT; keep each on its own paragraph.
            string group = string.IsNullOrWhiteSpace(groupValue)
                ? string.Empty
                : string.Join(Environment.NewLine + Environment.NewLine, groupValue.Split(',').Select(v => v.Trim()).Where(v => v.Length > 0));
            if (string.IsNullOrWhiteSpace(group))
            { return uniqueValue ?? string.Empty; }
            if (string.IsNullOrWhiteSpace(uniqueValue))
            { return group; }
            return group + Environment.NewLine + Environment.NewLine + uniqueValue;
        }

        /// <summary>The POA&amp;M query with the user's report filters applied (finding type, group, severity, status, RMF override).</summary>
        private void BuildFilteredCommand(SQLiteCommand sqliteCommand)
        {
            sqliteCommand.Parameters.Add(new SQLiteParameter("UserName", Properties.Settings.Default.ActiveUser));
            FilterTextCreator filterTextCreator = new FilterTextCreator();
            string findingTypeFilter = filterTextCreator.FindingType(sqliteCommand, ReportName);
            string groupFilter = filterTextCreator.Group(sqliteCommand, ReportName);
            string severityFilter = filterTextCreator.Severity(sqliteCommand, ReportName);
            string statusFilter = filterTextCreator.Status(sqliteCommand, ReportName);
            string rmfOverrideFilter = filterTextCreator.RmfOverride(sqliteCommand, ReportName);
            sqliteCommand.CommandText = _ddlReader.ReadDdl(StoredProcedureBase + "Select.EmassPoamVulnerabilities.dml", _assembly);

            if (!string.IsNullOrWhiteSpace(findingTypeFilter) || !string.IsNullOrWhiteSpace(groupFilter) ||
                !string.IsNullOrWhiteSpace(severityFilter) || !string.IsNullOrWhiteSpace(statusFilter))
            {
                Regex regex = new Regex(Properties.Resources.RegexSqlGroupBy);
                sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(regex.Match(sqliteCommand.CommandText).Index, "WHERE ");
                if (!string.IsNullOrWhiteSpace(findingTypeFilter))
                { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(regex.Match(sqliteCommand.CommandText).Index, findingTypeFilter); }
                if (!string.IsNullOrWhiteSpace(groupFilter))
                {
                    if (!string.IsNullOrWhiteSpace(findingTypeFilter))
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(regex.Match(sqliteCommand.CommandText).Index, $"AND {Environment.NewLine}"); }
                    sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(regex.Match(sqliteCommand.CommandText).Index, groupFilter);
                }
                if (!string.IsNullOrWhiteSpace(severityFilter))
                {
                    if (!string.IsNullOrWhiteSpace(findingTypeFilter) || !string.IsNullOrWhiteSpace(groupFilter))
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(regex.Match(sqliteCommand.CommandText).Index, $"AND {Environment.NewLine}"); }
                    sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(regex.Match(sqliteCommand.CommandText).Index, $"(PrimaryRawRiskIndicator {severityFilter}) ");
                }
                if (!string.IsNullOrWhiteSpace(statusFilter))
                {
                    if (!string.IsNullOrWhiteSpace(findingTypeFilter) || !string.IsNullOrWhiteSpace(groupFilter) || !string.IsNullOrWhiteSpace(severityFilter))
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(regex.Match(sqliteCommand.CommandText).Index, $"AND {Environment.NewLine}"); }
                    sqliteCommand.CommandText = string.IsNullOrWhiteSpace(rmfOverrideFilter)
                        ? sqliteCommand.CommandText.Insert(regex.Match(sqliteCommand.CommandText).Index, $"(RawStatus {statusFilter} OR UniqueMitigatedStatus {statusFilter}) ")
                        : sqliteCommand.CommandText.Insert(regex.Match(sqliteCommand.CommandText).Index, $"(RawStatus {statusFilter} OR UniqueMitigatedStatus {statusFilter} OR GroupMitigatedStatus {statusFilter}) ");
                    regex = new Regex(Properties.Resources.RegexGroupsMitigationsOrConditionsVulnerabilities);
                    sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(regex.Match(sqliteCommand.CommandText).Index, $"{Environment.NewLine}WHERE (MitigatedStatus {statusFilter}) ");
                }
                sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(regex.Match(sqliteCommand.CommandText).Index, Environment.NewLine);
            }

            if (!string.IsNullOrWhiteSpace(rmfOverrideFilter))
            {
                Regex regex = new Regex(Properties.Resources.RegexSqlFindingTypes);
                sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(regex.Match(sqliteCommand.CommandText).Index, rmfOverrideFilter);
                regex = new Regex(Properties.Resources.RegexSqlFromUniqueFindings);
                sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(regex.Match(sqliteCommand.CommandText).Index, Properties.Resources.StringGroupRmfFields);
            }
        }
    }
}
