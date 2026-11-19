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
    /// Writes a Hardware/Software list laid out like the eMASS "HWSWList_Template": a Hardware sheet and a
    /// Software sheet, each with the template's header block (rows 2-6) and columns (row 7), data from row 8.
    /// Only what Vulnerator records from scans is filled; the remaining template columns are left blank for the
    /// user (and eMASS requires Software Vendor, which scans do not provide).
    /// </summary>
    public class OpenXmlEmassHardwareSoftwareReportCreator
    {
        public const string ReportName = "eMASS Hardware/Software List";

        public static readonly string[] HardwareHeaders =
        {
            "#", "Component Type", "Asset Name", "Nickname", "MAC Address", "Asset IP Address", "Public Facing",
            "Public Facing FQDN", "Public Facing IP Address", "Public Facing URL(s)", "Virtual Asset?", "Manufacturer",
            "Model Number", "Serial Number", "Line Item Number", "National Stock Number", "OS/iOS/FW Version",
            "Memory Size / Type", "Location (P/C/S & Building)", "Approval Status", "Critical Information System Asset?"
        };

        public static readonly string[] SoftwareHeaders =
        {
            "#", "Software Type", "Software Vendor", "Software Name", "Version", "Parent System", "Subsystem", "Network",
            "Hosting Environment", "Software Dependencies", "Cryptographic Hash", "In Service Data", "IT Budget UII",
            "Fiscal Year (FY)", "POP End Date", "License or Contract", "License Term", "Cost per License",
            "Total Licenses", "Total License Cost", "Licenses Used", "License POC", "License Renewal Date",
            "License Expiration Date", "Approval Status", "Approval Date", "Release Date", "Maintenance Date",
            "Retirement Date", "End of Life/Support Date", "Extended End of Life/Support Date",
            "Critical Information System Asset?", "Location", "Purpose"
        };

        private const int HeaderRow = 7;
        private readonly DdlReader _ddlReader = new DdlReader();
        private readonly Assembly _assembly = Assembly.GetExecutingAssembly();
        private const string StoredProcedureBase = "Vulnerator.Resources.DdlFiles.StoredProcedures.";

        public string CreateHardwareSoftwareList(string fileName)
        {
            try
            {
                if (!DatabaseBuilder.sqliteConnection.State.ToString().Equals("Open"))
                { DatabaseBuilder.sqliteConnection.Open(); }

                Properties.Settings settings = Properties.Settings.Default;
                using (EmassWorkbookWriter workbook = new EmassWorkbookWriter(fileName, settings.EmassClassificationMarking))
                {
                    EmassSheet hardware = workbook.AddSheet("Hardware", Widths(HardwareHeaders.Length, 2, 3, 5, 6, 17));
                    hardware.HideRow(1);
                    WriteHeaderBlock(hardware, settings, "U");
                    WriteColumnHeaders(hardware, HardwareHeaders);
                    int hardwareRows = WriteHardware(hardware);
                    hardware.Save();

                    EmassSheet software = workbook.AddSheet("Software", Widths(SoftwareHeaders.Length, 3, 4, 34));
                    software.HideRow(1);
                    WriteHeaderBlock(software, settings, "AH");
                    WriteColumnHeaders(software, SoftwareHeaders);
                    int softwareRows = WriteSoftware(software);
                    software.Save();

                    LogWriter.LogStatusUpdate($"Hardware/Software list: {hardwareRows} hardware and {softwareRows} software row(s).");
                }
                return "Excel report creation successful";
            }
            catch (Exception exception)
            {
                LogWriter.LogErrorWithDebug($"Unable to create '{fileName}' (eMASS Hardware/Software list).", exception);
                return "Excel report creation failed - see log for details";
            }
            finally
            {
                DatabaseBuilder.sqliteConnection.Close();
            }
        }

        private static double[] Widths(int count, params int[] wideColumns)
        {
            double[] widths = Enumerable.Repeat(18.0, count).ToArray();
            widths[0] = 6;
            foreach (int column in wideColumns)
            { widths[column - 1] = 32; }
            return widths;
        }

        private static void WriteColumnHeaders(EmassSheet sheet, string[] headers)
        {
            for (int i = 0; i < headers.Length; i++)
            { sheet.Text(HeaderRow, i + 1, headers[i], EmassWorkbookWriter.StyleColumnHeader); }
        }

        private static void WriteHeaderBlock(EmassSheet sheet, Properties.Settings settings, string lastColumn)
        {
            // Template layout: labels A (merged A:B) with values C:F; G labels with values H:I;
            // J labels with values K:L. The N/Q-to-last-column band on rows 2-6 is merged and left empty.
            string[,] left =
            {
                { "Date Exported:", DateTime.Today.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture) },
                { "Exported By:", settings.Name },
                { "Information System Owner:", settings.EmassInformationSystemOwner },
                { "System Name:", settings.EmassSystemName },
                { "DITPR ID:", settings.EmassItRegistrationNumber }
            };
            for (int i = 0; i < left.GetLength(0); i++)
            {
                int row = 2 + i;
                sheet.Text(row, 1, left[i, 0], EmassWorkbookWriter.StyleLabel);
                sheet.Text(row, 3, left[i, 1], EmassWorkbookWriter.StyleHeaderValue);
                sheet.Merge("A" + row + ":B" + row);
                sheet.Merge("C" + row + ":F" + row);
            }
            string officeOrg = string.IsNullOrWhiteSpace(settings.EmassOfficeOrg) ? settings.Organization : settings.EmassOfficeOrg;
            string[,] middle =
            {
                { "Office / Org:", officeOrg },
                { "POC Name:", settings.Name },
                { "POC Phone:", settings.Phone },
                { "POC E-Mail:", settings.Email }
            };
            for (int i = 0; i < middle.GetLength(0); i++)
            {
                int row = 3 + i;
                sheet.Text(row, 7, middle[i, 0], EmassWorkbookWriter.StyleLabel);
                sheet.Text(row, 8, middle[i, 1], EmassWorkbookWriter.StyleHeaderValue);
                sheet.Merge("H" + row + ":I" + row);
            }
            sheet.Text(4, 10, "Date Reviewed / Updated:", EmassWorkbookWriter.StyleLabel);
            sheet.Date(4, 11, DateTime.Today);
            sheet.Merge("K4:L4");
            sheet.Text(5, 10, "Reviewed / Updated By:", EmassWorkbookWriter.StyleLabel);
            sheet.Text(5, 11, settings.Name, EmassWorkbookWriter.StyleHeaderValue);
            sheet.Merge("K5:L5");
            string bandStart = lastColumn == "U" ? "N" : "Q";
            for (int row = 2; row <= 6; row++)
            { sheet.Merge(bandStart + row + ":" + lastColumn + row); }
        }

        private int WriteHardware(EmassSheet sheet)
        {
            int row = HeaderRow + 1;
            using (SQLiteCommand command = FilteredCommand("Select.EmassHardwareList.dml"))
            using (SQLiteDataReader reader = command.ExecuteReader())
            {
                while (reader.Read())
                {
                    string assetName = FirstNonEmpty(Text(reader, "DisplayedHostName"), Text(reader, "DiscoveredHostName"),
                        Text(reader, "FQDN"), Text(reader, "ScanIP"));
                    if (string.IsNullOrWhiteSpace(assetName))
                    { continue; }
                    string virtualFlag = Text(reader, "IsVirtualServer").Trim().ToLowerInvariant();
                    string[] values = new string[HardwareHeaders.Length];
                    values[2] = Limit(assetName, 100);                                   // C Asset Name
                    values[4] = Limit(List(Text(reader, "MacAddresses")), 250);          // E MAC Address
                    values[5] = Limit(List(Text(reader, "IpAddresses")), 100);           // F Asset IP Address
                    values[10] = virtualFlag == "true" ? "Yes" : virtualFlag == "false" ? "No" : string.Empty; // K Virtual Asset?
                    values[11] = Limit(Text(reader, "Manufacturer"), 100);               // L Manufacturer
                    values[12] = Limit(Text(reader, "ModelNumber"), 100);                // M Model Number
                    values[13] = Limit(Text(reader, "SerialNumber"), 100);               // N Serial Number
                    values[16] = Limit(Text(reader, "OperatingSystem"), 100);            // Q OS/iOS/FW Version
                    WriteRow(sheet, row, values);
                    row++;
                }
            }
            return row - HeaderRow - 1;
        }

        private int WriteSoftware(EmassSheet sheet)
        {
            int row = HeaderRow + 1;
            using (SQLiteCommand command = FilteredCommand("Select.EmassSoftwareList.dml"))
            using (SQLiteDataReader reader = command.ExecuteReader())
            {
                while (reader.Read())
                {
                    string name = FirstNonEmpty(Text(reader, "DisplayedSoftwareName"), Text(reader, "DiscoveredSoftwareName"));
                    if (string.IsNullOrWhiteSpace(name))
                    { continue; }
                    string[] values = new string[SoftwareHeaders.Length];
                    values[3] = Limit(name, 100);                                        // D Software Name
                    values[4] = Limit(Text(reader, "SoftwareVersion"), 100);             // E Version
                    values[33] = Limit(Text(reader, "SoftwareFunction"), 100);           // AH Purpose
                    WriteRow(sheet, row, values);
                    row++;
                }
            }
            return row - HeaderRow - 1;
        }

        private static void WriteRow(EmassSheet sheet, int row, string[] values)
        {
            for (int i = 0; i < values.Length; i++)
            { sheet.Text(row, i + 1, values[i] ?? string.Empty); }
        }

        private SQLiteCommand FilteredCommand(string dml)
        {
            SQLiteCommand command = DatabaseBuilder.sqliteConnection.CreateCommand();
            command.Parameters.Add(new SQLiteParameter("UserName", Properties.Settings.Default.ActiveUser));
            string groupFilter = new FilterTextCreator().Group(command, ReportName);
            command.CommandText = _ddlReader.ReadDdl(StoredProcedureBase + dml, _assembly);
            if (!string.IsNullOrWhiteSpace(groupFilter))
            {
                Regex regex = new Regex(Properties.Resources.RegexSqlGroupBy);
                command.CommandText = command.CommandText.Insert(regex.Match(command.CommandText).Index,
                    "WHERE " + groupFilter + Environment.NewLine);
            }
            return command;
        }

        private static string Text(SQLiteDataReader reader, string column)
        {
            object value = reader[column];
            return value == null || value == DBNull.Value ? string.Empty : value.ToString().Trim();
        }

        private static string List(string commaJoined)
        {
            return string.Join("; ", (commaJoined ?? string.Empty).Split(',')
                .Select(v => v.Trim()).Where(v => v.Length > 0).Distinct(StringComparer.OrdinalIgnoreCase));
        }

        private static string Limit(string value, int max)
        {
            return string.IsNullOrEmpty(value) || value.Length <= max ? value : value.Substring(0, max);
        }

        private static string FirstNonEmpty(params string[] values)
        {
            return values.FirstOrDefault(v => !string.IsNullOrWhiteSpace(v)) ?? string.Empty;
        }
    }
}
