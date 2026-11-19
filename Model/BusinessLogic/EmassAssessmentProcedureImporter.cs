using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.IO;
using System.Linq;
using System.Reflection;
using DocumentFormat.OpenXml.Packaging;
using DocumentFormat.OpenXml.Spreadsheet;
using Vulnerator.Helper;
using Vulnerator.Model.DataAccess;

namespace Vulnerator.Model.BusinessLogic
{
    /// <summary>
    /// Imports assessment procedures by CCI: an eMASS "IG/APs" export (Control Number, AP Acronym, CCI, CCI Definition,
    /// Assessment Procedures, Potential Assessment Methods and Objectives) or any workbook or CSV with equivalent
    /// columns, into the local database. The data is kept in its own table and
    /// re-applied to the CCI-to-control mappings whenever the reference data reloads, so it is loaded once per
    /// machine from the user's own export and never ships with Vulnerator.
    /// </summary>
    public static class EmassAssessmentProcedureImporter
    {
        private const string StoredProcedureBase = "Vulnerator.Resources.DdlFiles.StoredProcedures.";

        // Header names accepted for each column, compared without case, spaces or punctuation. eMASS names come first.
        private static readonly string[] CciHeaders = { "CCI", "CCI Number", "CCI ID", "CCIs", "CCI Ref", "CCI Reference" };
        private static readonly string[] ControlHeaders = { "Control Number", "Control", "Control ID", "Security Control", "Control Acronym" };
        private static readonly string[] ApHeaders = { "AP Acronym", "AP", "AP ID", "AP Number", "Assessment Procedure ID", "Assessment Procedure Acronym" };
        private static readonly string[] ProcedureHeaders = { "Assessment Procedures", "Assessment Procedure", "Assessment Procedure Text", "Procedure", "Test Procedure" };
        private static readonly string[] MethodHeaders = { "Potential Assessment Methods and Objectives", "Assessment Methods", "Assessment Methods and Objectives", "Methods" };

        /// <summary>
        /// Imports assessment procedures from an eMASS IG/AP export or any workbook (.xlsx / .xlsm) or delimited text
        /// file (.csv / .tsv / .txt) with a CCI column and an AP acronym and / or assessment procedure column, in any
        /// order. Returns a one-line result for the user.
        /// </summary>
        public static string Import(string path)
        { return Import(path, null); }

        /// <summary>
        /// As <see cref="Import(string)"/>; when the workbook carries a sensitivity label, <paramref name="confirmLabel"/>
        /// is shown the label and the import goes ahead only if it returns true (null: accept).
        /// </summary>
        public static string Import(string path, Func<string, bool> confirmLabel)
        {
            string label = SensitivityLabel(path);
            if (label != null)
            {
                LogWriter.LogStatusUpdate($"'{path}' carries the sensitivity label '{label}'.");
                if (confirmLabel != null && !confirmLabel(label))
                { return $"Import cancelled: the file carries the sensitivity label \"{label}\"."; }
            }
            List<List<string[]>> tables;
            try
            {
                if (IsWorkbook(path))
                { tables = ReadWorkbook(path); }
                else
                {
                    // Comma, tab or semicolon: whichever parse yields the header row wins.
                    tables = DelimitedText.ParseCandidates(DelimitedText.ReadAllText(path)).ToList();
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogErrorWithDebug($"Unable to open assessment procedure file '{path}'.", exception);
                return "Could not open the file. If it carries a sensitivity label with encryption, save an unprotected copy " +
                       "(or CSV) in Excel and import that.";
            }

            // The first sheet (or the file) with a header row naming a CCI column and an AP or procedure column.
            List<string[]> rows = null;
            int header = -1;
            foreach (List<string[]> table in tables)
            {
                header = table.FindIndex(r => Find(r, CciHeaders) >= 0 && (Find(r, ApHeaders) >= 0 || Find(r, ProcedureHeaders) >= 0));
                if (header >= 0)
                { rows = table; break; }
            }
            if (rows == null)
            {
                return "No assessment procedures found: the file needs a header row with a \"CCI\" column and an " +
                       "\"AP Acronym\" or \"Assessment Procedures\" column (as in the eMASS IG/AP export).";
            }
            int colCci = Find(rows[header], CciHeaders);
            int colControl = Find(rows[header], ControlHeaders);
            int colAp = Find(rows[header], ApHeaders);
            int colProcedure = Find(rows[header], ProcedureHeaders);
            int colMethods = Find(rows[header], MethodHeaders);

            HashSet<string> seen = new HashSet<string>();
            int imported = 0, skipped = 0, applied;
            try
            {
                if (!DatabaseBuilder.sqliteConnection.State.ToString().Equals("Open"))
                { DatabaseBuilder.sqliteConnection.Open(); }
                using (SQLiteTransaction transaction = DatabaseBuilder.sqliteConnection.BeginTransaction())
                using (SQLiteCommand command = DatabaseBuilder.sqliteConnection.CreateCommand())
                {
                    command.CommandText = "DELETE FROM EmassAssessmentProcedures;";
                    command.ExecuteNonQuery();
                    command.CommandText =
                        "INSERT OR REPLACE INTO EmassAssessmentProcedures (CCI_Number, ControlNumber, AP_Acronym, AssessmentProcedure, AssessmentMethods, ImportedOn) " +
                        "VALUES (@CCI, @Control, @AP, @Procedure, @Methods, @ImportedOn);";
                    SQLiteParameter cci = command.Parameters.Add("@CCI", System.Data.DbType.String);
                    SQLiteParameter control = command.Parameters.Add("@Control", System.Data.DbType.String);
                    SQLiteParameter ap = command.Parameters.Add("@AP", System.Data.DbType.String);
                    SQLiteParameter procedure = command.Parameters.Add("@Procedure", System.Data.DbType.String);
                    SQLiteParameter methods = command.Parameters.Add("@Methods", System.Data.DbType.String);
                    command.Parameters.AddWithValue("@ImportedOn", DateTime.Now);
                    for (int i = header + 1; i < rows.Count; i++)
                    {
                        // A cell may list several CCIs; "CCI-NA" rows are control-level procedures with no CCI to attach to.
                        List<string> numbers = CciNumbers(Cell(rows[i], colCci));
                        if (numbers.Count == 0)
                        {
                            if (rows[i].Any(c => !string.IsNullOrWhiteSpace(c)))
                            { skipped++; }
                            continue;
                        }
                        control.Value = Cell(rows[i], colControl).Trim();
                        ap.Value = Cell(rows[i], colAp).Trim();
                        procedure.Value = Cell(rows[i], colProcedure).Trim();
                        methods.Value = Cell(rows[i], colMethods).Trim();
                        foreach (string number in numbers)
                        {
                            cci.Value = number;
                            command.ExecuteNonQuery();
                            if (seen.Add(number))
                            { imported++; }
                        }
                    }
                    command.Parameters.Clear();
                    applied = Apply(command);
                    transaction.Commit();
                }
            }
            finally
            { DatabaseBuilder.sqliteConnection.Close(); }

            string result = $"Imported assessment procedures for {imported} CCI(s); {applied} CCI-to-control mapping(s) updated" +
                            (skipped > 0 ? $"; {skipped} row(s) without a CCI skipped." : ".");
            LogWriter.LogStatusUpdate(result);
            return result;
        }

        /// <summary>Copies imported procedures onto the CCI-to-control mappings; returns the number of mappings updated.</summary>
        public static int Apply(SQLiteCommand command)
        {
            command.Parameters.Clear();
            command.CommandText = new DdlReader().ReadDdl(
                StoredProcedureBase + "Update.NistControlsCcisFromEmassAssessmentProcedures.dml", Assembly.GetExecutingAssembly());
            return command.ExecuteNonQuery();
        }

        private static int Find(string[] row, string[] names)
        { return DelimitedText.Find(row, names); }

        private static string Cell(string[] row, int index)
        { return DelimitedText.Cell(row, index); }

        /// <summary>CCI numbers in a cell as stored in the CCIs table (six digits, no prefix): "CCI-000015", "CCI-15" or "000015".</summary>
        private static List<string> CciNumbers(string cell)
        {
            List<string> numbers = new List<string>();
            foreach (string token in (cell ?? string.Empty).Split(new[] { ',', ';', ' ', '\t', '\r', '\n', '|' }, StringSplitOptions.RemoveEmptyEntries))
            {
                string digits = token.Trim();
                if (digits.StartsWith("CCI", StringComparison.OrdinalIgnoreCase))
                { digits = digits.Substring(3).TrimStart('-', '_', ' '); }
                int value;
                if (digits.Length > 0 && digits.All(char.IsDigit) && int.TryParse(digits, out value))
                {
                    string number = value.ToString("D6");
                    if (!numbers.Contains(number))
                    { numbers.Add(number); }
                }
            }
            return numbers;
        }

        /// <summary>
        /// The Microsoft Purview / AIP sensitivity label of an Office workbook (its name, or its id when the name is not
        /// stored), or null when it has none. Encrypted (protected) files cannot be read at all and are reported on open.
        /// </summary>
        public static string SensitivityLabel(string path)
        {
            try
            {
                using (System.IO.Compression.ZipArchive package = System.IO.Compression.ZipFile.OpenRead(path))
                {
                    System.IO.Compression.ZipArchiveEntry custom = package.GetEntry("docProps/custom.xml");
                    if (custom != null)
                    {
                        System.Xml.Linq.XDocument properties;
                        using (Stream stream = custom.Open())
                        { properties = System.Xml.Linq.XDocument.Load(stream); }
                        foreach (System.Xml.Linq.XElement property in properties.Root.Elements())
                        {
                            string name = (string)property.Attribute("name") ?? string.Empty;
                            if (name.StartsWith("MSIP_Label_", StringComparison.OrdinalIgnoreCase) && name.EndsWith("_Name", StringComparison.OrdinalIgnoreCase))
                            { return property.Value.Trim(); }
                        }
                    }
                    System.IO.Compression.ZipArchiveEntry labelInfo = package.GetEntry("docMetadata/LabelInfo.xml");
                    if (labelInfo != null)
                    {
                        System.Xml.Linq.XDocument info;
                        using (Stream stream = labelInfo.Open())
                        { info = System.Xml.Linq.XDocument.Load(stream); }
                        System.Xml.Linq.XElement entry = info.Descendants().FirstOrDefault(e => e.Name.LocalName == "label");
                        string id = (string)entry?.Attribute("id");
                        if (!string.IsNullOrWhiteSpace(id) && (string)entry.Attribute("removed") != "1")
                        { return "label " + id; }
                    }
                }
            }
            catch (Exception)
            { /* not a zip package (CSV, or an encrypted workbook): no readable label */ }
            return null;
        }

        private static bool IsWorkbook(string path)
        {
            string extension = (Path.GetExtension(path) ?? string.Empty).ToLowerInvariant();
            if (extension == ".xlsx" || extension == ".xlsm")
            { return true; }
            byte[] signature = new byte[4];
            using (FileStream stream = File.OpenRead(path))
            {
                if (stream.Read(signature, 0, 4) < 4)
                { return false; }
            }
            // A zip package (PK..) is an Office workbook; a protected (label-encrypted) workbook is an OLE file (D0 CF 11 E0).
            return (signature[0] == 0x50 && signature[1] == 0x4B) || (signature[0] == 0xD0 && signature[1] == 0xCF);
        }

        /// <summary>Every worksheet's rows as text, indexed by column (A = 0).</summary>
        private static List<List<string[]>> ReadWorkbook(string path)
        {
            List<List<string[]>> tables = new List<List<string[]>>();
            using (SpreadsheetDocument document = SpreadsheetDocument.Open(path, false))
            {
                WorkbookPart workbookPart = document.WorkbookPart;
                SharedStringItem[] sharedStrings = workbookPart.SharedStringTablePart?.SharedStringTable
                    .Elements<SharedStringItem>().ToArray() ?? new SharedStringItem[0];
                foreach (Sheet sheet in workbookPart.Workbook.Sheets.Elements<Sheet>())
                {
                    WorksheetPart worksheetPart = workbookPart.GetPartById(sheet.Id) as WorksheetPart;
                    if (worksheetPart == null)
                    { continue; }
                    List<string[]> rows = new List<string[]>();
                    foreach (Row row in worksheetPart.Worksheet.Descendants<Row>())
                    {
                        List<Cell> cells = row.Elements<Cell>().ToList();
                        int width = cells.Count == 0 ? 0 : cells.Max(c => ColumnIndex(c.CellReference?.Value)) + 1;
                        string[] values = new string[Math.Max(width, cells.Count)];
                        int position = 0;
                        foreach (Cell cell in cells)
                        {
                            int column = cell.CellReference != null ? ColumnIndex(cell.CellReference.Value) : position;
                            position = column + 1;
                            values[column] = CellText(cell, sharedStrings);
                        }
                        rows.Add(values);
                    }
                    tables.Add(rows);
                }
            }
            return tables;
        }

        private static string CellText(Cell cell, SharedStringItem[] sharedStrings)
        {
            if (cell.DataType != null && cell.DataType.Value == CellValues.SharedString)
            {
                int index;
                return int.TryParse(cell.CellValue?.Text, out index) && index >= 0 && index < sharedStrings.Length
                    ? sharedStrings[index].InnerText
                    : string.Empty;
            }
            if (cell.DataType != null && cell.DataType.Value == CellValues.InlineString)
            { return cell.InlineString?.InnerText ?? string.Empty; }
            return cell.CellValue?.Text ?? string.Empty;
        }

        private static int ColumnIndex(string reference)
        {
            int index = 0;
            foreach (char c in reference ?? string.Empty)
            {
                if (!char.IsLetter(c))
                { break; }
                index = index * 26 + (char.ToUpperInvariant(c) - 'A' + 1);
            }
            return Math.Max(index - 1, 0);
        }
    }
}
