using System;
using System.Collections.Generic;
using System.Linq;
using DocumentFormat.OpenXml;
using DocumentFormat.OpenXml.Packaging;
using DocumentFormat.OpenXml.Spreadsheet;

namespace Vulnerator.Model.BusinessLogic.Reports
{
    /// <summary>
    /// Builds plain .xlsx workbooks laid out like the eMASS import templates (header block in rows 2-6,
    /// column headers in row 7, data from row 8). Text is always written as text (no numeric sniffing),
    /// dates as real Excel dates, and every sheet carries the classification banner in its page
    /// header and footer, as the eMASS templates do.
    /// </summary>
    public sealed class EmassWorkbookWriter : IDisposable
    {
        public const uint StyleDefault = 0;
        public const uint StyleColumnHeader = 1;
        public const uint StyleText = 2;
        public const uint StyleDate = 3;
        public const uint StyleLabel = 4;
        public const uint StyleHeaderValue = 5;

        // Excel's hard limit for text in one cell.
        public const int MaxCellLength = 32767;

        private readonly SpreadsheetDocument _document;
        private readonly WorkbookPart _workbookPart;
        private readonly Sheets _sheets;
        private readonly Dictionary<string, int> _sharedStrings = new Dictionary<string, int>(StringComparer.Ordinal);
        private readonly List<string> _sharedStringOrder = new List<string>();
        private readonly string _classificationMarking;
        private uint _nextSheetId = 1;

        public EmassWorkbookWriter(string fileName, string classificationMarking)
        {
            _classificationMarking = classificationMarking ?? string.Empty;
            _document = SpreadsheetDocument.Create(fileName, SpreadsheetDocumentType.Workbook);
            _workbookPart = _document.AddWorkbookPart();
            _workbookPart.Workbook = new Workbook();
            _sheets = _workbookPart.Workbook.AppendChild(new Sheets());
            WorkbookStylesPart stylesPart = _workbookPart.AddNewPart<WorkbookStylesPart>();
            stylesPart.Stylesheet = CreateStylesheet();
        }

        public EmassSheet AddSheet(string name, double[] columnWidths, int[] hiddenColumns = null)
        {
            return new EmassSheet(this, name, columnWidths, hiddenColumns ?? new int[0]);
        }

        internal int SharedStringIndex(string text)
        {
            int index;
            if (!_sharedStrings.TryGetValue(text, out index))
            {
                index = _sharedStringOrder.Count;
                _sharedStrings.Add(text, index);
                _sharedStringOrder.Add(text);
            }
            return index;
        }

        internal void WriteSheet(EmassSheet sheet)
        {
            WorksheetPart worksheetPart = _workbookPart.AddNewPart<WorksheetPart>();
            Worksheet worksheet = new Worksheet();

            if (sheet.FrozenRows > 0)
            {
                string topLeft = "A" + (sheet.FrozenRows + 1).ToString(System.Globalization.CultureInfo.InvariantCulture);
                worksheet.Append(new SheetViews(new SheetView(
                    new Pane { VerticalSplit = sheet.FrozenRows, TopLeftCell = topLeft, ActivePane = PaneValues.BottomLeft, State = PaneStateValues.Frozen },
                    new Selection { Pane = PaneValues.BottomLeft, ActiveCell = topLeft, SequenceOfReferences = new ListValue<StringValue> { InnerText = topLeft } })
                { WorkbookViewId = 0U }));
            }

            Columns columns = new Columns();
            for (int i = 0; i < sheet.ColumnWidths.Length; i++)
            {
                uint index = (uint)(i + 1);
                Column column = new Column { Min = index, Max = index, Width = sheet.ColumnWidths[i], CustomWidth = true };
                if (sheet.HiddenColumns.Contains(i + 1))
                { column.Hidden = true; }
                columns.Append(column);
            }
            worksheet.Append(columns);

            SheetData sheetData = new SheetData();
            foreach (KeyValuePair<int, SortedDictionary<int, Cell>> row in sheet.Rows)
            {
                Row xmlRow = new Row { RowIndex = (uint)row.Key };
                if (sheet.HiddenRows.Contains(row.Key))
                { xmlRow.Hidden = true; }
                foreach (Cell cell in row.Value.Values)
                { xmlRow.Append(cell); }
                sheetData.Append(xmlRow);
            }
            worksheet.Append(sheetData);

            if (!string.IsNullOrWhiteSpace(sheet.AutoFilter))
            { worksheet.Append(new AutoFilter { Reference = sheet.AutoFilter }); }

            if (sheet.Merges.Count > 0)
            {
                MergeCells mergeCells = new MergeCells();
                foreach (string range in sheet.Merges)
                { mergeCells.Append(new MergeCell { Reference = range }); }
                worksheet.Append(mergeCells);
            }

            worksheet.Append(new PageMargins { Left = 0.25, Right = 0.25, Top = 0.75, Bottom = 0.75, Header = 0.3, Footer = 0.3 });
            if (!string.IsNullOrWhiteSpace(_classificationMarking))
            {
                string banner = "&C&B ***** " + _classificationMarking.Trim() + " *****";
                worksheet.Append(new HeaderFooter
                {
                    OddHeader = new OddHeader(banner),
                    OddFooter = new OddFooter(banner)
                });
            }

            worksheetPart.Worksheet = worksheet;
            _sheets.Append(new Sheet
            {
                Id = _workbookPart.GetIdOfPart(worksheetPart),
                SheetId = _nextSheetId++,
                Name = sheet.Name
            });
        }

        public void Dispose()
        {
            if (_sharedStringOrder.Count > 0)
            {
                SharedStringTablePart part = _workbookPart.AddNewPart<SharedStringTablePart>();
                SharedStringTable table = new SharedStringTable();
                foreach (string text in _sharedStringOrder)
                { table.Append(new SharedStringItem(new Text(text) { Space = SpaceProcessingModeValues.Preserve })); }
                table.Count = (uint)_sharedStringOrder.Count;
                table.UniqueCount = (uint)_sharedStringOrder.Count;
                part.SharedStringTable = table;
            }
            _workbookPart.Workbook.Save();
            _document.Dispose();
        }

        private static Stylesheet CreateStylesheet()
        {
            return new Stylesheet(
                new NumberingFormats(new NumberingFormat { NumberFormatId = 164, FormatCode = "mm-dd-yy" }) { Count = 1 },
                new Fonts(
                    new Font(new FontSize { Val = 10 }, new FontName { Val = "Arial" }),
                    new Font(new Bold(), new FontSize { Val = 10 }, new FontName { Val = "Arial" })) { Count = 2 },
                new Fills(
                    new Fill(new PatternFill { PatternType = PatternValues.None }),
                    new Fill(new PatternFill { PatternType = PatternValues.Gray125 }),
                    new Fill(new PatternFill(new ForegroundColor { Rgb = "FFD9D9D9" }) { PatternType = PatternValues.Solid })) { Count = 3 },
                new Borders(
                    new Border(new LeftBorder(), new RightBorder(), new TopBorder(), new BottomBorder(), new DiagonalBorder()),
                    new Border(
                        new LeftBorder(new Color { Auto = true }) { Style = BorderStyleValues.Thin },
                        new RightBorder(new Color { Auto = true }) { Style = BorderStyleValues.Thin },
                        new TopBorder(new Color { Auto = true }) { Style = BorderStyleValues.Thin },
                        new BottomBorder(new Color { Auto = true }) { Style = BorderStyleValues.Thin },
                        new DiagonalBorder())) { Count = 2 },
                new CellStyleFormats(new CellFormat()) { Count = 1 },
                new CellFormats(
                    // 0 default
                    new CellFormat(),
                    // 1 column header: bold, grey, bordered, wrapped, centered
                    new CellFormat(new Alignment { Horizontal = HorizontalAlignmentValues.Center, Vertical = VerticalAlignmentValues.Center, WrapText = true })
                    { FontId = 1, FillId = 2, BorderId = 1, ApplyFont = true, ApplyFill = true, ApplyBorder = true, ApplyAlignment = true },
                    // 2 text: bordered, wrapped, top-aligned
                    new CellFormat(new Alignment { Vertical = VerticalAlignmentValues.Top, WrapText = true })
                    { BorderId = 1, ApplyBorder = true, ApplyAlignment = true },
                    // 3 date: mm-dd-yy as in the eMASS templates
                    new CellFormat(new Alignment { Vertical = VerticalAlignmentValues.Top })
                    { NumberFormatId = 164, BorderId = 1, ApplyNumberFormat = true, ApplyBorder = true, ApplyAlignment = true },
                    // 4 header-block label: bold, right-aligned
                    new CellFormat(new Alignment { Horizontal = HorizontalAlignmentValues.Right })
                    { FontId = 1, ApplyFont = true, ApplyAlignment = true },
                    // 5 header-block value
                    new CellFormat(new Alignment { Horizontal = HorizontalAlignmentValues.Left })
                    { ApplyAlignment = true }) { Count = 6 },
                new CellStyles(new CellStyle { Name = "Normal", FormatId = 0, BuiltinId = 0 }) { Count = 1 });
        }
    }

    public sealed class EmassSheet
    {
        private readonly EmassWorkbookWriter _writer;
        internal readonly string Name;
        internal readonly double[] ColumnWidths;
        internal readonly HashSet<int> HiddenColumns;
        internal readonly HashSet<int> HiddenRows = new HashSet<int>();
        internal readonly SortedDictionary<int, SortedDictionary<int, Cell>> Rows = new SortedDictionary<int, SortedDictionary<int, Cell>>();
        internal readonly List<string> Merges = new List<string>();

        /// <summary>Rows kept visible at the top while scrolling (0 for none).</summary>
        public int FrozenRows { get; set; }

        /// <summary>Range with Excel filter buttons, for example "A1:W250" (null for none).</summary>
        public string AutoFilter { get; set; }

        internal EmassSheet(EmassWorkbookWriter writer, string name, double[] columnWidths, int[] hiddenColumns)
        {
            _writer = writer;
            Name = name;
            ColumnWidths = columnWidths;
            HiddenColumns = new HashSet<int>(hiddenColumns);
        }

        /// <summary>Writes text; null or empty writes nothing. Text longer than Excel allows is truncated with a marker.</summary>
        public void Text(int row, int column, string value, uint style = EmassWorkbookWriter.StyleText)
        {
            if (string.IsNullOrEmpty(value))
            {
                if (style != EmassWorkbookWriter.StyleDefault)
                { Put(row, column, new Cell { StyleIndex = style }); }
                return;
            }
            const string marker = " [truncated: exceeds the Excel cell limit]";
            if (value.Length > EmassWorkbookWriter.MaxCellLength)
            { value = value.Substring(0, EmassWorkbookWriter.MaxCellLength - marker.Length) + marker; }
            Put(row, column, new Cell
            {
                DataType = CellValues.SharedString,
                CellValue = new CellValue(_writer.SharedStringIndex(value).ToString(System.Globalization.CultureInfo.InvariantCulture)),
                StyleIndex = style
            });
        }

        /// <summary>Writes a real Excel date (no time). Null writes an empty, date-formatted cell.</summary>
        public void Date(int row, int column, DateTime? value)
        {
            if (!value.HasValue)
            {
                Put(row, column, new Cell { StyleIndex = EmassWorkbookWriter.StyleDate });
                return;
            }
            Put(row, column, new Cell
            {
                CellValue = new CellValue(value.Value.Date.ToOADate().ToString(System.Globalization.CultureInfo.InvariantCulture)),
                StyleIndex = EmassWorkbookWriter.StyleDate
            });
        }

        public void Merge(string range) { Merges.Add(range); }

        public void HideRow(int row)
        {
            HiddenRows.Add(row);
            if (!Rows.ContainsKey(row))
            { Rows[row] = new SortedDictionary<int, Cell>(); }
        }

        public void Save() { _writer.WriteSheet(this); }

        public static string ColumnName(int column)
        {
            string name = string.Empty;
            while (column > 0)
            {
                int modulo = (column - 1) % 26;
                name = Convert.ToChar('A' + modulo) + name;
                column = (column - modulo) / 26;
            }
            return name;
        }

        private void Put(int row, int column, Cell cell)
        {
            cell.CellReference = ColumnName(column) + row.ToString(System.Globalization.CultureInfo.InvariantCulture);
            SortedDictionary<int, Cell> cells;
            if (!Rows.TryGetValue(row, out cells))
            {
                cells = new SortedDictionary<int, Cell>();
                Rows[row] = cells;
            }
            cells[column] = cell;
        }
    }
}
