using System;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using DocumentFormat.OpenXml;
using DocumentFormat.OpenXml.Packaging;
using DocumentFormat.OpenXml.Spreadsheet;
using DocumentFormat.OpenXml.VariantTypes;

namespace Vulnerator.Helper
{
    /// <summary>
    /// The classification / handling marking on files Vulnerator creates. Before an export the user accepts or changes
    /// the marking (Settings keeps the last one); it is written as a banner in every sheet's header and footer, as the
    /// workbook's "Classification" document property, and as the CKL MARKING.
    /// </summary>
    public static class ExportMarking
    {
        public const string PropertyName = "Classification";

        /// <summary>
        /// Asks for the marking of an export (prefilled from Settings) unless the user turned the question off.
        /// Returns the marking, possibly empty, or null when the user cancels the export. Safe from any thread.
        /// </summary>
        public static string Confirm(string exportName)
        {
            string current = Vulnerator.Properties.Settings.Default.EmassClassificationMarking ?? string.Empty;
            if (!Vulnerator.Properties.Settings.Default.ConfirmExportMarking || Application.Current == null)
            { return current; }
            string result = null;
            Application.Current.Dispatcher.Invoke(() => result = ShowDialog(exportName, current));
            if (result != null && result != current)
            {
                Vulnerator.Properties.Settings.Default.EmassClassificationMarking = result;
                Vulnerator.Properties.Settings.Default.Save();
            }
            LogWriter.LogStatusUpdate(result == null ? $"{exportName}: export cancelled at the marking prompt." : $"{exportName}: marking '{result}'.");
            return result;
        }

        private static string ShowDialog(string exportName, string current)
        {
            Window window = new Window
            {
                Title = "Marking for " + exportName,
                Width = 480,
                SizeToContent = SizeToContent.Height,
                ResizeMode = ResizeMode.NoResize,
                WindowStartupLocation = WindowStartupLocation.CenterOwner,
                Owner = Application.Current.Windows.OfType<Window>().FirstOrDefault(w => w.IsActive) ?? Application.Current.MainWindow
            };
            StackPanel panel = new StackPanel { Margin = new Thickness(12) };
            panel.Children.Add(new TextBlock
            {
                Text = "Classification / handling marking for this export. It is printed at the top and bottom of every " +
                       "sheet and stored in the file's properties. Accept it, change it, or clear it for no marking.",
                TextWrapping = TextWrapping.Wrap,
                Margin = new Thickness(0, 0, 0, 8)
            });
            TextBox marking = new TextBox { Text = current, Margin = new Thickness(0, 0, 0, 8) };
            panel.Children.Add(marking);
            CheckBox ask = new CheckBox { Content = "Ask before every export", IsChecked = true, Margin = new Thickness(0, 0, 0, 12) };
            panel.Children.Add(ask);
            StackPanel buttons = new StackPanel { Orientation = Orientation.Horizontal, HorizontalAlignment = HorizontalAlignment.Right };
            Button ok = new Button { Content = "Export", IsDefault = true, MinWidth = 80, Margin = new Thickness(0, 0, 8, 0) };
            Button cancel = new Button { Content = "Cancel", IsCancel = true, MinWidth = 80 };
            ok.Click += (sender, args) => window.DialogResult = true;
            buttons.Children.Add(ok);
            buttons.Children.Add(cancel);
            panel.Children.Add(buttons);
            window.Content = panel;
            window.Loaded += (sender, args) => { marking.Focus(); marking.SelectAll(); };
            if (window.ShowDialog() != true)
            { return null; }
            Vulnerator.Properties.Settings.Default.ConfirmExportMarking = ask.IsChecked == true;
            return (marking.Text ?? string.Empty).Trim();
        }

        /// <summary>Writes the marking into every sheet's header / footer and the workbook properties (no-op when blank).</summary>
        public static void ApplyToWorkbook(string path, string marking)
        {
            if (string.IsNullOrWhiteSpace(marking) || !System.IO.File.Exists(path))
            { return; }
            string banner = "&C&B ***** " + marking.Trim().Replace("&", "&&") + " *****";
            using (SpreadsheetDocument document = SpreadsheetDocument.Open(path, true))
            {
                foreach (WorksheetPart worksheetPart in document.WorkbookPart.WorksheetParts)
                {
                    Worksheet worksheet = worksheetPart.Worksheet;
                    HeaderFooter headerFooter = new HeaderFooter(new OddHeader(banner), new OddFooter(banner));
                    HeaderFooter existing = worksheet.GetFirstChild<HeaderFooter>();
                    if (existing != null)
                    { worksheet.ReplaceChild(headerFooter, existing); }
                    else
                    {
                        // Schema order: ... printOptions, pageMargins, pageSetup, headerFooter, rowBreaks, ... drawing ...
                        OpenXmlElement after = worksheet.Elements<PageSetup>().Cast<OpenXmlElement>().LastOrDefault()
                                               ?? worksheet.Elements<PageMargins>().Cast<OpenXmlElement>().LastOrDefault()
                                               ?? worksheet.Elements<PrintOptions>().Cast<OpenXmlElement>().LastOrDefault();
                        if (after != null)
                        { worksheet.InsertAfter(headerFooter, after); }
                        else
                        {
                            OpenXmlElement before = worksheet.ChildElements.FirstOrDefault(e => e is RowBreaks || e is ColumnBreaks ||
                                e is CustomProperties || e is IgnoredErrors || e is Drawing || e is LegacyDrawing || e is TableParts ||
                                e is WorksheetExtensionList);
                            if (before != null)
                            { worksheet.InsertBefore(headerFooter, before); }
                            else
                            { worksheet.Append(headerFooter); }
                        }
                    }
                    worksheet.Save();
                }

                CustomFilePropertiesPart propertiesPart = document.CustomFilePropertiesPart ?? document.AddCustomFilePropertiesPart();
                if (propertiesPart.Properties == null)
                { propertiesPart.Properties = new DocumentFormat.OpenXml.CustomProperties.Properties(); }
                DocumentFormat.OpenXml.CustomProperties.CustomDocumentProperty property = propertiesPart.Properties.Elements<DocumentFormat.OpenXml.CustomProperties.CustomDocumentProperty>()
                    .FirstOrDefault(p => p.Name == PropertyName);
                if (property == null)
                {
                    int nextId = propertiesPart.Properties.Elements<DocumentFormat.OpenXml.CustomProperties.CustomDocumentProperty>()
                        .Select(p => p.PropertyId?.Value ?? 1).DefaultIfEmpty(1).Max() + 1;
                    property = new DocumentFormat.OpenXml.CustomProperties.CustomDocumentProperty
                    {
                        FormatId = "{D5CDD505-2E9C-101B-9397-08002B2CF9AE}",
                        PropertyId = Math.Max(2, nextId),
                        Name = PropertyName
                    };
                    propertiesPart.Properties.Append(property);
                }
                property.RemoveAllChildren();
                property.Append(new VTLPWSTR(marking.Trim()));
                propertiesPart.Properties.Save();
            }
        }
    }
}
