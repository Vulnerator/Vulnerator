using DocumentFormat.OpenXml;
using DocumentFormat.OpenXml.Spreadsheet;
using System;
using System.IO;

namespace Vulnerator.Model.Object
{
    public class FormattedCell : Cell
    {
        public FormattedCell(string text, UInt32Value index, string pluginId, string assetName)
        {
            int intParseResult;
            if (int.TryParse(text, out intParseResult))
            {
                DataType = CellValues.Number;
                CellValue = new CellValue(text);
                StyleIndex = index;
            }
            else
            {
                DataType = CellValues.InlineString;
                if (text.Contains(">"))
                { text.Replace(">", "&gt;"); }
                if (text.Contains("<"))
                { text.Replace("<", "&lt;"); }
                if (text.Length < 32767)
                { InlineString = new InlineString { Text = new Text { Text = text } }; }
                else if (text.Length > 32767 && !string.IsNullOrWhiteSpace(assetName))
                {
                    string outputPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop) + @"\AcasScanOutput_TextFiles";
                    string outputTextFile = outputPath + @"\" + pluginId + "_" + assetName + "_ScanOutput.txt";

                    InlineString = new InlineString
                    {
                        Text = new Text
                        {
                            Text = "Output text exceeds the maximum character allowance for an Excel cell; "
                                + "please see \"" + outputTextFile + "\" for full output details."
                        }
                    };

                    if (!Directory.Exists(outputPath))
                    { Directory.CreateDirectory(outputPath); }

                    try
                    {
                        if (!System.IO.File.Exists(outputTextFile))
                        {
                            using (FileStream fs = new FileStream(outputTextFile, FileMode.Append, FileAccess.Write))
                            using (StreamWriter sw = new StreamWriter(fs))
                            {
                                sw.WriteLine(text);
                                sw.Close();
                            }
                        }
                    }
                    catch
                    { return; }
                }
                StyleIndex = index;
            }
        }
    }
}
