using System;
using System.Collections.Generic;
using System.IO;
using System.Text.RegularExpressions;
using DocumentFormat.OpenXml;
using DocumentFormat.OpenXml.Packaging;
using DocumentFormat.OpenXml.Spreadsheet;
using Vulnerator.Helper;

namespace Vulnerator.Model.BusinessLogic.Reports
{
    public class OpenXmlCellDataHandler
    {
        public void WriteCellValue(OpenXmlWriter openXmlWriter, string cellValue, int styleIndex, ref int sharedStringMaxIndex, Dictionary<string, int> sharedStringDictionary)
        {
            try
            {
                List<OpenXmlAttribute> openXmlAttributes = new List<OpenXmlAttribute>();
                openXmlAttributes.Add(new OpenXmlAttribute("s", null, styleIndex.ToString()));
                int parseResult;
                if (int.TryParse(cellValue, out parseResult))
                {
                    openXmlWriter.WriteStartElement(new Cell(), openXmlAttributes);
                    openXmlWriter.WriteElement(new CellValue(cellValue));
                    openXmlWriter.WriteEndElement();
                }
                else
                {
                    openXmlAttributes.Add(new OpenXmlAttribute("t", null, "s"));
                    openXmlWriter.WriteStartElement(new Cell(), openXmlAttributes);
                    if (!sharedStringDictionary.ContainsKey(cellValue))
                    {
                        sharedStringDictionary.Add(cellValue, sharedStringMaxIndex);
                        sharedStringMaxIndex += 1;
                    }
                    openXmlWriter.WriteElement(new CellValue(sharedStringDictionary[cellValue].ToString()));
                    openXmlWriter.WriteEndElement();
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to write cell value to Excel report.");
                throw exception;
            }
        }

        public void CreateSharedStringPart(WorkbookPart workbookPart, int sharedStringMaxIndex, Dictionary<string, int> sharedStringDictionary)
        {
            try
            {
                if (sharedStringMaxIndex > 0)
                {
                    SharedStringTablePart sharedStringTablePart = workbookPart.AddNewPart<SharedStringTablePart>();
                    using (OpenXmlWriter openXmlWriter = OpenXmlWriter.Create(sharedStringTablePart))
                    {
                        openXmlWriter.WriteStartElement(new SharedStringTable());
                        foreach (var item in sharedStringDictionary)
                        {
                            openXmlWriter.WriteStartElement(new SharedStringItem());
                            openXmlWriter.WriteElement(new Text(item.Key));
                            openXmlWriter.WriteEndElement();
                        }

                        openXmlWriter.WriteEndElement();
                    }
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to create 'SharedStringPart' in Excel report.");
                throw exception;
            }
        }

        public string HandleLargeCellValue(string cellValue, string pluginId, string assetName, string columnName)
        {
            try
            {
                if (cellValue.Length < 32000)
                { return cellValue; }
                string regexPattern = "\\n((?![a-z])|(?=[udp])|(?=[tcp]))";
                Regex regex = new Regex(regexPattern);
                cellValue = regex.Replace(cellValue, "\r\n");
                if (assetName.Contains("\r\n"))
                { assetName = "MergedResults"; }
                assetName = assetName.Replace("\\", "-");
                assetName = assetName.Replace("/", "-");
                string outputPath = Environment.GetFolderPath(Environment.SpecialFolder.Desktop) + @"\Vulnerator - " + DateTime.Now.ToShortDateString().Replace('/', '-');
                string outputTextFile = string.Empty;
                outputTextFile = outputPath + @"\" + assetName + "_" + pluginId + "_" + "_" + columnName + ".txt";
                if (!Directory.Exists(outputPath))
                { Directory.CreateDirectory(outputPath); }
                if (!File.Exists(outputTextFile))
                {
                    using (FileStream fs = new FileStream(outputTextFile, FileMode.Append, FileAccess.Write))
                    using (StreamWriter sw = new StreamWriter(fs))
                    {
                        sw.WriteLine(cellValue);
                        sw.Close();
                    }
                }
                return "Output text exceeds the maximum character allowance for an Excel cell; " +
                       "please see \"" + outputTextFile + "\" for full output details.";
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to handle large cell value.");
                throw exception;
            }
        }
    }
}
