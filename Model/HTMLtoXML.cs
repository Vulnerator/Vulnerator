using log4net;
using System;
using System.Collections;
using System.IO;
using System.Linq;
using System.Xml.Linq;

namespace Vulnerator.Model
{
    public class HTMLtoXML
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(Logger));
        public string Convert(string fileName)
        {
            try
            {
                string htmlText = File.ReadAllText(fileName);

                // Replace ampersand, line breaks, nulls
                htmlText = htmlText.Replace("&", "-and");
                htmlText = htmlText.Replace("<br>", "\n");
                htmlText = htmlText.Replace(char.ConvertFromUtf32(0), string.Empty);

                // Remvoe "Look and Feel" tags
                htmlText = htmlText.Replace(" colspan=\"2\"", string.Empty);
                htmlText = htmlText.Replace("<center>", string.Empty);
                htmlText = htmlText.Replace("</center>", string.Empty);
                htmlText = htmlText.Replace("<hr>", string.Empty);
                htmlText = htmlText.Replace("</hr>", string.Empty);
                htmlText = htmlText.Replace("<b>", string.Empty);
                htmlText = htmlText.Replace("</b>", string.Empty);
                htmlText = htmlText.Replace("valign=middle", string.Empty);
                htmlText = htmlText.Replace("color=white", string.Empty);
                htmlText = htmlText.Replace("color=black", string.Empty);
                htmlText = htmlText.Replace("bgcolor=\"#CCCCCC\"", string.Empty);
                htmlText = htmlText.Replace("bgcolor=\"#999999\"", string.Empty);
                htmlText = htmlText.Replace("bgcolor=\"#FF9900\"", string.Empty);
                htmlText = htmlText.Replace("bgcolor=\"#FF0000\"", string.Empty);
                htmlText = htmlText.Replace("bgcolor=\"#FFFF00\"", string.Empty);
                htmlText = htmlText.Replace("bgcolor=\"#C0C0C0\"", string.Empty);
                htmlText = htmlText.Replace("bgcolor=#C0C0C0", string.Empty);
                htmlText = htmlText.Replace("bgcolor=\"blue\"", string.Empty);
                htmlText = htmlText.Replace("border=\"1\"", string.Empty);
                htmlText = htmlText.Replace("width=\"100%\"", string.Empty);
                htmlText = htmlText.Replace("valgin=middle", string.Empty);
                htmlText = htmlText.Replace("align=middle", string.Empty);
                htmlText = htmlText.Replace("width=\"15%\"", string.Empty);
                htmlText = htmlText.Replace("width=\"20%\"", string.Empty);
                htmlText = htmlText.Replace("width=\"15%\"", string.Empty);
                htmlText = htmlText.Replace("cellpadding=\"2\"", string.Empty);
                htmlText = htmlText.Replace("cellpadding=\"3\"", string.Empty);
                htmlText = htmlText.Replace("cellspacing=\"2\"", string.Empty);
                htmlText = htmlText.Replace("target=_blank", string.Empty);
                htmlText = htmlText.Replace("<Account domain not found>", "{Account domain not found}");
                htmlText = htmlText.Replace("<account_name>", "{account_name}");
                htmlText = htmlText.Replace("  >", ">");
                htmlText = htmlText.Replace(" >", ">");
                htmlText = htmlText.Replace("table ", "table");

                // Strip out font tags
                htmlText = htmlText.Replace("<font>", string.Empty);
                htmlText = htmlText.Replace("</font>", string.Empty);
                int currentIndex = 0;
                while (currentIndex != -1)
                {
                    currentIndex = htmlText.IndexOf("<font size=", currentIndex);
                    if (currentIndex != -1)
                    {
                        int endIndex = htmlText.IndexOf('>', currentIndex + 1);
                        string key = htmlText.Substring(currentIndex, endIndex - currentIndex + 1);
                        htmlText = htmlText.Replace(key, string.Empty);
                        currentIndex++;
                    }
                }
                htmlText = htmlText.Replace("<font >", string.Empty);

                // Strip out "img" tags
                htmlText = htmlText.Replace("</img>", string.Empty);
                currentIndex = 0;
                while (currentIndex != -1)
                {
                    currentIndex = htmlText.IndexOf("<img src", currentIndex);
                    if (currentIndex != -1)
                    {
                        int endIndex = htmlText.IndexOf('>', currentIndex + 1);
                        string key = htmlText.Substring(currentIndex, endIndex - currentIndex + 1);
                        htmlText = htmlText.Replace(key, string.Empty);
                        currentIndex++;
                    }
                }

                // Repair tables
                currentIndex = 0;
                while (currentIndex != -1)
                {
                    int tableBegins = htmlText.IndexOf("<table", currentIndex);
                    if (tableBegins != -1)
                    {
                        // we found a table. Now make sure every row has an ending
                        // before the next row begins or table ends.
                        int thisRowBegins = htmlText.IndexOf("<tr", tableBegins);
                        while (thisRowBegins != -1)
                        {
                            int nextRowBegins = htmlText.IndexOf("<tr", thisRowBegins + 3);
                            int thisTableEnds = htmlText.IndexOf("</table", thisRowBegins + 3);
                            int thisRowEnds = htmlText.IndexOf("</tr", thisRowBegins + 3);
                            if (thisRowEnds == -1 ||
                                thisRowEnds > thisTableEnds ||
                                (nextRowBegins != -1 && thisRowEnds > nextRowBegins))
                            {
                                int insertAt = nextRowBegins < thisTableEnds ? nextRowBegins : thisTableEnds;
                                htmlText = htmlText.Insert(insertAt, "</tr>");
                                currentIndex = nextRowBegins + 5;
                                thisRowBegins = htmlText.IndexOf("<tr", currentIndex);
                            }
                            else
                            {
                                currentIndex = nextRowBegins;
                                thisRowBegins = nextRowBegins;
                            }
                        }
                    }
                    else
                    {
                        currentIndex = tableBegins;
                    }
                }

                // Add missing document end tags
                if (!htmlText.Contains("</body>"))
                {
                    htmlText = htmlText + "</body>" + Environment.NewLine + "</html>";
                }

                // Insert new lines
                htmlText = htmlText.Replace("<", Environment.NewLine + "<");
                htmlText = htmlText.Replace("</", Environment.NewLine + "</");
                htmlText = htmlText.Replace(">", ">" + Environment.NewLine);

                string workingPath = Path.GetDirectoryName(fileName);
                string wasspXml = Path.GetFileNameWithoutExtension(fileName);
                string newXml = workingPath + "\\" + wasspXml + ".xml";
                string newTxt = workingPath + "\\WorkingHtml.txt";

                File.WriteAllText(newTxt, htmlText);
                var workingLines = File.ReadAllLines(newTxt).Where(arg => !string.IsNullOrWhiteSpace(arg));
                File.WriteAllLines(newTxt, workingLines);
                string[] workingText = File.ReadAllLines(newTxt);

                workingText[406] = string.Empty;
                workingText[407] = string.Empty;
                workingText[411] = string.Empty;

                for (int i = 0; i < workingText.Length; i++)
                {
                    if (workingText[i].Contains("<script"))
                    { workingText[i] = "<script>"; }
                    else if (workingText[i].Contains("<body>"))
                    {
                        workingText[i + 1] = string.Empty;
                        workingText[i + 2] = string.Empty;
                        workingText[i + 3] = string.Empty;
                        workingText[i + 4] = string.Empty;
                    }
                    else if (workingText[i].Contains("</table") && !workingText[i + 1].Contains("<"))
                    { workingText[i + 1] = "<TableTitle>" + workingText[i + 1] + "</TableTitle>"; }
                    else if (workingText[i].Contains("<th"))
                    { workingText[i] = "<th>"; }
                    else if (workingText[i].Contains("<a"))
                    { workingText[i] = "<a>"; }
                }

                // Get rid of white space
                File.Delete(newTxt);
                File.WriteAllLines(newTxt, workingText);
                var writingLines = File.ReadAllLines(newTxt).Where(arg => !string.IsNullOrWhiteSpace(arg));
                File.Delete(newTxt);
                File.WriteAllLines(newTxt, writingLines);
                string writingText = File.ReadAllText(newTxt);

                // Delete CML if it exists
                if (File.Exists(newXml))
                { File.Delete(newXml); }

                // Write text to XML
                XDocument xWassp = XDocument.Parse(writingText);

                // Lots of functions to clean up the XML for parsing into the DataSet
                XElement xRoot = xWassp.Root;
                xRoot.Element("head").Remove();

                foreach (XElement el in xRoot.Descendants())
                {
                    if (el.Name == "td" && el.Value.Contains("Finding:"))
                    {
                        el.Name = "Finding";
                    }
                    else if (el.Name == "td" && el.Value.Contains("Machine"))
                    {
                        el.Name = "MachineInfo";
                        foreach (XElement e in el.ElementsAfterSelf())
                        {
                            e.Name = "MachineInfo";
                        }
                    }
                    else if (el.Name == "td" && el.Value.Contains("Date"))
                    {
                        el.Name = "DateInfo";
                        foreach (XElement e in el.ElementsAfterSelf())
                        {
                            e.Name = "DateInfo";
                        }
                    }
                    else if (el.Name == "td" && el.Value.Contains("Test #"))
                    {
                        el.Name = "TestInfo";
                        foreach (XElement e in el.ElementsAfterSelf())
                        {
                            e.Name = "TestInfo";
                        }
                    }
                    else if (el.Name == "td" && el.Value.Contains("Requirement"))
                    {
                        el.Name = "Requirements";
                        foreach (XElement e in el.ElementsAfterSelf())
                        {
                            e.Name = "Requirements";
                        }
                    }
                    else if (el.Name == "td" && el.Value.Contains("Value"))
                    {
                        el.Name = "ValueInfo";
                        foreach (XElement e in el.ElementsAfterSelf())
                        {
                            e.Name = "ValueInfo";
                        }
                    }
                    else if (el.Name == "td" && el.Value.Contains("Description"))
                    {
                        el.Name = "DescriptionInfo";
                        foreach (XElement e in el.ElementsAfterSelf())
                        {
                            e.Name = "DescriptionInfo";
                        }
                    }
                    else if (el.Name == "td" && el.Value.Contains("Expected Results"))
                    {
                        el.Name = "ExpectRes";
                        foreach (XElement e in el.ElementsAfterSelf())
                        {
                            e.Name = "ExpectRes";
                        }
                    }
                    else if (el.Name == "td" && el.Value.Contains("Actual Results"))
                    {
                        el.Name = "ActualRes";
                        foreach (XElement e in el.ElementsAfterSelf())
                        {
                            e.Name = "ActualRes";
                        }
                    }
                    else if (el.Name == "td" && el.Value.Contains("Test Result"))
                    {
                        el.Name = "TestRes";
                        foreach (XElement e in el.ElementsAfterSelf())
                        {
                            e.Name = "TestRes";
                        }
                    }
                    else if (el.Name == "td" && el.Value.Contains("Vulnerability Level"))
                    {
                        el.Name = "VulnInfo";
                        foreach (XElement e in el.ElementsAfterSelf())
                        {
                            e.Name = "VulnInfo";
                        }
                    }
                    else if (el.Name == "td" && el.Value.Contains("Recommendation"))
                    {
                        el.Name = "RecInfo";
                        foreach (XElement e in el.ElementsAfterSelf())
                        {
                            e.Name = "RecInfo";
                        }
                    }
                    else if (el.Name == "td" && el.Value.Contains("Site/Command Mitigation"))
                    {
                        el.Name = "MitInfo";
                        foreach (XElement e in el.ElementsAfterSelf())
                        {
                            e.Name = "MitInfo";
                        }
                    }
                    else if (el.Name == "td" && el.Value.Contains("DOD Review/Response"))
                    {
                        el.Name = "DodInfo";
                        foreach (XElement e in el.ElementsAfterSelf())
                        {
                            e.Name = "DodInfo";
                        }
                    }
                }

                // Still doing cleanup functions...
                ArrayList arL = new ArrayList();
                XElement xBody = xRoot.Element("body");
                XElement xTable = xBody.Element("table");

                foreach (XElement el in xBody.Elements())
                {
                    if (el.Name != "table")
                    {
                        arL.Add(el);
                    }
                    else
                    {
                        XElement xTr = el.Element("tr");
                        bool hasFind = xTr.Elements("Finding").Any();
                        if (hasFind == false)
                        {
                            arL.Add(el);
                        }
                    }
                }

                foreach (XElement el in arL)
                {
                    el.Remove();
                }

                // Save XML file, delete text file that was created, add XML file to list for parsing into DataSet
                xWassp.Save(newXml);
                File.Delete(newTxt);
                return newXml;
            }
            catch (Exception exception)
            {
                log.Error("Unable to parse WASSP HTML file to XML format.");
                log.Debug("Exception details: " + exception);
                return "Failed; See Log";
            }
        }
    }
}
