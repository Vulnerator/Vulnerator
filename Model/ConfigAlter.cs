using log4net;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Xml.Linq;

namespace Vulnerator.Model
{
    /// <summary>
    /// Alterations to the Vulnerator_Config.xml file are made here
    /// </summary>
    public class ConfigAlter
    {
        private static string xmlPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + @"\Vulnerator";
        private static string xmlFile = xmlPath + @"\Vulnerator_Config.xml";
        public static Dictionary<string, string> configDic = new Dictionary<string, string>();
        public static XDocument xdocumentConfigurationXmlFile;
        Assembly assembly = Assembly.GetExecutingAssembly();
        private static readonly ILog log = LogManager.GetLogger(typeof(Logger));

        #region CreateSettingsDictionary

        /// <summary>
        /// Create the dictionary used to store the user's configuration settings while the application is running.
        /// </summary>
        public void CreateSettingsDictionary()
        {
            try
            {
                log.Info("Creating settings dictionary.");
                xdocumentConfigurationXmlFile = XDocument.Load(xmlFile);
                XElement rootElement = xdocumentConfigurationXmlFile.Element("preferencesRoot");
                XElement reportingTabElement = rootElement.Element("reportingTab");
                XElement mitigationsTabElement = rootElement.Element("mitigationsTab");
                XElement createSubTabElement = mitigationsTabElement.Element("createSubTab");
                XElement iavmComplianceTabElement = rootElement.Element("iavmComplianceTab");
                XElement reportingSubTabElement = iavmComplianceTabElement.Element("reportingSubTab");
                XElement contactsSubTabElement = iavmComplianceTabElement.Element("contactsSubTab");
                XElement themeFlyoutElement = rootElement.Element("themeFlyout");
                XElement iavmEmailOptionsFlyoutElement = rootElement.Element("iavmEmailOptionsFlyout");

                foreach (XElement el in reportingTabElement.Elements())
                { configDic[el.Name.LocalName] = el.Value; }
                foreach (XElement el in createSubTabElement.Elements())
                { configDic[el.Name.LocalName] = el.Value; }
                foreach (XElement el in reportingSubTabElement.Elements())
                { configDic[el.Name.LocalName] = el.Value; }
                foreach (XElement el in contactsSubTabElement.Elements())
                { configDic[el.Name.LocalName] = el.Value; }
                foreach (XElement el in themeFlyoutElement.Elements())
                { configDic[el.Name.LocalName] = el.Value; }
                foreach (XElement el in iavmEmailOptionsFlyoutElement.Elements())
                { configDic[el.Name.LocalName] = el.Value; }
            }
            catch (Exception exception)
            {
                log.Error("Unable to create settings dictionary.");
                log.Debug("Exception details: " + exception);
            }
        }

        #endregion

        #region ReadSettingsFromDictionary

        /// <summary>
        /// Read the value of the provided key from the user's settings dictionary
        /// </summary>
        /// <param name="dicKey">Dictionary value to be read</param>
        /// <returns>string Value</returns>
        public static string ReadSettingsFromDictionary(string dicKey)
        {
            try
            {
                if (dicKey != null)
                {
                    string dicVal;
                    configDic.TryGetValue(dicKey, out dicVal);
                    return dicVal;
                }

                else
                {
                    string dicVal = string.Empty;
                    return dicVal;
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to read setting value for " + dicKey + ".");
                log.Debug("Exception details: " + exception);
                return string.Empty;
            }
        }

        #endregion

        #region WriteSettingsToDictionary

        /// <summary>
        /// Update the provided key within the user's settings dictionary with the provided value
        /// </summary>
        /// <param name="dicKey">Dictionary key to be updated</param>
        /// <param name="dicVal">Dictionary value to be updated</param>
        public void WriteSettingsToDictionary(string dicKey, string dicVal)
        {
            try
            {
                if (dicKey != null)
                { configDic[dicKey] = dicVal; }
            }
            catch (Exception exception)
            {
                log.Error("Unable to write value to dictionary for " + dicKey + ".");
                log.Debug("Exception details: " + exception);
            }
        }

        #endregion

        #region WriteSettingsToConfigurationXml

        /// <summary>
        /// Updates the user's "Vulnerator_Configuration.xml" file on application close
        /// </summary>
        public void WriteSettingsToConfigurationXml()
        {
            try
            {
                log.Info("Writing settings values fro dictionary to configuration XML.");
                foreach (string key in configDic.Keys)
                {
                    string value;
                    configDic.TryGetValue(key, out value);
                    XElement el = xdocumentConfigurationXmlFile.Descendants().FirstOrDefault(n => n.Name.LocalName == key);
                    el.Value = value;
                }
                xdocumentConfigurationXmlFile.Save(xmlFile);
            }
            catch (Exception exception)
            {
                log.Error("Unable to write settings from dictionary to configuration XML.");
                log.Debug("Exception details: " + exception);
            }
        }

        #endregion

        #region CreateConfigurationXml

        /// <summary>
        /// Validate presence of "Vulnerator_Config.xml" file; if the file does not exist, create it.
        /// </summary>
        public void CreateConfigurationXml()
        {
            try
            {
                
                if (!Directory.Exists(xmlPath))
                { Directory.CreateDirectory(xmlPath); }

                if (File.Exists(xmlFile))
                {
                    log.Info("Verifying XML configuration file is current.");
                    XDocument oldXmlConfigCheck = XDocument.Load(xmlFile);
                    var versionNode = oldXmlConfigCheck.Root.Descendants().FirstOrDefault(x => x.Name.LocalName.Equals("version"));
                    if (versionNode == null)
                    { File.Delete(xmlFile); }
                    else if (versionNode.Value != FileVersionInfo.GetVersionInfo(assembly.Location).FileVersion.ToString())
                    { File.Delete(xmlFile); }
                }
                
                if (!File.Exists(xmlFile))
                {
                    log.Info("Creating XML configuration file.");
                    
                    XDocument configDoc = new XDocument(
                        new XDeclaration("1.0", "utf-8", "True"),
                        new XElement("preferencesRoot",
                            new XElement("version", FileVersionInfo.GetVersionInfo(assembly.Location).FileVersion.ToString()),
                            new XElement("reportingTab",
                                new XElement("rbDiacap", "True"),
                                new XElement("rbRmf", "False"),
                                new XElement("cbCritical", "True"),
                                new XElement("cbHigh", "True"),
                                new XElement("cbMedium", "True"),
                                new XElement("cbLow", "True"),
                                new XElement("cbInfo", "True"),
                                new XElement("cbCatI", "True"),
                                new XElement("cbCatII", "True"),
                                new XElement("cbCatIII", "True"),
                                new XElement("cbCatIV", "True"),
                                new XElement("cbOpen", "True"),
                                new XElement("cbNotReviewed", "True"),
                                new XElement("cbNotApplicable", "True"),
                                new XElement("cbCompleted", "True"),
                                new XElement("cbPoamRar", "True"),
                                new XElement("cbAssetOverview", "True"),
                                new XElement("cbDiscrepancies", "True"),
                                new XElement("cbStigDetails", "True"),
                                new XElement("cbFprDetails", "True"),
                                new XElement("cbAcasOutput", "True"),
                                new XElement("cbOsUser", "False"),
                                new XElement("cbPdfSum", "False"),
                                new XElement("cbMergeAcas", "True"),
                                new XElement("cbMergeXccdf", "True"),
                                new XElement("cbMergeCkl", "True"),
                                new XElement("cbMergeWassp", "True"),
                                new XElement("cbMergeFpr", "True"),
                                new XElement("tbEmassOrg", string.Empty),
                                new XElement("tbEmassName", string.Empty),
                                new XElement("tbEmassNumber", string.Empty),
                                new XElement("tbEmassEmail", string.Empty),
                                new XElement("cbAllFindings", "False"),
                                new XElement("cbBySystem", "False"),
                                new XElement("cbByGroup", "False"),
                                new XElement("rbHostIdentifier", "True"),
                                new XElement("rbIpIdentifier", "False"),
                                new XElement("cbComments", "True"),
                                new XElement("cbFindingDetails", "True"),
                                new XElement("revisionThreeRadioButton", "True"),
                                new XElement("revisionFourRadioButton", "False"),
                                new XElement("cbNistAppendixA", "True"),
                                new XElement("cbTestPlan", "True")
                            ),
                            new XElement("mitigationsTab",
                                new XElement("createSubTab",
                                    new XElement("tbMitDbLocation", Environment.GetFolderPath(
                                        Environment.SpecialFolder.ApplicationData) + @"\Vulnerator\VulneratorDatabase.sqlite")
                                )
                            ),
                            new XElement("iavmComplianceTab",
                                new XElement("reportingSubTab",
                                    new XElement("cbNotifyOne", "True"),
                                    new XElement("cbNotifyTwo", "True"),
                                    new XElement("cbNotifyThree", "True"),
                                    new XElement("cbNotifyFour", "True"),
                                    new XElement("tbNotifyingEmail", string.Empty),
                                    new XElement("rbPki", "True"),
                                    new XElement("rbNone", "True"),
                                    new XElement("cbReportOne", "True"),
                                    new XElement("cbReportTwo", "True"),
                                    new XElement("cbReportThree", "True"),
                                    new XElement("cbReportFour", "True"),
                                    new XElement("cbIavmPdf", "True"),
                                    new XElement("cbIavmExcel", "True")
                                ),
                                new XElement("contactsSubTab",
                                    new XElement("tbContactDbLocation", Environment.GetFolderPath(
                                        Environment.SpecialFolder.ApplicationData) + @"\Vulnerator\VulneratorDatabase.sqlite")
                                )
                            ),
                            new XElement("themeFlyout",
                                new XElement("currentTheme", "Light"),
                                new XElement("currentAccent", "Cobalt")
                            ),
                            new XElement("iavmEmailOptionsFlyout",
                                new XElement("iavmFilterOne", "30"),
                                new XElement("iavmFilterTwo", "60"),
                                new XElement("iavmFilterThree", "90"),
                                new XElement("iavmFilterFour", "120")
                            )
                        )
                    );
                    configDoc.Save(xmlFile);
                }
                log.Info("XML configuration file created successfully.");
            }
            catch (Exception exception)
            {
                log.Error("Creation of XML configuration file failed.");
                log.Debug("Exception details: " + exception);
            }
        }

        #endregion
    }
}
