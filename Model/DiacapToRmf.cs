using log4net;
using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Xml;

namespace Vulnerator.Model
{
    public static class DiacapToRmf
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(Logger));
        public static Dictionary<string, string> RevisionThree = new Dictionary<string, string>();
        public static Dictionary<string, string> RevisionFour = new Dictionary<string, string>();

        public static void InitializeDictionaries()
        {
            try
            {
                log.Info("Initializing DIACAP to RMF conversion dictionaries.");
                string diacapControl = string.Empty;
                Assembly assembly = Assembly.GetExecutingAssembly();
                string fileName = "Vulnerator.Resources.DiacapToRmf.xml";
                using (Stream stream = assembly.GetManifestResourceStream(fileName))
                {
                    using (XmlReader xmlReader = XmlReader.Create(stream))
                    {
                        while (xmlReader.Read())
                        {
                            if (xmlReader.IsStartElement())
                            {
                                switch (xmlReader.Name)
                                {
                                    case "Iac":
                                        {
                                            diacapControl = xmlReader.GetAttribute("control");
                                            break;
                                        }
                                    case "NistControl":
                                        {
                                            switch (xmlReader.GetAttribute("revision"))
                                            {
                                                case "3":
                                                    {
                                                        InsertDictionaryValue(RevisionThree, xmlReader, diacapControl);
                                                        break;
                                                    }
                                                case "4":
                                                    {
                                                        InsertDictionaryValue(RevisionFour, xmlReader, diacapControl);
                                                        break;
                                                    }
                                                default:
                                                    { break; }
                                            }
                                            break;
                                        }
                                    default:
                                        { break; }
                                }
                            }
                        }
                    }
                }
                log.Info("DIACAP to RMF conversion dictionaries initialize successfully.");
            }
            catch (Exception exception)
            {
                log.Error("Unable to initialize DIACAP to RMF conversion dictionaries.");
                log.Debug("Exception details: " + exception);
            }
        }

        private static void InsertDictionaryValue(Dictionary<string, string> conversionDictionary, XmlReader xmlReader, string diacapControl)
        {
            xmlReader.Read();
            if (!conversionDictionary.ContainsKey(diacapControl))
            { conversionDictionary.Add(diacapControl, xmlReader.Value); }
            else
            { conversionDictionary[diacapControl] = conversionDictionary[diacapControl].ToString() + Environment.NewLine + xmlReader.Value; }
        }
    }
}
