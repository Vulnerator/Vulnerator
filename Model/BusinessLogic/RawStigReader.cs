using log4net;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Xml;
using Vulnerator.Model.BusinessLogic;
using Vulnerator.Model.Object;
using Vulnerator.ViewModel.ViewModelHelper;

namespace Vulnerator.Model.BusinessLogic
{
    public class RawStigReader
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(Logger));

        public void ReadRawStig(ZipArchiveEntry rawStig)
        {
            try
            {
                log.Info(string.Format("Begin ingestion of raw STIG file {0}", rawStig.FullName));
                using (XmlReader xmlReader = XmlReader.Create(rawStig.Open(), GenerateXmlReaderSettings()))
                {
                    xmlReader.Read();
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to process STIG file.");
                log.Debug("Exception details: " + exception);
            }
        }

        private XmlReaderSettings GenerateXmlReaderSettings()
        {
            try
            {
                XmlReaderSettings xmlReaderSettings = new XmlReaderSettings();
                xmlReaderSettings.IgnoreWhitespace = true;
                xmlReaderSettings.IgnoreComments = true;
                xmlReaderSettings.ValidationType = ValidationType.Schema;
                xmlReaderSettings.ValidationFlags = System.Xml.Schema.XmlSchemaValidationFlags.ProcessInlineSchema;
                xmlReaderSettings.ValidationFlags = System.Xml.Schema.XmlSchemaValidationFlags.ProcessSchemaLocation;
                return xmlReaderSettings;
            }
            catch (Exception exception)
            {
                log.Error("Unable to generate XmlReaderSettings.");
                throw exception;
            }
        }
    }
}
