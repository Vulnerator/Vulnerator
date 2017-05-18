using log4net;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using Vulnerator.Model.BusinessLogic;
using Vulnerator.Model.Object;
using Vulnerator.ViewModel.ViewModelHelper;

namespace Vulnerator.Model.BusinessLogic
{
    public class RawStigReader
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(Logger));

        public string ReadRawStig(string filename)
        {
            try
            {
                log.Info(string.Format("Begin ingestion of raw STIG file {0}", filename));
                using (ZipArchive zipArchive = ZipFile.Open(filename, ZipArchiveMode.Read))
                {
                    foreach (ZipArchiveEntry entry in zipArchive.Entries.Where(x => x.Name.Contains("zip") && x.Name.Contains("STIG")))
                    {
                        Console.WriteLine(entry.Name);
                    }
                }
                return "Success";
            }
            catch (Exception exception)
            {
                log.Error("Unable to process STIG file.");
                log.Debug("Exception details: " + exception);
                return "Error";
            }
        }
    }
}
