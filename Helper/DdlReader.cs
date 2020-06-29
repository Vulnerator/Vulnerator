using System;
using System.IO;
using System.Reflection;

namespace Vulnerator.Helper
{
    class DdlReader
    {
        public string ReadDdl(string ddlResourceFile, Assembly assembly)
        {
            try
            {
                string ddlText = string.Empty;
                using (Stream stream = assembly.GetManifestResourceStream(ddlResourceFile))
                {
                    using (StreamReader streamReader = new StreamReader(stream))
                    { ddlText = streamReader.ReadToEnd(); }
                }
                return ddlText;
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to read DDL Resource File '{ddlResourceFile}'.");
                throw exception;
            }
        }
    }
}
