using log4net.Layout.Pattern;
using log4net.Core;
using System.IO;
using System;

namespace Vulnerator.Helper
{
    public class FileNameNoPathConverter : PatternLayoutConverter
    {
        override protected void Convert(TextWriter writer, LoggingEvent loggingEvent)
        {
            try
            {
                writer.Write(Path.GetFileName(loggingEvent.LocationInformation.FileName));
            }
            catch (Exception exception)
            {
                #if DEBUG
                throw exception;
                #endif
            }
        }
    }
}
