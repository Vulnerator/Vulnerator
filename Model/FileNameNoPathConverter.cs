using log4net.Layout.Pattern;
using log4net.Core;
using System.IO;

namespace Vulnerator.Model
{
    public class FileNameNoPathConverter : PatternLayoutConverter
    {
        override protected void Convert(TextWriter writer, LoggingEvent loggingEvent)
        { writer.Write(Path.GetFileName(loggingEvent.LocationInformation.FileName)); }
    }
}
