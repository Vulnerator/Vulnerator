using System;
using System.Diagnostics;
using System.IO;

namespace Vulnerator.Model
{
    public class WriteLog
    {
        public static string logPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + Path.DirectorySeparatorChar.ToString() + "Vulnerator";
        public static string logFile = logPath + Path.DirectorySeparatorChar.ToString() + @"VulneratorV6Log.txt";
        
        public static void LogWriter(Exception exception, string fileName)
        {
            #if DEBUG
                try
                {
                    if (!Directory.Exists(logPath))
                    { Directory.CreateDirectory(logPath); }

                    using (FileStream fs = new FileStream(logFile, FileMode.Append, FileAccess.Write))
                    {
                        using (StreamWriter sw = new StreamWriter(fs))
                        {
                        if (!string.IsNullOrWhiteSpace(fileName))
                            { sw.WriteLine("File Name :: " + fileName); }
                            sw.WriteLine(DateTime.Now + " :: " + exception.Message);
                            sw.WriteLine("Source :: " + exception.Source);
                            if (exception.InnerException != null)
                            { sw.WriteLine("Inner Exception :: " + exception.InnerException); }
                            sw.WriteLine();
                            sw.WriteLine("*************** BEGIN STACK TRACE ***************");
                            sw.WriteLine(exception.StackTrace);
                            sw.WriteLine("*************** END STACK TRACE ***************");
                            sw.WriteLine();
                            sw.WriteLine();
                            sw.Close();
                        }
                    }
                }
                catch
                { return; }
            #else
                try
                {
                    if (!Directory.Exists(logPath))
                    { Directory.CreateDirectory(logPath); }
                    using (FileStream fs = new FileStream(logFile, FileMode.Append, FileAccess.Write))
                    using (StreamWriter sw = new StreamWriter(fs))
                    {
                        sw.WriteLine(DateTime.Now);
                        sw.WriteLine(fileName);
                        sw.WriteLine(exception);
                        sw.Close();
                    }
                }
                catch
                { return; }
        #endif
        }


        public static void StringBasedLogWriter(string stringToWrite, string fileName)
        {
            try
            {
                if (!Directory.Exists(logPath))
                { Directory.CreateDirectory(logPath); }

                using (FileStream fs = new FileStream(logFile, FileMode.Append, FileAccess.Write))
                using (StreamWriter sw = new StreamWriter(fs))
                {
                    sw.WriteLine(DateTime.Now);
                    sw.WriteLine(fileName);
                    sw.WriteLine(stringToWrite);
                    sw.Close();
                }
            }
            catch
            { return; }
        }

        public static void DiagnosticsInformation(string filename, string processStatus, string stopwatchElapsed)
        {
            if (!Directory.Exists(logPath))
            { Directory.CreateDirectory(logPath); }

            try
            {
                using (FileStream fs = new FileStream(logFile, FileMode.Append, FileAccess.Write))
                using (StreamWriter sw = new StreamWriter(fs))
                {
                    if (String.IsNullOrWhiteSpace(stopwatchElapsed))
                    {
                        sw.WriteLine("{0} {1}: {2}", processStatus, filename, DateTime.Now.ToShortDateString() + " " + DateTime.Now.ToShortTimeString());
                        sw.Close();
                    }
                    else
                    {
                        sw.WriteLine("{0} {1}: Elapsed Time {2}", processStatus, filename, stopwatchElapsed);
                        sw.Close();
                    }
                }
            }
            catch (Exception exception)
            {
                WriteLog.LogWriter(exception, string.Empty);
                return;
            }
        }
    }
}
