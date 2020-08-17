using log4net;
using log4net.Appender;
using log4net.Core;
using log4net.Layout;
using log4net.Repository.Hierarchy;
using log4net.Util;
using System;
using System.Diagnostics;

namespace Vulnerator.Helper
{
    /// <summary>
    /// Generates an instance of the log4net logging utility
    /// </summary>
    public class Logger
    {
        private static bool _isDebug;

        /// <summary>
        /// Sets up the log4net LogManager with the desired default values
        /// </summary>
        public void Setup()
        {
            try
            {
                SetIsDebugFlag();
                Hierarchy hierarchy = (Hierarchy)LogManager.GetRepository();
                hierarchy.Root.RemoveAllAppenders();
                PatternLayout patternLayout = new PatternLayout();
                patternLayout.AddConverter(new ConverterInfo
                {
                    Name = "fileNameNoPath",
                    Type = typeof(FileNameNoPathConverter)
                }
                );
                // patternLayout.ConversionPattern = "%-30d %-15level %-40fileNameNoPath %-20L %m%n";
                patternLayout.ConversionPattern = "%-30d %-15level %m%n";
                patternLayout.ActivateOptions();
                RollingFileAppender rollingFileAppender = GenerateRollingFileAppender(patternLayout);
                hierarchy.Root.AddAppender(rollingFileAppender);
                log4net.Config.BasicConfigurator.Configure(rollingFileAppender);

                if (_isDebug)
                { hierarchy.Root.Level = Level.All; }
                else
                { hierarchy.Root.Level = Level.Info; }
            }
            catch (Exception exception)
            {
                #if DEBUG
                throw exception;
                #endif
            }
        }

        /// <summary>
        /// Generates RollingFileAppender with Vulnerator-specific settings
        /// </summary>
        /// <param name="patternLayout">log4net.Layout.PatternLayout instance with file layout instructions</param>
        /// <returns>A log4net.Appender.RollingFileAppender with the required settings</returns>
        private RollingFileAppender GenerateRollingFileAppender(PatternLayout patternLayout)
        {
            try
            {
                RollingFileAppender rollingFileAppender = new RollingFileAppender();
                rollingFileAppender.LockingModel = new FileAppender.MinimalLock();
                rollingFileAppender.AppendToFile = true;
                rollingFileAppender.File = Properties.Settings.Default.LogPath;
                rollingFileAppender.Layout = patternLayout;
                rollingFileAppender.MaxSizeRollBackups = 5;
                rollingFileAppender.RollingStyle = RollingFileAppender.RollingMode.Once;
                rollingFileAppender.StaticLogFileName = true;
                rollingFileAppender.ActivateOptions();
                return rollingFileAppender;
            }
            catch (Exception exception)
            {
                #if DEBUG
                throw exception;
                #endif
            }
        }

        /// <summary>
        /// Sets a flag based on whether or not the application is in DEBUG mode
        /// </summary>
        [Conditional("DEBUG")]
        private void SetIsDebugFlag()
        { _isDebug = true; }
    }
}
