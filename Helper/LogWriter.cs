using System;
using log4net;

namespace Vulnerator.Helper
{
    /// <summary>
    /// Class to handle writing logs for the application
    /// </summary>
    public static class LogWriter
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(Logger));

        public static void LogStatusUpdate(string message)
        {
            try
            { log.Info(message); }
            catch (Exception exception)
            {
                #if DEBUG
                throw exception;
                #endif
            }
        }

        /// <summary>
        /// Log writer to handle 'Error' level logging
        /// </summary>
        /// <param name="message">The 'Error' message to be logged</param>
        public static void LogError(string message)
        {
            try
            { log.Error(message); }
            catch (Exception exception)
            {
                #if DEBUG
                throw exception;
                #endif
            }
        }

        /// <summary>
        /// Log writer to handle 'Error' and 'Debug' level logging
        /// </summary>
        /// <param name="message">The 'Error' message to be logged</param>
        /// <param name="exception">The Exception to be logged in the 'Debug' output</param>
        public static void LogErrorWithDebug(string message, Exception ex)
        {
            try
            {
                log.Error(message);
                log.Debug($"Exception Details: {ex}");
            }
            catch (Exception exception)
            {
                #if DEBUG
                throw exception;
                #endif
            }
        }

        /// <summary>
        /// Log writer to handle 'Warn' level logging
        /// </summary>
        /// <param name="message">The 'Warn' message to be logged</param>
        public static void LogWarning(string message)
        {
            try
            { log.Warn(message); }
            catch (Exception exception)
            {
#if DEBUG
                throw exception;
#endif
            }
        }
    }
}
