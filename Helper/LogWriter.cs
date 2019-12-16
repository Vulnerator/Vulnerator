using System;
using log4net;

namespace Vulnerator.Helper
{
    /// <summary>
    /// Class to handle writing logs for the application
    /// </summary>
    public class LogWriter
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(Model.Object.Logger));

        public void LogStatusUpdate(string message)
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
        public void LogError(string message)
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
        public void LogErrorWithDebug(string message, Exception ex)
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
    }
}
