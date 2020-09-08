using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using DocumentFormat.OpenXml.Drawing.Diagrams;

namespace Vulnerator.Helper
{
    public class BackgroundWorkerFactory
    {
        public void Build(DoWorkEventHandler doWork,
            RunWorkerCompletedEventHandler runWorkerCompleted = null,
            object arguments = null)
        {
            try
            {
                BackgroundWorker backgroundWorker = new BackgroundWorker();
                backgroundWorker.DoWork += doWork;
                if (runWorkerCompleted != null)
                { backgroundWorker.RunWorkerCompleted += runWorkerCompleted; }
                if (arguments != null)
                { backgroundWorker.RunWorkerAsync(arguments); }
                else
                { backgroundWorker.RunWorkerAsync(); }
                backgroundWorker.Dispose();
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to create a new BackgroundWorker using BackgroundWorkerFactory.");
                throw exception;
            }
        }
    }
}
