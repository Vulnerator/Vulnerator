using System;
using System.IO;
using System.Windows.Data;

namespace Vulnerator.View.ViewHelper
{
    class MyXmlDataProvider : XmlDataProvider
    {
        public new Uri Source
        {
            get { return base.Source; }
            set
            {
                base.Source = value;

                FileSystemWatcher watcher = new FileSystemWatcher();
                watcher.Path = AppDomain.CurrentDomain.BaseDirectory;

                watcher.Filter = value.OriginalString;

                watcher.Changed += new FileSystemEventHandler(file_Changed);

                watcher.EnableRaisingEvents = true;
            }
        }

        void file_Changed(object sender, FileSystemEventArgs e)
        {
            base.Refresh();
        }
    }
}
