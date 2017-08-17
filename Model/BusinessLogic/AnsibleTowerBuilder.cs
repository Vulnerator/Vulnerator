using log4net;
using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using Vulnerator.Model.DataAccess;
using Vulnerator.Model.Object;

namespace Vulnerator.Model.BusinessLogic
{
    public class AnsibleTowerBuilder
    {
        private DatabaseInterface databaseInterface = new DatabaseInterface();
        private static readonly ILog log = LogManager.GetLogger(typeof(Logger));
        public bool BuildRoles(string operatingSystem, string saveDirectory)
        { 
            try
            {
                if (!Directory.Exists(saveDirectory))
                { Directory.CreateDirectory(saveDirectory); }
                if (!DatabaseBuilder.sqliteConnection.State.ToString().Equals("Open"))
                { DatabaseBuilder.sqliteConnection.Open(); }
                using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                {
                    sqliteCommand.Parameters.Add(new SQLiteParameter("Operating_System", string.Format("%{0}%", operatingSystem)));
                    sqliteCommand.CommandText = Properties.Resources.SelectAnsibleTowerData;
                    using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
                    {
                        if (!sqliteDataReader.HasRows)
                        { return false; }
                        while (sqliteDataReader.Read())
                        {
                            string fileName = string.Format(
                                "{0}\\{1}.xml", 
                                saveDirectory, 
                                sqliteDataReader["Unique_Vulnerability_Identifier"].ToString()
                                );
                            using (XmlWriter xmlWriter = XmlWriter.Create(fileName, GenerateXmlWriterSettings()))
                            {
                                xmlWriter.WriteStartElement("finding");
                                
                                xmlWriter.WriteEndElement();
                            }
                        }
                    }
                }
                    return true;
            }
            catch (Exception exception)
            {
                log.Error(string.Format("\"{0}\" role file creation failed"));
                log.Debug("Exception details:", exception);
                return false;
            }
            finally
            { DatabaseBuilder.sqliteConnection.Close(); }
        }

        private XmlWriterSettings GenerateXmlWriterSettings()
        { 
            try
            {
                XmlWriterSettings xmlWriterSettings = new XmlWriterSettings();
                xmlWriterSettings.Indent = true;
                xmlWriterSettings.IndentChars = "\t";
                return xmlWriterSettings;
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to generate XmlWriterSettings."));
                log.Debug("Exception details:", exception);
                throw exception;
            }
        }
    }
}
