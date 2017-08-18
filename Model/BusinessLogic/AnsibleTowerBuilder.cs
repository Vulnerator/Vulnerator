using log4net;
using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
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
                                sqliteDataReader["Vulnerability_Group_ID"].ToString()
                                );
                            using (XmlWriter xmlWriter = XmlWriter.Create(fileName, GenerateXmlWriterSettings()))
                            {
                                string ruleId = string.Format(
                                    "{0}r{1}_rule",
                                    sqliteDataReader["Unique_Vulnerability_Identifier"].ToString(),
                                    sqliteDataReader["Vulnerability_Version"].ToString());
                                xmlWriter.WriteStartElement("finding");
                                xmlWriter.WriteAttributeString("v_id", sqliteDataReader["Vulnerability_Group_ID"].ToString());
                                xmlWriter.WriteAttributeString("rule_id", ruleId);
                                xmlWriter.WriteAttributeString("raw_risk", sqliteDataReader["Raw_Risk"].ToString());
                                xmlWriter.WriteAttributeString("datetime", string.Empty);
                                xmlWriter.WriteElementString("title", sqliteDataReader["Vulnerability_Title"].ToString());
                                xmlWriter.WriteElementString("discussion", sqliteDataReader["Vulnerability_Description"].ToString());
                                xmlWriter.WriteElementString("check_content", sqliteDataReader["Check_Content"].ToString());
                                xmlWriter.WriteElementString("fix_text", sqliteDataReader["Fix_Text"].ToString());
                                xmlWriter.WriteElementString("procedure", string.Empty);
                                xmlWriter.WriteElementString("output", string.Empty);
                                xmlWriter.WriteElementString("comments", string.Empty);
                                xmlWriter.WriteElementString("status", string.Empty);
                                xmlWriter.WriteStartElement("ccis");
                                Regex regex = new Regex(Properties.Resources.RegexCciSelector);
                                foreach (Match match in regex.Matches(sqliteDataReader["CCIs"].ToString()))
                                { xmlWriter.WriteElementString("cci", match.ToString()); }
                                xmlWriter.WriteEndElement();
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
