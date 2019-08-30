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
                    sqliteCommand.Parameters.Add(new SQLiteParameter("Operating_System", $"%{operatingSystem}%"));
                    sqliteCommand.CommandText = Properties.Resources.SelectAnsibleTowerData;
                    using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
                    {
                        if (!sqliteDataReader.HasRows)
                        { return false; }
                        while (sqliteDataReader.Read())
                        {
                            string fileName =
                                $"{saveDirectory}\\{sqliteDataReader["Vulnerability_Group_ID"].ToString()}.xml";
                            using (XmlWriter xmlWriter = XmlWriter.Create(fileName, GenerateXmlWriterSettings()))
                            {
                                string ruleId =
                                    $"{sqliteDataReader["Unique_Vulnerability_Identifier"].ToString()}r{sqliteDataReader["Vulnerability_Version"].ToString()}_rule";
                                xmlWriter.WriteStartElement("finding");
                                xmlWriter.WriteAttributeString("v_id", sqliteDataReader["Vulnerability_Group_ID"].ToString());
                                xmlWriter.WriteAttributeString("rule_id", ruleId);
                                xmlWriter.WriteAttributeString("raw_risk", sqliteDataReader["Raw_Risk"].ToString());
                                xmlWriter.WriteAttributeString("datetime", "{{ ansible_date_time.date }}");
                                xmlWriter.WriteElementString("title", sqliteDataReader["Vulnerability_Title"].ToString());
                                xmlWriter.WriteElementString("discussion", sqliteDataReader["Vulnerability_Description"].ToString());
                                xmlWriter.WriteElementString("check_content", sqliteDataReader["Check_Content"].ToString());
                                xmlWriter.WriteElementString("fix_text", sqliteDataReader["Fix_Text"].ToString());
                                xmlWriter.WriteElementString("procedure", "{ Procedure goes here }");
                                xmlWriter.WriteElementString("output", "{ Output goes here }");
                                xmlWriter.WriteElementString("comments", "{ Comments go here }");
                                xmlWriter.WriteElementString("status", "{ Status goes here }");
                                xmlWriter.WriteStartElement("ccis");
                                Regex regex = new Regex(Properties.Resources.RegexCciSelector);
                                foreach (Match match in regex.Matches(sqliteDataReader["CCIs"].ToString()))
                                {
                                    if (!string.IsNullOrWhiteSpace(match.ToString()))
                                    { xmlWriter.WriteElementString("cci", $"CCI-{match.ToString()}"); }
                                }
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
                XmlWriterSettings xmlWriterSettings = new XmlWriterSettings()
                {
                    Indent = true,
                    OmitXmlDeclaration = true,
                    NewLineOnAttributes = true,
                    IndentChars = "\t",
                    NewLineChars = Environment.NewLine,
                    NewLineHandling = NewLineHandling.Replace
                };
                
                return xmlWriterSettings;
            }
            catch (Exception exception)
            {
                log.Error("Unable to generate XmlWriterSettings.");
                log.Debug("Exception details:", exception);
                throw exception;
            }
        }
    }
}
