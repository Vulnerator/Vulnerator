using log4net;
using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml;
using Vulnerator.Model.DataAccess;
using Vulnerator.Model.Entity;
using Vulnerator.Model.Object;

namespace Vulnerator.Model.BusinessLogic
{
    public class CklCreator
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(Logger));

        public void CreateCklFromHardware(Hardware hardware, VulnerabilitySource vulnerabilitySource, string saveDirectory)
        { 
            try
            {
                if (!DatabaseBuilder.sqliteConnection.State.ToString().Equals("Open"))
                { DatabaseBuilder.sqliteConnection.Open(); }
                using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                {
                    sqliteCommand.Parameters.Add(new SQLiteParameter("Hardware_ID", hardware.Hardware_ID));
                    sqliteCommand.Parameters.Add(new SQLiteParameter("Vulnerability_Source_ID", vulnerabilitySource.Vulnerability_Source_ID));
                    sqliteCommand.CommandText = Properties.Resources.SelectHardwareCklCreationData;
                    using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
                    {
                        if (sqliteDataReader.HasRows)
                        {
                            string stigName = vulnerabilitySource.Source_Name
                                    .Replace(" ", string.Empty)
                                    .Replace("Security Technical Implentation Guide", "_STIG");
                            string saveFile = string.Format("{0}\\U_{1}_v{2}_r{3}_{4}.ckl",
                                saveDirectory, stigName, vulnerabilitySource.Source_Version,
                                vulnerabilitySource.Source_Release, hardware.Displayed_Host_Name);
                            using (XmlWriter xmlWriter = XmlWriter.Create(saveFile, GenerateXmlWriterSettings()))
                            {
                                xmlWriter.WriteStartDocument(true);
                                xmlWriter.WriteStartElement("CHECKLIST");
                                int i = 0;
                                while (sqliteDataReader.Read())
                                {
                                    if (i == 0)
                                    {
                                        WriteAssetInformation(sqliteDataReader, xmlWriter);
                                        WriteStigInformation(sqliteDataReader, xmlWriter);
                                        i++;
                                    }
                                    WriteVulnerabilityInformation(sqliteDataReader, xmlWriter);
                                }
                                xmlWriter.WriteEndElement();
                                xmlWriter.WriteEndElement();
                                xmlWriter.WriteEndElement();
                            }
                        }
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to generate a CKL for {0} - {1}.",
                    hardware.Displayed_Host_Name, vulnerabilitySource.Source_Name));
                throw exception;
            }
            finally
            { DatabaseBuilder.sqliteConnection.Close(); }
        }

        private void WriteAssetInformation(SQLiteDataReader sqliteDataReader, XmlWriter xmlWriter)
        { 
            try
            {

            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to write CKL asset information."));
                throw exception;
            }
        }

        private void WriteStigInformation(SQLiteDataReader sqliteDataReader, XmlWriter xmlWriter)
        { 
            try
            {
                xmlWriter.WriteStartElement("STIGS");
                xmlWriter.WriteStartElement("iSTIG");
                xmlWriter.WriteStartElement("STIG_INFO");
                WriteSiDataNode(xmlWriter, "version", sqliteDataReader["Source_Version"].ToString());
                WriteSiDataNode(xmlWriter, "classification", sqliteDataReader["Classification"].ToString());
                WriteSiDataNode(xmlWriter, "customname", string.Empty);
                WriteSiDataNode(xmlWriter, "stigid", sqliteDataReader["Source_Secondary_Identifier"].ToString());
                WriteSiDataNode(xmlWriter, "description", sqliteDataReader["Source_Description"].ToString());
                WriteSiDataNode(xmlWriter, "filename", sqliteDataReader["Vulnerability_Source_File_Name"].ToString());
                WriteSiDataNode(xmlWriter, "releaseinfo", sqliteDataReader["Source_Release"].ToString());
                WriteSiDataNode(xmlWriter, "title", sqliteDataReader["Source_Name"].ToString());
                xmlWriter.WriteEndElement();
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to write CKL STIG information."));
                throw exception;
            }
        }

        private void WriteSiDataNode(XmlWriter xmlWriter, string sidName, string sidData)
        { 
            try
            {
                xmlWriter.WriteStartElement("SI_DATA");
                xmlWriter.WriteElementString("SID_NAME", sidName);
                xmlWriter.WriteElementString("SID_DATA", sidData);
                xmlWriter.WriteEndElement();
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to generate SI_DATA node."));
                throw exception;
            }
        }

        private void WriteVulnerabilityInformation(SQLiteDataReader sqliteDataReader, XmlWriter xmlWriter)
        { 
            try
            {

            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to write CKL vulnerability node."));
                throw exception;
            }
        }

        private XmlWriterSettings GenerateXmlWriterSettings()
        {
            try
            {
                XmlWriterSettings xmlWriterSettings = new XmlWriterSettings()
                {
                    Encoding = Encoding.UTF8,
                    Indent = true,
                    NewLineOnAttributes = true,
                    IndentChars = "\t",
                    NewLineChars = Environment.NewLine,
                    NewLineHandling = NewLineHandling.Replace
                };

                return xmlWriterSettings;
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to generate XmlWriterSettings."));
                throw exception;
            }
        }
    }
}
