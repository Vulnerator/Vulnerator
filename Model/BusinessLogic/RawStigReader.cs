using log4net;
using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data.SQLite;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Xml;
using Vulnerator.Model.DataAccess;
using Vulnerator.Model.Object;
using Vulnerator.ViewModel.ViewModelHelper;

namespace Vulnerator.Model.BusinessLogic
{
    public class RawStigReader
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(Logger));
        private int lastRowId = 0;

        public void ReadRawStig(ZipArchiveEntry rawStig)
        {
            try
            {
                log.Info(string.Format("Begin ingestion of raw STIG file {0}", rawStig.FullName));
                using (SQLiteTransaction sqliteTransaction = DatabaseBuilder.sqliteConnection.BeginTransaction())
                {
                    using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                    {
                        using (XmlReader xmlReader = XmlReader.Create(rawStig.Open(), GenerateXmlReaderSettings()))
                        {
                            while (xmlReader.Read())
                            {
                                if (xmlReader.IsStartElement())
                                {
                                    switch (xmlReader.Name)
                                    {
                                        case "Benchmark":
                                            {
                                                sqliteCommand.Parameters.Add(new SQLiteParameter("Vulnerability_Source_File_Name", rawStig.Name));
                                                ReadBenchmarkNode(sqliteCommand, xmlReader);
                                                break;
                                            }
                                        case "Group":
                                            {
                                                ReadGroupNode(sqliteCommand, xmlReader);
                                                break;
                                            }
                                        default:
                                            { break; }
                                    }
                                }
                            }
                        }
                    }
                    sqliteTransaction.Commit();
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to process STIG file.");
                log.Debug("Exception details: " + exception);
            }
        }

        private XmlReaderSettings GenerateXmlReaderSettings()
        {
            try
            {
                XmlReaderSettings xmlReaderSettings = new XmlReaderSettings();
                xmlReaderSettings.IgnoreWhitespace = true;
                xmlReaderSettings.IgnoreComments = true;
                xmlReaderSettings.ValidationType = ValidationType.Schema;
                xmlReaderSettings.ValidationFlags = System.Xml.Schema.XmlSchemaValidationFlags.ProcessInlineSchema;
                xmlReaderSettings.ValidationFlags = System.Xml.Schema.XmlSchemaValidationFlags.ProcessSchemaLocation;
                return xmlReaderSettings;
            }
            catch (Exception exception)
            {
                log.Error("Unable to generate XmlReaderSettings.");
                throw exception;
            }
        }

        private void ReadBenchmarkNode(SQLiteCommand sqliteCommand, XmlReader xmlReader)
        {
            try
            {
                sqliteCommand.Parameters.Add(new SQLiteParameter("Source_Secondary_Identifier", xmlReader.GetAttribute("id")));
                while (xmlReader.Read())
                {
                    if (xmlReader.IsStartElement())
                    {
                        switch (xmlReader.Name)
                        {
                            case "title":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Source_Name", ObtainCurrentNodeValue(xmlReader)));
                                    break;
                                }
                            case "description":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Source_Description", ObtainCurrentNodeValue(xmlReader)));
                                    break;
                                }
                            case "plain-text":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Source_Release", ObtainCurrentNodeValue(xmlReader)));
                                    break;
                                }
                            case "version":
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("Source_Version", ObtainCurrentNodeValue(xmlReader)));
                                    break;
                                }
                            case "Profile":
                                {
                                    sqliteCommand.CommandText = Properties.Resources.InsertVulnerabilitySource;
                                    foreach (SQLiteParameter parameter in sqliteCommand.Parameters)
                                    {
                                        if (sqliteCommand.Parameters.IndexOf(parameter) == 0)
                                        { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(44, parameter.ParameterName); }
                                        else
                                        { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(44, parameter.ParameterName + ", "); }
                                        
                                    }
                                    foreach (SQLiteParameter parameter in sqliteCommand.Parameters)
                                    {
                                        if (sqliteCommand.Parameters.IndexOf(parameter) == 0)
                                        { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(34, parameter.ParameterName); }
                                        else
                                        { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(34, parameter.ParameterName + ", "); }
                                    }
                                    sqliteCommand.ExecuteNonQuery();
                                    sqliteCommand.Parameters.Clear();
                                    sqliteCommand.CommandText = "SELECT last_insert_rowid();";
                                    lastRowId = int.Parse(sqliteCommand.ExecuteScalar().ToString());
                                    return;
                                }
                            default:
                                { break; }
                        }
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to process Benchmark node.");
                throw exception;
            }
        }

        private void ReadGroupNode(SQLiteCommand sqliteCommand, XmlReader xmlReader)
        {
            try
            {

            }
            catch (Exception exception)
            {
                log.Error("Unable to process Group node.");
                throw exception;
            }
        }

        private string ObtainCurrentNodeValue(XmlReader xmlReader)
        {
            try
            {
                xmlReader.Read();
                string value = xmlReader.Value;
                value = value.Replace("&gt", ">");
                value = value.Replace("&lt", "<");
                return value;
            }
            catch (Exception exception)
            {
                log.Error("Unable to obtain currently accessed node value.");
                throw exception;
            }
        }

        private string ConvertSeverityToRawRisk(string severity)
        {
            try
            {
                switch (severity)
                {
                    case "high":
                        { return "I"; }
                    case "medium":
                        { return "II"; }
                    case "low":
                        { return "III"; }
                    case "unknown":
                        { return "unknown"; }
                    default:
                        { return "unknown"; }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to convert impact to raw risk.");
                throw exception;
            }
        }
    }
}
