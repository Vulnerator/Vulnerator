using log4net;
using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.IO;
using System.Reflection;
using System.Xml;
using Vulnerator.Model.Object;

namespace Vulnerator.Model.DataAccess
{
    public class DatabaseBuilder
    {
        private Assembly assembly = Assembly.GetExecutingAssembly();
        private static string databasePath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        private static string databaseFile = databasePath + @"\Vulnerator\Vulnerator.sqlite";
        public static string databaseConnection = @"Data Source = " + databaseFile + @"; Version=3;";
        private static readonly ILog log = LogManager.GetLogger(typeof(Logger));
        public static SQLiteConnection sqliteConnection = new SQLiteConnection(databaseConnection);
        public SQLiteTransaction sqliteTransaction;

        public DatabaseBuilder()
        {
            try
            {
                if (System.IO.File.Exists(databaseFile))
                { CheckDatabase(); }
                else
                { CreateDatabase(); }
            }
            catch (Exception exception)
            {
                log.Error("Unable create database file.");
                log.Debug("Exception details:", exception);
            }
        }

        private void CheckDatabase()
        {
            try
            {
                int currentVersion = 0;
                int latestVersion = 1;
                sqliteConnection.Open();
                using (SQLiteCommand sqliteCommand = new SQLiteCommand("PRAGMA user_version", sqliteConnection))
                { currentVersion = int.Parse(sqliteCommand.ExecuteScalar().ToString()); }
                sqliteConnection.Close();
                if (currentVersion == latestVersion)
                { return; }
                else
                {
                    using (SQLiteCommand sqliteCommand = new SQLiteCommand("", sqliteConnection))
                    {
                        for (int i = currentVersion; i <= latestVersion; i++)
                        { UpdateDatabase(i); }
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to verify the version of the Vulnerator Database.");
                throw exception;
            }
        }

        private void UpdateDatabase(int version)
        {
            try
            {
                switch (version)
                {
                    case 0:
                        {
                            System.IO.File.Delete(databaseFile);
                            CreateDatabase();
                            break;
                        }
                    default:
                        { break; }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to update the Vulnerator Database.");
                throw exception;
            }
        }

        private void CreateDatabase()
        {
            try
            {
                SQLiteConnection.CreateFile(databaseFile);
                sqliteConnection.Open();
                using (sqliteTransaction = sqliteConnection.BeginTransaction())
                {
                    using (SQLiteCommand sqliteCommand = new SQLiteCommand(ReadDdl("Vulnerator.Resources.DdlFiles.CreateDatabase.ddl"), sqliteConnection))
                    { sqliteCommand.ExecuteNonQuery(); }
                    ReadCciList();
                    sqliteTransaction.Commit();
                }
                sqliteConnection.Close();
                log.Info("Findings database created successfully.");
            }
            catch (Exception exception)
            {
                log.Error("Findings database creation failed.");
                throw exception;
            }
        }

        private string ReadDdl(string ddlResourceFile)
        {
            try
            {
                string ddlText = string.Empty;
                using (Stream stream = assembly.GetManifestResourceStream(ddlResourceFile))
                {
                    using (StreamReader streamReader = new StreamReader(stream))
                    { ddlText = streamReader.ReadToEnd(); }
                }
                return ddlText;
            }
            catch (Exception exception)
            {
                log.Error("Unable to read DDL Resource File.");
                throw exception;
            }
        }

        private void ReadCciList()
        {
            try
            {
                Cci cci = new Cci();
                using (Stream stream = assembly.GetManifestResourceStream("Vulnerator.Resources.U_CCI_List.xml"))
                {
                    using (XmlReader xmlReader = XmlReader.Create(stream))
                    {
                        while (xmlReader.Read())
                        {
                            if (xmlReader.IsStartElement())
                            {
                                switch (xmlReader.Name)
                                {
                                    case "cci_item":
                                        {
                                            cci = new Cci();
                                            cci.CciItem = xmlReader.GetAttribute("id");
                                            break;
                                        }
                                    case "status":
                                        {
                                            cci.Status = ObtainCurrentNodeValue(xmlReader);
                                            break;
                                        }
                                    case "definition":
                                        {
                                            cci.Definition = ObtainCurrentNodeValue(xmlReader);
                                            break;
                                        }
                                    case "type":
                                        {
                                            cci.Type = ObtainCurrentNodeValue(xmlReader);
                                            break;
                                        }
                                    case "references":
                                        {
                                            cci.CciReferences = ObtainCciReferences(xmlReader);
                                            break;
                                        }
                                    default:
                                        { break; }
                                }
                            }
                            else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("cci_item"))
                            { InsertCciValues(cci); }
                        }
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to parse CCI List.");
                throw exception;
            }
        }

        private string ObtainCurrentNodeValue(XmlReader xmlReader)
        {
            try
            {
                xmlReader.Read();
                string value = xmlReader.Value;
                return value;
            }
            catch (Exception exception)
            {
                log.Error("Unable to obtain currently accessed node value.");
                throw exception;
            }
        }

        private List<CciReference> ObtainCciReferences(XmlReader xmlReader)
        {
            try
            {
                List<CciReference> cciReferences = new List<CciReference>();
                while (xmlReader.Read())
                {
                    if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("references"))
                    { return cciReferences; }
                    else
                    {
                        cciReferences.Add(new CciReference()
                        {
                            Index = xmlReader.GetAttribute("index"),
                            Title = xmlReader.GetAttribute("title"),
                            Version = xmlReader.GetAttribute("version")
                        });
                    }
                }
                return cciReferences;
            }
            catch (Exception exception)
            {
                log.Error("Unable to obtain CCI References.");
                throw exception;
            }
        }

        private void InsertCciValues(Cci cci)
        {
            try
            {
                using (SQLiteCommand sqliteCommand = sqliteConnection.CreateCommand())
                {
                    sqliteCommand.Parameters.Add(new SQLiteParameter("CCI", cci.CciItem));
                    sqliteCommand.Parameters.Add(new SQLiteParameter("Definition", cci.Definition));
                    sqliteCommand.Parameters.Add(new SQLiteParameter("Type", cci.Type));
                    sqliteCommand.Parameters.Add(new SQLiteParameter("Status", cci.Status));
                    sqliteCommand.CommandText = "INSERT INTO Ccis VALUES (NULL, @CCI, @Definition, @Type, @Status);";
                    sqliteCommand.ExecuteNonQuery();
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to insert CCI Item into database.");
                throw exception;
            }
        }
    }
}