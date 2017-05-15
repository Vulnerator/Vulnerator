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
        //private static string databasePath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        private static string databaseFile = Properties.Settings.Default.Database;
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
                    PopulateCciData();
                    PopulateNistControls();
                    sqliteTransaction.Commit();
                }
                sqliteConnection.Close();
                log.Info("Database created successfully.");
            }
            catch (Exception exception)
            {
                log.Error("Database creation failed.");
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

        private void PopulateCciData()
        {
            try
            {
                Cci cci = new Cci();
                using (Stream stream = assembly.GetManifestResourceStream("Vulnerator.Resources.RawData.U_CCI_List.xml"))
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
                log.Error("Unable to populate CCI List.");
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

        private void PopulateNistControls()
        {
            try
            {
                // Set Initial C-I-A triad flags
                string highConfidentiality = string.Empty;
                string moderateConfidentiality = string.Empty;
                string lowConfidentiality = string.Empty;

                string highIntegrity = string.Empty;
                string moderateIntegrity = string.Empty;
                string lowIntegrity = string.Empty;

                string highAvailability = string.Empty;
                string moderateAvailability = string.Empty;
                string lowAvailability = string.Empty;

                Dictionary<string, string> ciaTriadFlags = new Dictionary<string, string>();

                using (SQLiteCommand sqliteCommand = sqliteConnection.CreateCommand())
                {
                    using (Stream stream = assembly.GetManifestResourceStream("Vulnerator.Resources.RawData.NIST_800-53_CNSS_Mapping.xml"))
                    {
                        using (XmlReader xmlReader = XmlReader.Create(stream))
                        {
                            while (xmlReader.Read())
                            {
                                if (xmlReader.IsStartElement())
                                {
                                    switch (xmlReader.Name)
                                    {
                                        case "Control":
                                            {
                                                ciaTriadFlags = new Dictionary<string, string>();
                                                sqliteCommand.Parameters.Add(new SQLiteParameter("Family", xmlReader.GetAttribute("family")));
                                                sqliteCommand.Parameters.Add(new SQLiteParameter("Number", xmlReader.GetAttribute("number")));
                                                if (!xmlReader.GetAttribute("enhancement").Equals("0"))
                                                { sqliteCommand.Parameters.Add(new SQLiteParameter("Enhancement", xmlReader.GetAttribute("enhancement"))); }
                                                break;
                                            }
                                        case "Title":
                                            {
                                                sqliteCommand.Parameters.Add(new SQLiteParameter("Title", ObtainCurrentNodeValue(xmlReader)));
                                                break;
                                            }
                                        case "Text":
                                            {
                                                sqliteCommand.Parameters.Add(new SQLiteParameter("Text", ObtainCurrentNodeValue(xmlReader)));
                                                break;
                                            }
                                        case "SupplementalGuidance":
                                            {
                                                sqliteCommand.Parameters.Add(new SQLiteParameter("SupplementalGuidance", ObtainCurrentNodeValue(xmlReader)));
                                                break;
                                            }
                                        case "Confidentiality":
                                            {
                                                ciaTriadFlags.Add("highConfidentiality", xmlReader.GetAttribute("high"));
                                                ciaTriadFlags.Add("moderateConfidentiality", xmlReader.GetAttribute("moderate"));
                                                ciaTriadFlags.Add("lowConfidentiality", xmlReader.GetAttribute("low"));
                                                break;
                                            }
                                        case "Integrity":
                                            {
                                                ciaTriadFlags.Add("highIntegrity", xmlReader.GetAttribute("high"));
                                                ciaTriadFlags.Add("moderateIntegrity", xmlReader.GetAttribute("moderate"));
                                                ciaTriadFlags.Add("lowIntegrity", xmlReader.GetAttribute("low"));
                                                break;
                                            }
                                        case "Availability":
                                            {
                                                ciaTriadFlags.Add("highAvailability", xmlReader.GetAttribute("high"));
                                                ciaTriadFlags.Add("moderateAvailability", xmlReader.GetAttribute("moderate"));
                                                ciaTriadFlags.Add("lowAvailability", xmlReader.GetAttribute("low"));
                                                break;
                                            }
                                        default:
                                            { break; }
                                    }
                                }
                                else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("Control"))
                                {
                                    InsertNistControls(sqliteCommand);
                                    sqliteCommand.CommandText = "SELECT last_insert_rowid();";
                                    string lastInsertId = sqliteCommand.ExecuteScalar().ToString();
                                    if (!string.IsNullOrWhiteSpace(highConfidentiality))
                                    { SetCiaValues(lastInsertId, "Confidentiality", "High", highConfidentiality, sqliteCommand); }
                                    if (!string.IsNullOrWhiteSpace(moderateConfidentiality))
                                    { SetCiaValues(lastInsertId, "Confidentiality", "Moderate", moderateConfidentiality, sqliteCommand); }
                                    if (!string.IsNullOrWhiteSpace(lowConfidentiality))
                                    { SetCiaValues(lastInsertId, "Confidentiality", "Low", lowConfidentiality, sqliteCommand); }
                                    if (!string.IsNullOrWhiteSpace(highIntegrity))
                                    { SetCiaValues(lastInsertId, "Integrity", "High", highIntegrity, sqliteCommand); }
                                    if (!string.IsNullOrWhiteSpace(moderateIntegrity))
                                    { SetCiaValues(lastInsertId, "Integrity", "Moderate", moderateIntegrity, sqliteCommand); }
                                    if (!string.IsNullOrWhiteSpace(lowIntegrity))
                                    { SetCiaValues(lastInsertId, "Integrity", "Low", lowIntegrity, sqliteCommand); }
                                    if (!string.IsNullOrWhiteSpace(highAvailability))
                                    { SetCiaValues(lastInsertId, "Availability", "High", highAvailability, sqliteCommand); }
                                    if (!string.IsNullOrWhiteSpace(moderateAvailability))
                                    { SetCiaValues(lastInsertId, "Availability", "Moderate", moderateAvailability, sqliteCommand); }
                                    if (!string.IsNullOrWhiteSpace(lowAvailability))
                                    { SetCiaValues(lastInsertId, "Availability", "Low", lowAvailability, sqliteCommand); }
                                    sqliteCommand.CommandText = string.Empty;
                                    sqliteCommand.Parameters.Clear();
                                    highConfidentiality = moderateConfidentiality = lowConfidentiality = string.Empty;
                                    highIntegrity = moderateIntegrity = lowIntegrity = string.Empty;
                                    highAvailability = moderateAvailability = lowAvailability = string.Empty;
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to populate NIST Control list.");
                throw exception;
            }
        }

        private void InsertNistControls(SQLiteCommand sqliteCommand)
        {
            try
            {
                if (!sqliteCommand.Parameters.Contains("SupplementalGuidance"))
                { sqliteCommand.Parameters.Add(new SQLiteParameter("SupplementalGuidance", string.Empty)); }
                if (sqliteCommand.Parameters.Contains("Enhancement"))
                { sqliteCommand.CommandText = "INSERT INTO NistControls VALUES (NULL, @Family, @Number, @Enhancement, @Title, @Text, @SupplementalGuidance);"; }
                else
                { sqliteCommand.CommandText = "INSERT INTO NistControls VALUES (NULL, @Family, @Number, NULL, @Title, @Text, @SupplementalGuidance);"; }
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                log.Error("Unable to insert NIST Controls into database.");
                throw exception;
            }
        }

        private void SetCiaValues(string nistControlId, string triadItem, string level, string parsedValue, SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.Parameters.Add(new SQLiteParameter("NIST_Control_ID", nistControlId));
                sqliteCommand.Parameters.Add(new SQLiteParameter("Level", level));
                if (parsedValue.Equals("NSS"))
                { sqliteCommand.Parameters.Add(new SQLiteParameter("IsNss", "True")); }
                else
                { sqliteCommand.Parameters.Add(new SQLiteParameter("IsNss", "False")); }
                if (triadItem.Equals("Confidentiality"))
                {
                    sqliteCommand.CommandText = "INSERT INTO NistControlsConfidentialityLevels VALUES " +
                        "(@NIST_Control_ID, (SELECT Confidentiality_ID FROM ConfidentialityLevels WHERE Confidentiality_Level = @Level), @IsNss);";
                }
                else if (triadItem.Equals("Integrity"))
                {
                    sqliteCommand.CommandText = "INSERT INTO NistControlsIntegrityLevels VALUES " +
                        "(@NIST_Control_ID, (SELECT Integrity_ID FROM IntegrityLevels WHERE Integrity_Level = @Level), @IsNss);";
                }
                else
                {
                    sqliteCommand.CommandText = "INSERT INTO NistControlsAvailabilityLevels VALUES " +
                        "(@NIST_Control_ID, (SELECT Availability_ID FROM AvailabilityLevels WHERE Availability_Level = @Level), @IsNss);";
                }
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                log.Error("Unable to insert NIST Control CIA Value.");
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
    }
}