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
                    MapControlsToCci();
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
                                                ciaTriadFlags.Add("HighConfidentiality", xmlReader.GetAttribute("high"));
                                                ciaTriadFlags.Add("ModerateConfidentiality", xmlReader.GetAttribute("moderate"));
                                                ciaTriadFlags.Add("LowConfidentiality", xmlReader.GetAttribute("low"));
                                                break;
                                            }
                                        case "Integrity":
                                            {
                                                ciaTriadFlags.Add("HighIntegrity", xmlReader.GetAttribute("high"));
                                                ciaTriadFlags.Add("ModerateIntegrity", xmlReader.GetAttribute("moderate"));
                                                ciaTriadFlags.Add("LowIntegrity", xmlReader.GetAttribute("low"));
                                                break;
                                            }
                                        case "Availability":
                                            {
                                                ciaTriadFlags.Add("HighAvailability", xmlReader.GetAttribute("high"));
                                                ciaTriadFlags.Add("ModerateAvailability", xmlReader.GetAttribute("moderate"));
                                                ciaTriadFlags.Add("LowAvailability", xmlReader.GetAttribute("low"));
                                                break;
                                            }
                                        default:
                                            { break; }
                                    }
                                }
                                else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("Control"))
                                {
                                    InsertNistControls(sqliteCommand);
                                    MapControlsToCia(sqliteCommand, ciaTriadFlags);
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

        private void MapControlsToCia(SQLiteCommand sqliteCommand, Dictionary<string, string> ciaTriadFlags)
        {
            try
            {
                sqliteCommand.CommandText = "SELECT last_insert_rowid();";
                sqliteCommand.Parameters.Add(new SQLiteParameter("NIST_Control_ID", sqliteCommand.ExecuteScalar().ToString()));
                foreach (string key in ciaTriadFlags.Keys)
                {
                    // Skip item or set IsNss Flag, as applicable
                    if (ciaTriadFlags[key].Equals("false"))
                    { continue; }
                    else if (ciaTriadFlags[key].Equals("NSS"))
                    { sqliteCommand.Parameters.Add(new SQLiteParameter("IsNss", "True")); }
                    else
                    { sqliteCommand.Parameters.Add(new SQLiteParameter("IsNss", "False")); }

                    // Set appropriate applicability level for C-I-A triad item
                    if (key.Contains("High"))
                    { sqliteCommand.Parameters.Add(new SQLiteParameter("Level", "High")); }
                    else if (key.Contains("Moderate"))
                    { sqliteCommand.Parameters.Add(new SQLiteParameter("Level", "Moderate")); }
                    else
                    { sqliteCommand.Parameters.Add(new SQLiteParameter("Level", "Low")); }

                    // Insert data into appropriate table
                    if (key.Contains("Confidentiality"))
                    {
                        sqliteCommand.CommandText = "INSERT INTO NistControlsConfidentialityLevels VALUES " +
                            "(@NIST_Control_ID, (SELECT Confidentiality_ID FROM ConfidentialityLevels WHERE Confidentiality_Level = @Level), @IsNss);";
                    }
                    else if (key.Contains("Integrity"))
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
                    sqliteCommand.Parameters.Remove(sqliteCommand.Parameters["IsNss"]);
                    sqliteCommand.Parameters.Remove(sqliteCommand.Parameters["Level"]);

                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to map NIST Controls to CIA Triad.");
                throw exception;
            }
        }

        private void MapControlsToCci()
        {
            try
            {
                using (SQLiteCommand sqliteCommand = sqliteConnection.CreateCommand())
                {
                    using (Stream stream = assembly.GetManifestResourceStream("Vulnerator.Resources.RawData.NIST_800-53_CCI_Mapping.xml"))
                    {
                        using (XmlReader xmlReader = XmlReader.Create(stream))
                        {
                            while (xmlReader.Read())
                            {
                                if (xmlReader.IsStartElement())
                                {
                                    switch (xmlReader.Name)
                                    {
                                        case "Pair":
                                            {
                                                sqliteCommand.Parameters.Add(new SQLiteParameter("Family", xmlReader.GetAttribute("family")));
                                                sqliteCommand.Parameters.Add(new SQLiteParameter("Number", xmlReader.GetAttribute("number")));
                                                if (!xmlReader.GetAttribute("enhancement").Equals("0"))
                                                { sqliteCommand.Parameters.Add(new SQLiteParameter("Enhancement", xmlReader.GetAttribute("enhancement"))); }
                                                sqliteCommand.Parameters.Add(new SQLiteParameter("DoD_AP", xmlReader.GetAttribute("dod-ap")));
                                                sqliteCommand.Parameters.Add(new SQLiteParameter("ControlIndicator", xmlReader.GetAttribute("indicator")));
                                                sqliteCommand.Parameters.Add(new SQLiteParameter("CCI", xmlReader.GetAttribute("cci")));
                                                break;
                                            }
                                        case "ImplementationGuidance":
                                            {
                                                sqliteCommand.Parameters.Add(new SQLiteParameter("ImplementationGuidance", ObtainCurrentNodeValue(xmlReader)));
                                                break;
                                            }
                                        case "AssessmentProcedures":
                                            {
                                                sqliteCommand.Parameters.Add(new SQLiteParameter("AP_Text", ObtainCurrentNodeValue(xmlReader)));
                                                break;
                                            }
                                        default:
                                            { break; }
                                    }
                                }
                                else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("Pair"))
                                {
                                    if (sqliteCommand.Parameters.Contains("Enhancement"))
                                    {
                                        sqliteCommand.CommandText = "INSERT INTO NistcontrolsCCIs VALUES " +
                                            "((SELECT NIST_Control_ID FROM NistControls WHERE Control_Family = @Family AND Control_Number = @Number AND Enhancement = @Enhancement), " +
                                            "(SELECT CCI_ID FROM CCIs WHERE CCI = @CCI), @DoD_AP, @ControlIndicator, @ImplementationGuidance, @AP_Text);";
                                    }
                                    else
                                    {
                                        sqliteCommand.CommandText = "INSERT INTO NistcontrolsCCIs VALUES " +
                                            "((SELECT NIST_Control_ID FROM NistControls WHERE Control_Family = @Family AND Control_Number = @Number AND Enhancement IS NULL), " +
                                            "(SELECT CCI_ID FROM CCIs WHERE CCI = @CCI), @DoD_AP, @ControlIndicator, @ImplementationGuidance, @AP_Text);";
                                    }
                                    sqliteCommand.ExecuteNonQuery();
                                    sqliteCommand.Parameters.Clear();
                                }
                            }
                        }
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to map NIST Controls to CCI values.");
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