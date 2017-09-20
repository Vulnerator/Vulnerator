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
        public static string databaseConnection = string.Format(
            @"Data Source = {0}; Version=3;datetimeformat=Ticks;", 
            Properties.Settings.Default.Database);
        private static readonly ILog log = LogManager.GetLogger(typeof(Logger));
        public static SQLiteConnection sqliteConnection = new SQLiteConnection(databaseConnection);

        public DatabaseBuilder()
        {
            try
            {
                if (!System.IO.File.Exists(Properties.Settings.Default.Database))
                {
                    CreateDatabase();
                    return;
                }
                if (!sqliteConnection.State.ToString().Equals("Open"))
                { sqliteConnection.Open(); }
                using (SQLiteTransaction sqliteTransaction = sqliteConnection.BeginTransaction())
                {
                    using (SQLiteCommand sqliteCommand = sqliteConnection.CreateCommand())
                    {
                        sqliteCommand.CommandText = "PRAGMA user_version";
                        int latestVersion = int.Parse(sqliteCommand.ExecuteScalar().ToString());
                        for (int i = 0; i <= latestVersion; i++)
                        { UpdateDatabase(i, sqliteCommand); }
                    }
                    sqliteTransaction.Commit();
                }
                
            }
            catch (Exception exception)
            {
                log.Error("Unable create database file.");
                log.Debug("Exception details:", exception);
            }
            finally
            { sqliteConnection.Close(); }
        }

        private void UpdateDatabase(int version, SQLiteCommand sqlitecommand)
        {
            try
            {
                switch (version)
                {
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
                log.Info("Begin creating database.");
                SQLiteConnection.CreateFile(Properties.Settings.Default.Database);
                if (!sqliteConnection.State.ToString().Equals("Open"))
                { sqliteConnection.Open(); }
                using (SQLiteTransaction sqliteTransaction = sqliteConnection.BeginTransaction())
                {
                    using (SQLiteCommand sqliteCommand = sqliteConnection.CreateCommand())
                    {
                        sqliteCommand.CommandText = ReadDdl("Vulnerator.Resources.DdlFiles.v6-2-0_CreateDatabase.ddl");
                        sqliteCommand.ExecuteNonQuery();
                        PopulateIaControlData(sqliteCommand);
                        PopulateCciData(sqliteCommand);
                        PopulateNistControls(sqliteCommand);
                        MapControlsToCci(sqliteCommand);
                        MapControlsToMonitoringFrequency(sqliteCommand);
                    }
                    sqliteTransaction.Commit();
                }
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

        private void PopulateIaControlData(SQLiteCommand sqliteCommand)
        {
            try
            {
                using (Stream stream = assembly.GetManifestResourceStream("Vulnerator.Resources.RawData.IAControls_Mapping.xml"))
                {
                    sqliteCommand.CommandText = "INSERT INTO IA_Controls VALUES (NULL, @Number, @Impact, @Area, @Name, @Description, @Threat, @Implementation, @Resources);";
                    using (XmlReader xmlReader = XmlReader.Create(stream))
                    {
                        while (xmlReader.Read())
                        {
                            if (xmlReader.IsStartElement())
                            {
                                switch (xmlReader.Name)
                                {
                                    case "IAControl":
                                        {
                                            sqliteCommand.Parameters.Add(new SQLiteParameter("Number", xmlReader.GetAttribute("number")));
                                            sqliteCommand.Parameters.Add(new SQLiteParameter("Impact", xmlReader.GetAttribute("impact")));
                                            sqliteCommand.Parameters.Add(new SQLiteParameter("Area", xmlReader.GetAttribute("subject-area")));
                                            break;
                                        }
                                    case "Control-Name":
                                        {
                                            sqliteCommand.Parameters.Add(new SQLiteParameter("Name", ObtainCurrentNodeValue(xmlReader)));
                                            break;
                                        }
                                    case "Description":
                                        {
                                            sqliteCommand.Parameters.Add(new SQLiteParameter("Description", ObtainCurrentNodeValue(xmlReader)));
                                            break;
                                        }
                                    case "Threat-Vuln-Countermeasure":
                                        {
                                            sqliteCommand.Parameters.Add(new SQLiteParameter("Threat", ObtainCurrentNodeValue(xmlReader)));
                                            break;
                                        }
                                    case "General-Implementation-Guidance":
                                        {
                                            sqliteCommand.Parameters.Add(new SQLiteParameter("Implementation", ObtainCurrentNodeValue(xmlReader)));
                                            break;
                                        }
                                    case "System-Specific-Guidance-Resources":
                                        {
                                            sqliteCommand.Parameters.Add(new SQLiteParameter("Resources", ObtainCurrentNodeValue(xmlReader)));
                                            break;
                                        }
                                    default:
                                        { break; }
                                }
                            }
                            else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("IAControl"))
                            {
                                sqliteCommand.ExecuteNonQuery();
                                sqliteCommand.Parameters.Clear();
                            }
                        }
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to populate IA Control List.");
                throw exception;
            }
        }

        private void PopulateCciData(SQLiteCommand sqliteCommand)
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
                                            cci.CciItem = xmlReader.GetAttribute("id").Replace("CCI-", string.Empty);
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
                            { InsertCciValues(cci, sqliteCommand); }
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

        private void InsertCciValues(Cci cci, SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.Parameters.Add(new SQLiteParameter("CCI", cci.CciItem));
                sqliteCommand.Parameters.Add(new SQLiteParameter("Definition", cci.Definition));
                sqliteCommand.Parameters.Add(new SQLiteParameter("Type", cci.Type));
                sqliteCommand.Parameters.Add(new SQLiteParameter("Status", cci.Status));
                sqliteCommand.CommandText = "INSERT INTO Ccis VALUES (NULL, @CCI, @Definition, @Type, @Status);";
                sqliteCommand.ExecuteNonQuery();
                sqliteCommand.Parameters.Clear();
            }
            catch (Exception exception)
            {
                log.Error("Unable to insert CCI Item into database.");
                throw exception;
            }
        }

        private void PopulateNistControls(SQLiteCommand sqliteCommand)
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
                { sqliteCommand.CommandText = "INSERT INTO NistControls VALUES (NULL, @Family, @Number, @Enhancement, @Title, @Text, @SupplementalGuidance, NULL);"; }
                else
                { sqliteCommand.CommandText = "INSERT INTO NistControls VALUES (NULL, @Family, @Number, NULL, @Title, @Text, @SupplementalGuidance, NULL);"; }
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

        private void MapControlsToCci(SQLiteCommand sqliteCommand)
        {
            try
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
                                if (!sqliteCommand.Parameters.Contains("DoD_AP"))
                                { sqliteCommand.Parameters.Add(new SQLiteParameter("DoD_AP", DBNull.Value)); }
                                if (sqliteCommand.Parameters.Contains("Enhancement"))
                                {
                                    sqliteCommand.CommandText = "INSERT INTO NistControlsCCIs VALUES " +
                                        "((SELECT NIST_Control_ID FROM NistControls WHERE Control_Family = @Family AND Control_Number = @Number AND Enhancement = @Enhancement), " +
                                        "(SELECT CCI_ID FROM CCIs WHERE CCI = @CCI), @DoD_AP, @ControlIndicator, @ImplementationGuidance, @AP_Text);";
                                }
                                else
                                {
                                    sqliteCommand.CommandText = "INSERT INTO NistControlsCCIs VALUES " +
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
            catch (Exception exception)
            {
                log.Error("Unable to map NIST Controls to CCI values.");
                throw exception;
            }
        }

        private void MapControlsToCnssOverlays(SQLiteCommand sqliteCommand)
        {
            try
            {
                Dictionary<string, string> overlayApplicability = new Dictionary<string, string>();
                using (Stream stream = assembly.GetManifestResourceStream("Vulnerator.Resources.RawData.NIST_800-53_CNSS-Overlay_Mapping.xml"))
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
                                            sqliteCommand.Parameters.Add(new SQLiteParameter("Family", xmlReader.GetAttribute("family")));
                                            sqliteCommand.Parameters.Add(new SQLiteParameter("Number", xmlReader.GetAttribute("number")));
                                            if (!xmlReader.GetAttribute("enhancement").Equals("0"))
                                            { sqliteCommand.Parameters.Add(new SQLiteParameter("Enhancement", xmlReader.GetAttribute("enhancement"))); }
                                            break;
                                        }
                                    default:
                                        {
                                            overlayApplicability.Add(xmlReader.Name.Replace("-", " "), ObtainCurrentNodeValue(xmlReader));
                                            break;
                                        }
                                }
                            }
                            else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("Control"))
                            {
                                if (sqliteCommand.Parameters.Contains("enhancement"))
                                {

                                }
                                else
                                {

                                }
                            }
                        }
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to map NIST controls to CNSS 1523 Overlays.");
                throw exception;
            }
        }

        private void MapControlsToMonitoringFrequency(SQLiteCommand sqliteCommand)
        {
            try
            {
                using (Stream stream = assembly.GetManifestResourceStream("Vulnerator.Resources.RawData.NIST_800-53_MonitoringFrequency_Mapping.xml"))
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
                                            sqliteCommand.Parameters.Add(new SQLiteParameter("Family", xmlReader.GetAttribute("family")));
                                            sqliteCommand.Parameters.Add(new SQLiteParameter("Number", xmlReader.GetAttribute("number")));
                                            if (!xmlReader.GetAttribute("enhancement").Equals("0"))
                                            { sqliteCommand.Parameters.Add(new SQLiteParameter("Enhancement", xmlReader.GetAttribute("enhancement"))); }
                                            break;
                                        }
                                    case "Frequency":
                                        {
                                            sqliteCommand.Parameters.Add(new SQLiteParameter("Frequency", ObtainCurrentNodeValue(xmlReader)));
                                            break;
                                        }
                                    default:
                                        { break; }
                                }
                            }
                            else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("Control"))
                            {
                                if (sqliteCommand.Parameters.Contains("Enhancement"))
                                {
                                    sqliteCommand.CommandText = "UPDATE NistControls SET Monitoring_Frequency = @Frequency WHERE Control_Family = @Family AND " +
                                        "Control_Number = @Number AND Enhancement = @Enhancement;";
                                }
                                else
                                {
                                    sqliteCommand.CommandText = "UPDATE NistControls SET Monitoring_Frequency = @Frequency WHERE Control_Family = @Family AND " +
                                        "Control_Number = @Number AND Enhancement IS NULL;";
                                }
                                sqliteCommand.ExecuteNonQuery();
                                sqliteCommand.Parameters.Clear();
                            }
                        }
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to map NIST controls to monitoring frequencies.");
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