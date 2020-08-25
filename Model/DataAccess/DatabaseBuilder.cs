using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SQLite;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Xml;
using GalaSoft.MvvmLight.Messaging;
using GalaSoft.MvvmLight.Threading;
using Vulnerator.Helper;
using Vulnerator.Model.Object;
using Vulnerator.ViewModel;
using File = System.IO.File;

namespace Vulnerator.Model.DataAccess
{
    public class DatabaseBuilder
    {
        private DdlReader _ddlReader = new DdlReader();
        private Assembly assembly = Assembly.GetExecutingAssembly();

        public static string databaseConnection =
            $@"Data Source = {Properties.Settings.Default.Database}; Version=3;datetimeformat=Ticks;";

        public static SQLiteConnection sqliteConnection = new SQLiteConnection(databaseConnection);

        public DatabaseBuilder()
        {
            try
            {
                CreateDatabase();
            }
            catch (Exception exception)
            {
                string error = $"Unable create database file '{Properties.Settings.Default.Database}'.";
                LogWriter.LogErrorWithDebug(error, exception);
            }
            finally
            {
                sqliteConnection.Close();
            }
        }

        private void CreateDatabase()
        {
            try
            {
                LogWriter.LogStatusUpdate(
                    $"Begin verifying and, if needed, creating and / or updating database '{Properties.Settings.Default.Database}'.");
                if (!File.Exists(Properties.Settings.Default.Database))
                {
                    SQLiteConnection.CreateFile(Properties.Settings.Default.Database);
                }

                if (!sqliteConnection.State.ToString().Equals("Open"))
                {
                    sqliteConnection.Open();
                }

                using (SQLiteTransaction sqliteTransaction = sqliteConnection.BeginTransaction())
                {
                    using (SQLiteCommand sqliteCommand = sqliteConnection.CreateCommand())
                    {
                        string[] resourceNames = Assembly.GetExecutingAssembly().GetManifestResourceNames();
                        foreach (string name in resourceNames.Where(x =>
                            x.Contains("Vulnerator.Resources.DdlFiles.Tables.Create.")))
                        {
                            string loadingText =
                                $"Verifying table '{name.Replace("Vulnerator.Resources.DdlFiles.Tables.Create.", "").Replace(".ddl", "")}'";
                            Messenger.Default.Send(loadingText, MessengerToken.LoadingTextUpdated);
                            LogWriter.LogStatusUpdate( loadingText);
                            sqliteCommand.CommandText = _ddlReader.ReadDdl(name, assembly);
                            sqliteCommand.ExecuteNonQuery();
                        }

                        foreach (string name in resourceNames
                            .Where(x => x.Contains("Vulnerator.Resources.DdlFiles.Tables.Insert.Data.")).AsEnumerable())
                        {
                            LogWriter.LogStatusUpdate(
                                $"Verifying table '{name.Replace("Vulnerator.Resources.DdlFiles.Tables.Insert.Data.", "").Replace(".ddl", "")}' base data exists.");
                            sqliteCommand.CommandText = _ddlReader.ReadDdl(name, assembly);
                            sqliteCommand.ExecuteNonQuery();
                        }

                        sqliteCommand.ExecuteNonQuery();
                        PopulateIaControlData(sqliteCommand);
                        PopulateCciData(sqliteCommand);
                        PopulateNistControls(sqliteCommand);
                        MapControlsToCci(sqliteCommand);
                        MapControlsToCnssOverlays(sqliteCommand);
                        MapControlsToMonitoringFrequency(sqliteCommand);
                        InsertUserReportSettings(sqliteCommand);
                    }

                    sqliteTransaction.Commit();
                }

                LogWriter.LogStatusUpdate($"Database '{Properties.Settings.Default.Database}' verified successfully.");
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Database '{Properties.Settings.Default.Database}' verification failed.");
                throw exception;
            }
        }

        private void PopulateIaControlData(SQLiteCommand sqliteCommand)
        {
            try
            {
                LogWriter.LogStatusUpdate("Verifying IA Controls are populated.");
                using (Stream stream =
                    assembly.GetManifestResourceStream("Vulnerator.Resources.RawData.IAControls_Mapping.xml"))
                {
                    sqliteCommand.CommandText =
                        "INSERT INTO IA_Controls VALUES (NULL, @Number, @Impact, @Area, @Name, @Description, @Threat, @Implementation, @Resources);";
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
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("Number",
                                            xmlReader.GetAttribute("number")));
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("Impact",
                                            xmlReader.GetAttribute("impact")));
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("Area",
                                            xmlReader.GetAttribute("subject-area")));
                                        break;
                                    }
                                    case "Control-Name":
                                    {
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("Name",
                                            xmlReader.ObtainCurrentNodeValue(false)));
                                        break;
                                    }
                                    case "Description":
                                    {
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("Description",
                                            xmlReader.ObtainCurrentNodeValue(false)));
                                        break;
                                    }
                                    case "Threat-Vuln-Countermeasure":
                                    {
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("Threat",
                                            xmlReader.ObtainCurrentNodeValue(false)));
                                        break;
                                    }
                                    case "General-Implementation-Guidance":
                                    {
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("Implementation",
                                            xmlReader.ObtainCurrentNodeValue(false)));
                                        break;
                                    }
                                    case "System-Specific-Guidance-Resources":
                                    {
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("Resources",
                                            xmlReader.ObtainCurrentNodeValue(false)));
                                        break;
                                    }
                                    default:
                                    {
                                        break;
                                    }
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
                LogWriter.LogError("Unable to verify IA Control table data.");
                throw exception;
            }
        }

        private void PopulateCciData(SQLiteCommand sqliteCommand)
        {
            try
            {
                LogWriter.LogStatusUpdate("Verifying CCIs are populated.");
                Cci cci = new Cci();
                string version = string.Empty;
                using (Stream stream =
                    assembly.GetManifestResourceStream("Vulnerator.Resources.RawData.U_CCI_List.xml"))
                {
                    using (XmlReader xmlReader = XmlReader.Create(stream))
                    {
                        while (xmlReader.Read())
                        {
                            if (xmlReader.IsStartElement())
                            {
                                switch (xmlReader.Name)
                                {
                                    case "version":
                                    {
                                        version = xmlReader.ObtainCurrentNodeValue(false).ToString();
                                        break;
                                    }
                                    case "cci_item":
                                    {
                                        cci = new Cci();
                                        cci.CciItem = xmlReader.GetAttribute("id").Replace("CCI-", string.Empty);
                                        break;
                                    }
                                    case "status":
                                    {
                                        cci.Status = xmlReader.ObtainCurrentNodeValue(false).ToString();
                                        break;
                                    }
                                    case "definition":
                                    {
                                        cci.Definition = xmlReader.ObtainCurrentNodeValue(false).ToString();
                                        break;
                                    }
                                    case "type":
                                    {
                                        cci.Type = xmlReader.ObtainCurrentNodeValue(false).ToString();
                                        break;
                                    }
                                    case "references":
                                    {
                                        cci.CciReferences = ObtainCciReferences(xmlReader);
                                        break;
                                    }
                                }
                            }
                            else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("cci_item"))
                            {
                                InsertCciValues(cci, sqliteCommand, version);
                            }
                        }
                    }
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to verify CCI table data.");
                throw exception;
            }
        }

        private void InsertCciValues(Cci cci, SQLiteCommand sqliteCommand, string version)
        {
            try
            {
                DateTime versionDateTime = DateTime.ParseExact(version, "yyyy-MM-dd",
                    System.Globalization.CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.None);
                sqliteCommand.Parameters.Add(new SQLiteParameter("CCI", cci.CciItem));
                sqliteCommand.Parameters.Add(new SQLiteParameter("Definition", cci.Definition));
                sqliteCommand.Parameters.Add(new SQLiteParameter("Type", cci.Type));
                sqliteCommand.Parameters.Add(new SQLiteParameter("Status", cci.Status));
                sqliteCommand.Parameters.Add(new SQLiteParameter("Version", versionDateTime));
                sqliteCommand.CommandText = "INSERT INTO Ccis VALUES (NULL, @CCI, @Definition, @Type, @Status, @Version);";
                sqliteCommand.ExecuteNonQuery();
                sqliteCommand.Parameters.Clear();
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to insert CCI item '{cci.CciItem}' into database.");
                throw exception;
            }
        }

        private void PopulateNistControls(SQLiteCommand sqliteCommand)
        {
            try
            {
                LogWriter.LogStatusUpdate("Verifying NIST Controls are populated.");
                Dictionary<string, string> ciaTriadFlags = new Dictionary<string, string>();

                using (Stream stream =
                    assembly.GetManifestResourceStream("Vulnerator.Resources.RawData.NIST_800-53_CNSS_Mapping.xml"))
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
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("Family",
                                            xmlReader.GetAttribute("family")));
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("Number",
                                            xmlReader.GetAttribute("number")));
                                        if (!xmlReader.GetAttribute("enhancement").Equals("0"))
                                        {
                                            sqliteCommand.Parameters.Add(new SQLiteParameter("Enhancement",
                                                xmlReader.GetAttribute("enhancement")));
                                        }

                                        break;
                                    }
                                    case "Title":
                                    {
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("Title",
                                            xmlReader.ObtainCurrentNodeValue(false)));
                                        break;
                                    }
                                    case "Text":
                                    {
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("Text",
                                            xmlReader.ObtainCurrentNodeValue(false)));
                                        break;
                                    }
                                    case "SupplementalGuidance":
                                    {
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("SupplementalGuidance",
                                            xmlReader.ObtainCurrentNodeValue(false)));
                                        break;
                                    }
                                    case "Confidentiality":
                                    {
                                        ciaTriadFlags.Add("HighConfidentiality", xmlReader.GetAttribute("high"));
                                        ciaTriadFlags.Add("ModerateConfidentiality",
                                            xmlReader.GetAttribute("moderate"));
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
                                    {
                                        break;
                                    }
                                }
                            }
                            else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("Control"))
                            {
                                InsertNistControls(sqliteCommand);
                                MapControlsToCia(sqliteCommand, ciaTriadFlags);
                                sqliteCommand.CommandText = string.Empty;
                                sqliteCommand.Parameters.Clear();
                            }
                        }
                    }
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to populate NIST Control list.");
                throw exception;
            }
        }

        private void InsertNistControls(SQLiteCommand sqliteCommand)
        {
            try
            {
                if (!sqliteCommand.Parameters.Contains("SupplementalGuidance"))
                {
                    sqliteCommand.Parameters.Add(new SQLiteParameter("SupplementalGuidance", string.Empty));
                }

                if (sqliteCommand.Parameters.Contains("Enhancement"))
                {
                    sqliteCommand.CommandText =
                        "INSERT INTO NIST_Controls VALUES (NULL, @Family, @Number, @Enhancement, @Title, @Text, @SupplementalGuidance, NULL);";
                }
                else
                {
                    sqliteCommand.CommandText =
                        "INSERT INTO NIST_Controls VALUES (NULL, @Family, @Number, NULL, @Title, @Text, @SupplementalGuidance, NULL);";
                }

                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to insert NIST Controls into database.");
                throw exception;
            }
        }

        private void MapControlsToCia(SQLiteCommand sqliteCommand, Dictionary<string, string> ciaTriadFlags)
        {
            try
            {
                sqliteCommand.CommandText = "SELECT last_insert_rowid();";
                sqliteCommand.Parameters.Add(new SQLiteParameter("NIST_Control_ID",
                    sqliteCommand.ExecuteScalar().ToString()));
                foreach (string key in ciaTriadFlags.Keys)
                {
                    // Skip item or set IsNss Flag, as applicable
                    if (ciaTriadFlags[key].Equals("false"))
                    {
                        continue;
                    }
                    else if (ciaTriadFlags[key].Equals("NSS"))
                    {
                        sqliteCommand.Parameters.Add(new SQLiteParameter("IsNss", "True"));
                    }
                    else
                    {
                        sqliteCommand.Parameters.Add(new SQLiteParameter("IsNss", "False"));
                    }

                    // Set appropriate applicability level for C-I-A triad item
                    if (key.Contains("High"))
                    {
                        sqliteCommand.Parameters.Add(new SQLiteParameter("Level", "High"));
                    }
                    else if (key.Contains("Moderate"))
                    {
                        sqliteCommand.Parameters.Add(new SQLiteParameter("Level", "Moderate"));
                    }
                    else
                    {
                        sqliteCommand.Parameters.Add(new SQLiteParameter("Level", "Low"));
                    }

                    // Insert data into appropriate table
                    if (key.Contains("Confidentiality"))
                    {
                        sqliteCommand.CommandText = "INSERT INTO NIST_ControlsConfidentialityLevels VALUES " +
                                                    "(NULL, @NIST_Control_ID, (SELECT ConfidentialityLevel_ID FROM ConfidentialityLevels WHERE ConfidentialityLevel = @Level), @IsNss);";
                    }
                    else if (key.Contains("Integrity"))
                    {
                        sqliteCommand.CommandText = "INSERT INTO NIST_ControlsIntegrityLevels VALUES " +
                                                    "(NULL, @NIST_Control_ID, (SELECT IntegrityLevel_ID FROM IntegrityLevels WHERE IntegrityLevel = @Level), @IsNss);";
                    }
                    else
                    {
                        sqliteCommand.CommandText = "INSERT INTO NIST_ControlsAvailabilityLevels VALUES " +
                                                    "(NULL, @NIST_Control_ID, (SELECT AvailabilityLevel_ID FROM AvailabilityLevels WHERE AvailabilityLevel = @Level), @IsNss);";
                    }

                    sqliteCommand.ExecuteNonQuery();
                    sqliteCommand.Parameters.Remove(sqliteCommand.Parameters["IsNss"]);
                    sqliteCommand.Parameters.Remove(sqliteCommand.Parameters["Level"]);
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to map NIST Controls to CIA triad.");
                throw exception;
            }
        }

        private void MapControlsToCci(SQLiteCommand sqliteCommand)
        {
            try
            {
                LogWriter.LogStatusUpdate("Verifying NIST Controls are mapped to CCIs.");
                using (Stream stream =
                    assembly.GetManifestResourceStream("Vulnerator.Resources.RawData.NIST_800-53_CCI_Mapping.xml"))
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
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("Family",
                                            xmlReader.GetAttribute("family")));
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("Number",
                                            xmlReader.GetAttribute("number")));
                                        if (!xmlReader.GetAttribute("enhancement").Equals("0"))
                                        {
                                            sqliteCommand.Parameters.Add(new SQLiteParameter("Enhancement",
                                                xmlReader.GetAttribute("enhancement")));
                                        }

                                        sqliteCommand.Parameters.Add(new SQLiteParameter("DoD_AP",
                                            xmlReader.GetAttribute("dod-ap")?.Replace(" )", ")")));
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("ControlIndicator",
                                            xmlReader.GetAttribute("indicator")));
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("CCI",
                                            xmlReader.GetAttribute("cci")));
                                        break;
                                    }
                                    case "ImplementationGuidance":
                                    {
                                        string implementationGuidance = xmlReader.ObtainCurrentNodeValue(false).ToString();
                                        implementationGuidance =
                                            implementationGuidance.SanitizeNewLines().InsertStartingBullet();
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("ImplementationGuidance",
                                            implementationGuidance));
                                        break;
                                    }
                                    case "AssessmentProcedures":
                                    {
                                        string ap = xmlReader.ObtainCurrentNodeValue(false).ToString();
                                        ap = ap.SanitizeNewLines().InsertStartingBullet();
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("AP_Text", ap));
                                        break;
                                    }
                                    default:
                                    {
                                        break;
                                    }
                                }
                            }
                            else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("Pair"))
                            {
                                if (!sqliteCommand.Parameters.Contains("DoD_AP"))
                                {
                                    sqliteCommand.Parameters.Add(new SQLiteParameter("DoD_AP", DBNull.Value));
                                }

                                if (sqliteCommand.Parameters.Contains("Enhancement"))
                                {
                                    sqliteCommand.CommandText = "INSERT INTO NIST_ControlsCCIs VALUES " +
                                                                "(NULL, (SELECT NIST_Control_ID FROM NIST_Controls WHERE ControlFamily = @Family AND ControlNumber = @Number AND ControlEnhancement = @Enhancement), " +
                                                                "(SELECT CCI_ID FROM CCIs WHERE CCI_Number = @CCI), @DoD_AP, @ControlIndicator, @ImplementationGuidance, @AP_Text);";
                                }
                                else
                                {
                                    sqliteCommand.CommandText = "INSERT INTO NIST_ControlsCCIs VALUES " +
                                                                "(NULL, (SELECT NIST_Control_ID FROM NIST_Controls WHERE ControlFamily = @Family AND ControlNumber = @Number AND ControlEnhancement IS NULL), " +
                                                                "(SELECT CCI_ID FROM CCIs WHERE CCI_Number = @CCI), @DoD_AP, @ControlIndicator, @ImplementationGuidance, @AP_Text);";
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
                LogWriter.LogError("Unable to map NIST Controls to CCI values.");
                throw exception;
            }
        }

        private void MapControlsToCnssOverlays(SQLiteCommand sqliteCommand)
        {
            try
            {
                LogWriter.LogStatusUpdate("Verifying NIST Controls are mapped to CNSS Overlays.");
                Dictionary<string, string> overlayApplicability = new Dictionary<string, string>();
                using (Stream stream =
                    assembly.GetManifestResourceStream(
                        "Vulnerator.Resources.RawData.NIST_800-53_CNSS-Overlay_Mapping.xml"))
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
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("Family",
                                            xmlReader.GetAttribute("family")));
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("Number",
                                            xmlReader.GetAttribute("number")));
                                        if (!xmlReader.GetAttribute("enhancement").Equals("0"))
                                        {
                                            sqliteCommand.Parameters.Add(new SQLiteParameter("Enhancement",
                                                xmlReader.GetAttribute("enhancement")));
                                        }

                                        break;
                                    }
                                    default:
                                    {
                                        overlayApplicability.Add(xmlReader.Name.Replace("-", " "),
                                            xmlReader.ObtainCurrentNodeValue(false).ToString());
                                        break;
                                    }
                                }
                            }
                            else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("Control"))
                            {
                                // TODO: Finish this
                                if (sqliteCommand.Parameters.Contains("enhancement"))
                                { }
                                else
                                { }
                            }
                        }
                    }
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to map NIST controls to CNSS 1523 Overlays.");
                throw exception;
            }
        }

        private void MapControlsToMonitoringFrequency(SQLiteCommand sqliteCommand)
        {
            try
            {
                LogWriter.LogStatusUpdate("Verifying NIST Controls are mapped to monitoring frequencies.");
                using (Stream stream =
                    assembly.GetManifestResourceStream(
                        "Vulnerator.Resources.RawData.NIST_800-53_MonitoringFrequency_Mapping.xml"))
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
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("Family",
                                            xmlReader.GetAttribute("family")));
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("Number",
                                            xmlReader.GetAttribute("number")));
                                        if (!xmlReader.GetAttribute("enhancement").Equals("0"))
                                        {
                                            sqliteCommand.Parameters.Add(new SQLiteParameter("Enhancement",
                                                xmlReader.GetAttribute("enhancement")));
                                        }

                                        break;
                                    }
                                    case "Frequency":
                                    {
                                        sqliteCommand.Parameters.Add(new SQLiteParameter("Frequency",
                                            xmlReader.ObtainCurrentNodeValue(false)));
                                        break;
                                    }
                                    default:
                                    {
                                        break;
                                    }
                                }
                            }
                            else if (xmlReader.NodeType == XmlNodeType.EndElement && xmlReader.Name.Equals("Control"))
                            {
                                if (sqliteCommand.Parameters.Contains("Enhancement"))
                                {
                                    sqliteCommand.CommandText =
                                        "UPDATE NIST_Controls SET MonitoringFrequency = @Frequency WHERE ControlFamily = @Family AND " +
                                        "ControlNumber = @Number AND ControlEnhancement = @Enhancement;";
                                }
                                else
                                {
                                    sqliteCommand.CommandText =
                                        "UPDATE NIST_Controls SET MonitoringFrequency = @Frequency WHERE ControlFamily = @Family AND " +
                                        "ControlNumber = @Number AND ControlEnhancement IS NULL;";
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
                LogWriter.LogError("Unable to map NIST controls to monitoring frequencies.");
                throw exception;
            }
        }

        private void InsertUserReportSettings(SQLiteCommand sqliteCommand)
        {
            try
            {
                LogWriter.LogStatusUpdate("Inserting user-specific report requirements.");
                string[] severities = {"CAT I", "CAT II", "CAT III", "CAT IV"};
                string[] statuses = {"Ongoing", "Not Reviewed", "Not Applicable", "Completed", "Error"};
                string storedProcedureBase = "Vulnerator.Resources.DdlFiles.StoredProcedures.Select.";
                List<string> reportIds = new List<string>();
                List<string> findingTypeIds = new List<string>();
                List<string> groupIds = new List<string>();

                sqliteCommand.CommandText = _ddlReader.ReadDdl(storedProcedureBase + "RequiredReportIds.dml",
                    assembly);;
                using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
                {
                    if (sqliteDataReader.HasRows)
                    {
                        while (sqliteDataReader.Read())
                        {
                            reportIds.Add(sqliteDataReader[0].ToString());
                        }
                    }
                }

                sqliteCommand.CommandText = _ddlReader.ReadDdl(storedProcedureBase + "FindingTypeIds.dml",
                    assembly);
                using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
                {
                    if (sqliteDataReader.HasRows)
                    {
                        while (sqliteDataReader.Read())
                        {
                            findingTypeIds.Add(sqliteDataReader[0].ToString());
                        }
                    }
                }

                sqliteCommand.CommandText = _ddlReader.ReadDdl(storedProcedureBase + "GroupIds.dml",
                    assembly);
                using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
                {
                    if (sqliteDataReader.HasRows)
                    {
                        while (sqliteDataReader.Read())
                        {
                            groupIds.Add(sqliteDataReader[0].ToString());
                        }
                    }
                }

                sqliteCommand.Parameters.Add(new SQLiteParameter("UserName", Properties.Settings.Default.ActiveUser));
                storedProcedureBase = "Vulnerator.Resources.DdlFiles.StoredProcedures.Insert.";
                foreach (string report in reportIds)
                {
                    sqliteCommand.Parameters.Add(new SQLiteParameter("RequiredReport_ID", report));
                    sqliteCommand.CommandText =
                        _ddlReader.ReadDdl(storedProcedureBase + "RequiredReportUserFindingTypes.dml",
                            assembly);
                    foreach (string findingType in findingTypeIds)
                    {
                        sqliteCommand.Parameters.Add(new SQLiteParameter("FindingType_ID", findingType));
                        sqliteCommand.ExecuteNonQuery();
                    }
                    sqliteCommand.CommandText =
                        _ddlReader.ReadDdl(storedProcedureBase + "RequiredReportUserSeverities.dml",
                            assembly);
                    foreach (string severity in severities)
                    {
                        sqliteCommand.Parameters.Add(new SQLiteParameter("Severity", severity));
                        sqliteCommand.ExecuteNonQuery();
                    }
                    sqliteCommand.CommandText =
                        _ddlReader.ReadDdl(storedProcedureBase + "RequiredReportUserStatuses.dml",
                            assembly);
                    foreach (string status in statuses)
                    {
                        sqliteCommand.Parameters.Add(new SQLiteParameter("Status", status));
                        sqliteCommand.ExecuteNonQuery();
                    }
                    foreach (string group in groupIds)
                    {
                        sqliteCommand.Parameters.Add(new SQLiteParameter("Group_ID", group));
                        sqliteCommand.CommandText =
                            _ddlReader.ReadDdl(storedProcedureBase + "RequiredReportUserGroups.dml",
                                assembly);
                        sqliteCommand.ExecuteNonQuery();
                    }
                    sqliteCommand.Parameters.Add(new SQLiteParameter("Group_ID", DBNull.Value));
                    sqliteCommand.CommandText =
                        _ddlReader.ReadDdl(storedProcedureBase + "RequiredReportUserRmfOverride.dml",
                            assembly);
                    sqliteCommand.ExecuteNonQuery();
                    sqliteCommand.CommandText =
                        _ddlReader.ReadDdl(storedProcedureBase + "RequiredReportUserSelections.dml",
                            assembly);
                    sqliteCommand.ExecuteNonQuery();

                    sqliteCommand.CommandText =
                        _ddlReader.ReadDdl(storedProcedureBase + "RequiredReportUserGlobalSelections.dml",
                            assembly);
                    sqliteCommand.ExecuteNonQuery();
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to insert user-specific report requirements.");
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
                    {
                        return cciReferences;
                    }
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
                LogWriter.LogError("Unable to obtain CCI References.");
                throw exception;
            }
        }
    }
}