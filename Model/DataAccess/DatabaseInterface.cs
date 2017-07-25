using log4net;
using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.Text.RegularExpressions;
using Vulnerator.Model.Object;

namespace Vulnerator.Model.DataAccess
{
    public class DatabaseInterface
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(Logger));

        public void InsertGroup(SQLiteCommand sqliteCommand, File file)
        {
            try
            {
                string groupName;
                if (!string.IsNullOrWhiteSpace(file.FileSystemName))
                { groupName = file.FileSystemName; }
                else
                { groupName = "Unassigned"; }
                sqliteCommand.Parameters.Add(new SQLiteParameter("Group_Name", groupName));
                sqliteCommand.CommandText = Properties.Resources.InsertGroup;
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to insert group \"{0}\" into database.", file.FileSystemName));
                throw exception;
            }
        }
        
        public void InsertParsedFile(SQLiteCommand sqliteCommand, File file)
        {
            try
            {
                sqliteCommand.Parameters.Add(new SQLiteParameter("Finding_Source_File_Name", file.FileName));
                sqliteCommand.CommandText = Properties.Resources.InsertUniqueFindingSource;
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to insert unique finding source file \"{0}\".", file.FileName));
                throw exception;
            }
        }

        public void InsertHardware(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.Parameters.Add(new SQLiteParameter("Is_Virtual_Server", "False"));
                sqliteCommand.CommandText = Properties.Resources.InsertHardware;
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to insert host \"{0}\".", sqliteCommand.Parameters["IP_Address"].Value.ToString()));
                throw exception;
            }
        }

        public void MapHardwareToGroup(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = Properties.Resources.MapHardwareToGroup;
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to map \"{0}\" to \"{1}\".",
                    sqliteCommand.Parameters["Host_Name"].Value.ToString(),
                    sqliteCommand.Parameters["Group_Name"].Value.ToString()));
                throw exception;
            }
        }

        public void InsertSoftware(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = Properties.Resources.InsertSoftware;
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to insert software \"{0}\" into table.", sqliteCommand.Parameters["Discovered_Software_Name"].Value.ToString()));
                throw exception;
            }
        }

        public void MapHardwareToSoftware(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = Properties.Resources.MapHardwareToSoftware;
                sqliteCommand.Parameters.Add(new SQLiteParameter("ReportInAccreditation", "False"));
                sqliteCommand.Parameters.Add(new SQLiteParameter("ApprovedForBaseline", "False"));
                sqliteCommand.Parameters.Add(new SQLiteParameter("BaselineApprover", DBNull.Value));
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to map software \"{0}\" to \"{1}\".",
                    sqliteCommand.Parameters["Discovered_Software_Name"].Value.ToString(),
                    sqliteCommand.Parameters["Host_Name"].Value.ToString()));
                throw exception;
            }
        }

        public void InsertAndMapIpAddress(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = Properties.Resources.InsertIpAddress;
                sqliteCommand.ExecuteNonQuery();
                sqliteCommand.CommandText = Properties.Resources.MapIpToHardware;
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to insert IP Address \"{0}\"."));
                log.Debug("Exception details:", exception);
                throw exception;
            }
        }

        public void InsertAndMapMacAddress(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = Properties.Resources.InsertMacAddress;
                sqliteCommand.ExecuteNonQuery();
                sqliteCommand.CommandText = Properties.Resources.MapMacToHardware;
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to insert / map MAC Address \"{0}\" belonging to host \"{1}\"."));
                throw exception;
            }
        }

        public void InsertVulnerabilitySource(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = Properties.Resources.InsertVulnerabilitySource;
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to insert vulnerability source \"{0}\".", sqliteCommand.Parameters["Source_Name"].Value.ToString()));
                throw exception;
            }
        }

        public void UpdateVulnerabilitySource(SQLiteCommand sqliteCommand, string findingType)
        {
            try
            {
                switch (findingType)
                {
                    case "ACAS":
                        {
                            sqliteCommand.CommandText = Properties.Resources.UpdateAcasVulnerabilitySource;
                            sqliteCommand.ExecuteNonQuery();
                            sqliteCommand.CommandText = Properties.Resources.DeleteUnknownAcasVersions;
                            sqliteCommand.ExecuteNonQuery();
                            return;
                        }
                    case "CKL":
                        {
                            if (VulnerabilitySourceUpdateRequired(sqliteCommand))
                            {
                                sqliteCommand.CommandText = Properties.Resources.UpdateVulnerabilitySource;
                                sqliteCommand.ExecuteNonQuery();
                            }
                            return;
                        }
                    default:
                        { break; }
                }
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to update vulnerability source \"{0}\".", sqliteCommand.Parameters["Source_Name"].Value.ToString()));
                throw exception;
            }
        }

        public void InsertVulnerability(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = Properties.Resources.InsertVulnerability;
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to insert vulnerability \"{0}\".", sqliteCommand.Parameters["Unique_Vulnerability_Identifier"].Value.ToString()));
                throw exception;
            }
        }

        public void UpdateVulnerability(SQLiteCommand sqliteCommand)
        {
            try
            {
                if (VulnerabilityUpdateRequired(sqliteCommand))
                {
                    sqliteCommand.CommandText = Properties.Resources.UpdateVulnerability;
                    sqliteCommand.ExecuteNonQuery();
                    sqliteCommand.CommandText = Properties.Resources.UpdateDeltaAnalysisFlag;
                    sqliteCommand.ExecuteNonQuery();
                }
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to insert vulnerability \"{0}\".", sqliteCommand.Parameters["Unique_Vulnerability_Identifier"].Value.ToString()));
                throw exception;
            }
        }

        private void MapVulnerbailityToIAControl(SQLiteCommand sqliteCommand)
        {
            try
            {

            }
            catch (Exception exception)
            {
                log.Error("Unable to vulnerability to IA Control.");
                log.Debug("Exception details: " + exception);
            }
        }

        public void MapVulnerabilityToSource(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = Properties.Resources.MapVulnerabilityToSource;
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to map vulnerability \"{0}\" to source \"{1}\"."));
                log.Debug("Exception details: " + exception);
            }
        }

        public void InsertAndMapPort(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = Properties.Resources.InsertPort;
                sqliteCommand.ExecuteNonQuery();
                sqliteCommand.CommandText = Properties.Resources.MapPortToHardware;
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to insert or map port \"{0} {1}\".",
                    sqliteCommand.Parameters["Protocol"].Value.ToString(),
                    sqliteCommand.Parameters["Port"].Value.ToString()));
                throw exception;
            }
        }

        public void InsertUniqueFinding(SQLiteCommand sqliteCommand)
        { 
            try
            {
                sqliteCommand.CommandText = Properties.Resources.InsertUniqueFinding;
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to generate a new unique finding for \"{0}\", \"{1}\", \"{2}\".",
                    sqliteCommand.Parameters["Unique_Vulnerability_Identifier"].Value.ToString(),
                    sqliteCommand.Parameters["Host_Name"].Value.ToString(),
                    sqliteCommand.Parameters["Scan_IP"].Value.ToString()));
                throw exception;
            }
        }

        public void UpdateUniqueFinding(SQLiteCommand sqliteCommand, string findingType)
        { 
            try
            {
                switch (findingType)
                {
                    case "ACAS":
                        {
                            sqliteCommand.CommandText = Properties.Resources.UpdateAcasUniqueFinding;
                            sqliteCommand.ExecuteNonQuery();
                            break;
                        }
                    case "CKL":
                        {
                            sqliteCommand.CommandText = Properties.Resources.UpdateCklUniqueFinding;
                            sqliteCommand.ExecuteNonQuery();
                            break;
                        }
                    default:
                        { break; }
                }
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to update the unique finding for \"{0}\", \"{1}\", \"{2}\".",
                    sqliteCommand.Parameters["Unique_Vulnerability_Identifier"].Value.ToString(),
                    sqliteCommand.Parameters["Host_Name"].Value.ToString(),
                    sqliteCommand.Parameters["Scan_IP"].Value.ToString()));
                throw exception;
            }
        }

        public void InsertAndMapVulnerabilityReferences(SQLiteCommand sqliteCommand, List<string> references, string referenceType)
        {
            try
            {
                foreach (string reference in references)
                {
                    sqliteCommand.CommandText = Properties.Resources.InsertVulnerabilityReference;
                    if (!referenceType.Equals("CVE") && !referenceType.Equals("CPE"))
                    {
                        referenceType = reference.Split(':')[0];
                        sqliteCommand.Parameters.Add(new SQLiteParameter("Reference", reference.Split(':')[1]));
                    }
                    else
                    { sqliteCommand.Parameters.Add(new SQLiteParameter("Reference", reference)); }
                    sqliteCommand.Parameters.Add(new SQLiteParameter("Reference_Type", referenceType));
                    sqliteCommand.ExecuteNonQuery();
                    sqliteCommand.CommandText = Properties.Resources.MapReferenceToVulnerability;
                    sqliteCommand.ExecuteNonQuery();
                }
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to insert / map reference."));
                throw exception;
            }
        }

        public void MapVulnerabilityToCci(SQLiteCommand sqliteCommand)
        { 
            try
            {
                sqliteCommand.CommandText = Properties.Resources.MapVulnerabilityToCci;
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to map CCI \"{0}\" to vulnerability \"{1}\".",
                    sqliteCommand.Parameters["CCI"].Value.ToString(),
                    sqliteCommand.Parameters["Unique_Vulnerability_Identifier"].Value.ToString()));
                throw exception;
            }
        }

        public void InsertScapScore(SQLiteCommand sqliteCommand)
        { 
            try
            {
                sqliteCommand.CommandText = Properties.Resources.InsertScapScore;
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to insert SCAP score for \"{0}\" - \"{1}\".", 
                    sqliteCommand.Parameters["Host_Name"].Value.ToString(),
                    sqliteCommand.Parameters["Source_Name"].Value.ToString()));
                throw exception;
            }
        }

        private bool VulnerabilitySourceUpdateRequired(SQLiteCommand sqliteCommand)
        { 
            try
            {
                bool versionUpdated = false;
                bool versionSame = false;
                bool releaseUpdated = false;
                sqliteCommand.CommandText = Properties.Resources.SelectVulnerabilitySourceVersionAndRelease;
                using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
                {
                    if (sqliteDataReader.HasRows)
                    {
                        while (sqliteDataReader.Read())
                        {
                            if (string.IsNullOrWhiteSpace(sqliteDataReader["Source_Version"].ToString()))
                            { return true; }
                            Regex regex = new Regex(@"\D");
                            int newVersion;
                            int newRelease;
                            bool newVersionParsed = int.TryParse(regex.Replace(sqliteCommand.Parameters["Source_Version"].Value.ToString(), string.Empty), out newVersion);
                            bool newReleaseParsed = int.TryParse(regex.Replace(sqliteCommand.Parameters["Source_Release"].Value.ToString(), string.Empty), out newRelease);
                            int oldVersion;
                            int oldRelease;
                            bool oldVersionParsed = int.TryParse(regex.Replace(sqliteDataReader["Source_Version"].ToString(), string.Empty), out oldVersion);
                            bool oldReleaseParsed = int.TryParse(regex.Replace(sqliteDataReader["Source_Release"].ToString(), string.Empty), out oldRelease);
                            if (newVersionParsed && oldVersionParsed)
                            {
                                versionUpdated = (newVersion > oldVersion) ? true : false;
                                versionSame = (newVersion == oldVersion) ? true : false;
                            }
                            if (newReleaseParsed && oldReleaseParsed && (newRelease > oldRelease))
                            { releaseUpdated = true; }
                            if (versionUpdated || (versionSame && releaseUpdated))
                            { return true; }
                        }
                    }
                    return false;
                }
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to determine if an update is required for vulnerability \"{0}\".",
                    sqliteCommand.Parameters["Source_Name"].Value.ToString()));
                throw exception;
            }
        }

        private bool VulnerabilityUpdateRequired(SQLiteCommand sqliteCommand)
        { 
            try
            {
                bool versionUpdated = false;
                bool versionSame = false;
                bool releaseUpdated = false;
                sqliteCommand.CommandText = Properties.Resources.SelectVulnerabilityVersionAndRelease;
                using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
                {
                    if (sqliteDataReader.HasRows)
                    {
                        while (sqliteDataReader.Read())
                        {
                            if (string.IsNullOrWhiteSpace(sqliteDataReader["Vulnerability_Version"].ToString()))
                            { return true; }
                            Regex regex = new Regex(@"\D");
                            int newVersion;
                            int newRelease;
                            bool newVersionParsed = int.TryParse(regex.Replace(sqliteCommand.Parameters["Vulnerability_Version"].Value.ToString(), string.Empty), out newVersion);
                            bool newReleaseParsed = int.TryParse(regex.Replace(sqliteCommand.Parameters["Vulnerability_Release"].Value.ToString(), string.Empty), out newRelease);
                            int oldVersion;
                            int oldRelease;
                            bool oldVersionParsed = int.TryParse(regex.Replace(sqliteDataReader["Vulnerability_Version"].ToString(), string.Empty), out oldVersion);
                            bool oldReleaseParsed = int.TryParse(regex.Replace(sqliteDataReader["Vulnerability_Release"].ToString(), string.Empty), out oldRelease);
                            if (newVersionParsed && oldVersionParsed)
                            {
                                versionUpdated = (newVersion > oldVersion) ? true : false;
                                versionSame = (newVersion == oldVersion) ? true : false;
                            }
                            if (newReleaseParsed && oldReleaseParsed && (newRelease > oldRelease))
                            { releaseUpdated = true; }
                            if (versionUpdated || (versionSame && releaseUpdated))
                            { return true; }
                        }
                    }
                }
                return false;
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to determine if an update is required for vulnerability \"{0}\".", 
                    sqliteCommand.Parameters["Unique_Vulnerability_Identifier"].Value.ToString()));
                throw exception;
            }
        }
    }
}
