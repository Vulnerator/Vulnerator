using log4net;
using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.IO;
using System.Reflection;
using System.Text.RegularExpressions;
using Vulnerator.Helper;
using Vulnerator.Model.Object;

namespace Vulnerator.Model.DataAccess
{
    public class DatabaseInterface
    {
        public void CreateVulnerabilityRelatedIndices()
        {
            try
            {
                if (!DatabaseBuilder.sqliteConnection.State.ToString().Equals("Open"))
                { DatabaseBuilder.sqliteConnection.Open(); }
                using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                {
                    sqliteCommand.CommandText = "PRAGMA user_version";
                    int latestVersion = int.Parse(sqliteCommand.ExecuteScalar().ToString());
                    for (int i = 0; i <= latestVersion; i++)
                    {
                        switch (i)
                        {
                            case 0:
                                {
                                    sqliteCommand.CommandText = ReadDdl("Vulnerator.Resources.DdlFiles.v6-2-0_CreateVulnerabilityRelatedIndices.ddl");
                                    break;
                                }
                            default:
                                { break; }
                        }
                        if (sqliteCommand.CommandText.Equals(string.Empty))
                        { return; }
                        sqliteCommand.ExecuteNonQuery();
                        sqliteCommand.CommandText = string.Empty;
                    }
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to create vulnerability related indices.");
                throw exception;
            }
            finally
            { DatabaseBuilder.sqliteConnection.Close(); }
        }

        public void DeleteVulnerabilityToCciMapping(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = Properties.Resources.DeleteVulnerabilityCciMapping;
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to delete the Vulnerability / CCI mapping for UniqueFinding ID '{sqliteCommand.Parameters["UniqueVulnerabilityIdentifier"].Value}' and CCI '{sqliteCommand.Parameters["CCI"].Value}'.");
                throw exception;
            }
        }

        public void DeleteRemovedVulnerabilities(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = Properties.Resources.SelectVulnerabilitiesForDeletion;
                using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
                {
                    if (!sqliteDataReader.HasRows)
                    { return; }

                    using (SQLiteCommand deleteVulnsCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                    {
                        deleteVulnsCommand.CommandText = Properties.Resources.DeleteVulnerability;
                        while (sqliteDataReader.Read())
                        {
                            deleteVulnsCommand.Parameters.Add(new SQLiteParameter("Vulnerability_ID", sqliteDataReader["Vulnerability_ID"].ToString()));
                            deleteVulnsCommand.ExecuteNonQuery();
                        }
                    }
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to delete the Vulnerability '{sqliteCommand.Parameters["UniqueVulnerabilityIdentifier"].Value}'.");
                throw exception;
            }
        }

        public void DeleteMitigationGroupMappingByMitigation(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = Properties.Resources.DeleteMitigationGroupMappingByMitigation;
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to delete the Mitigation / Group mappings for Mitigation ID '{sqliteCommand.Parameters["MitigationOrCondition_ID"].Value}'.");
                throw exception;
            }
        }

        public void DeleteMitigationOrCondition(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = Properties.Resources.DeleteMitigation;
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to delete the MitigationOrCondition with Mitigation ID '{sqliteCommand.Parameters["MitigationOrCondition_ID"].Value}'.");
                throw exception;
            }
        }

        public void DeleteUniqueFinding(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = Properties.Resources.DeleteUniqueFinding;
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to delete the selected UniqueFinding with Unique Finding ID '{sqliteCommand.Parameters["UniqueFinding_ID"].Value}'.");
                throw exception;
            }
        }

        public void DropVulnerabilityRelatedIndices()
        {
            try
            {
                if (!DatabaseBuilder.sqliteConnection.State.ToString().Equals("Open"))
                { DatabaseBuilder.sqliteConnection.Open(); }
                using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                {
                    sqliteCommand.CommandText = "PRAGMA user_version";
                    int latestVersion = int.Parse(sqliteCommand.ExecuteScalar().ToString());
                    for (int i = 0; i <= latestVersion; i++)
                    {
                        switch (i)
                        {
                            case 0:
                                {
                                    sqliteCommand.CommandText = ReadDdl("Vulnerator.Resources.DdlFiles.v6-2-0_DropVulnerabilityRelatedIndices.ddl");
                                    break;

                                }
                            default:
                                { break; }
                        }
                        if (sqliteCommand.CommandText.Equals(string.Empty))
                        { return; }
                        sqliteCommand.ExecuteNonQuery();
                        sqliteCommand.CommandText = string.Empty;
                    }
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError("$Unable to drop vulnerability related indices.");
                throw exception;
            }
            finally
            { DatabaseBuilder.sqliteConnection.Close(); }
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
                LogWriter.LogError($"Unable to insert and map IP Address '{sqliteCommand.Parameters["IP_Address"].Value}'.");
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
                LogWriter.LogError($"Unable to insert and map MAC Address '{sqliteCommand.Parameters["MAC_Address"].Value}'.");
                throw exception;
            }
        }

        public void InsertAndMapPort(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = Properties.Resources.InsertPortsProtocols;
                sqliteCommand.ExecuteNonQuery();
                sqliteCommand.CommandText = Properties.Resources.MapPortToHardware;
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to insert or map '{sqliteCommand.Parameters["Protocol"].Value} {sqliteCommand.Parameters["Port"].Value}'.");
                throw exception;
            }
        }

        public void InsertAndMapVulnerabilityReferences(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = Properties.Resources.InsertVulnerabilityReference;
                sqliteCommand.ExecuteNonQuery();
                sqliteCommand.CommandText = Properties.Resources.MapReferenceToVulnerability;
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to insert and map vulnerability reference '{sqliteCommand.Parameters["Reference"].Value}'.");
                throw exception;
            }
        }

        public void InsertDataEntryDate(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = Properties.Resources.InsertDataEntryDate;
                sqliteCommand.Parameters.Add(new SQLiteParameter("EntryDate", DateTime.Now.ToShortDateString()));
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to insert a new data entry date.");
                throw exception;
            }
        }

        public void InsertGroup(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = Properties.Resources.InsertGroup;
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to insert group '{sqliteCommand.Parameters["Name"].Value}' into database.");
                throw exception;
            }
        }

        public void InsertHardware(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.Parameters.Add(new SQLiteParameter("IsVirtualServer", "False"));
                sqliteCommand.CommandText = Properties.Resources.InsertHardware;
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to insert host '{sqliteCommand.Parameters["IP_Address"].Value}'.");
                throw exception;
            }
        }

        public void InsertEmptyMitigationOrCondition(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = Properties.Resources.InsertMitigationsOrConditionsDefaultValues;
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to insert a new empty mitigation.");
                throw exception;
            }
        }

        public void InsertMitigationOrCondition(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = Properties.Resources.InsertMitigationOrCondition;
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to insert the new mitigation.");
                throw exception;
            }
        }

        public void InsertParameterPlaceholders(SQLiteCommand sqliteCommand)
        {
            try
            {
                string[] parameters = {
                    // CCI Table
                    "CCI_Number",
                    // FindingTypes Table
                    "FindingType",
                    // Groups Table
                    "Group_ID", "GroupName", "GroupAcronym", "GroupTier", "IsAccreditation", "Accreditation_eMASS_ID", "IsPlatform", "Organization_ID",
                    "ConfidentialityLevel_ID", "IntegrityLevel_ID", "AvailabilityLevel_ID", "SystemCategorization_ID", "AccreditationVersion", "CybersafeGrade",
                    "FISCAM_Applies", "ControlSelection_ID", "HasForeignNationals", "SystemType", "RDTE_Zone", "StepOneQuestionnaire_ID", "SecurityAssessmentProcedure_ID",
                    "PIT_Determination_ID",
                    // Hardware Table
                    "Hardware_ID", "DisplayedHostName", "DiscoveredHostName", "FQDN", "NetBIOS", "ScanIP", "Found21745", "Found26917", "IsVirtualServer", "NIAP_Level",
                    "Manufacturer", "ModelNumber", "IsIA_Enabled", "SerialNumber", "Role", "Lifecycle_Status_ID",  "OperatingSystem",
                    // IP_Addresses Table
                    "IP_Address_ID", "IP_Address",
                    // MAC_Addresses Table
                    "MAC_Address_ID", "MAC_Address",
                    // MitigationsOrConditions Table
                    "MitigationOrCondition_ID", "ImpactDescription",  "PredisposingConditions", "TechnicalMitigation", "ProposedMitigation",
                    "ThreatRelevance", "SeverityPervasiveness", "Likelihood", "Impact", "Risk", "ResidualRisk", "ResidualRiskAfterProposed",
                    "MitigatedStatus", "EstimatedCompletionDate", "ApprovalDate", "ExpirationDate", "IsApproved", "Approver",
                    // PortsProtocols Table
                    "PortsProtocols_ID", "Port", "Protocol", "DiscoveredService", "DisplayService",
                    // PortsServices Table
                    "PortService_ID", "DiscoveredServiceName", "DisplayedServiceName", "ServiceAcronym",
                    // Software Table
                    "Software_ID", "DiscoveredSoftwareName", "DisplayedSoftwareName", "SoftwareAcronym", "SoftwareVersion",
                    "Function", "InstallDate", "DADMS_ID", "DADMS_Disposition", "DADMS_LastDateAuthorized", "HasCustomCode", "IA_OrIA_Enabled",
                    "IsOS_OrFirmware", "FAM_Accepted", "ExternallyAuthorized", "ReportInAccreditationGlobal",
                    "ApprovedForBaselineGlobal", "BaselineApproverGlobal", "Instance",
                    // UniqueFindings Table
                    "UniqueFinding_ID", "InstanceIdentifier", "ToolGeneratedOutput", "Comments", "FindingDetails",  "FirstDiscovered",  "LastObserved",
                    "DeltaAnalysisRequired", "FindingType_ID", "FindingSourceFile_ID", "Status", "Vulnerability_ID", "Hardware_ID",  "Software_ID",
                    "SeverityOverride", "SeverityOverrideJustification", "TechnologyArea", "WebDB_Site", "WebDB_Instance",
                    "Classification", "CVSS_EnvironmentalScore", "CVSS_EnvironmentalVector",
                    // UniqueFindingSourceFiles Table
                    "FindingSourceFile_ID", "FindingSourceFileName", 
                    // Vulnerabilities Table
                    "Vulnerability_ID", "UniqueVulnerabilityIdentifier", "VulnerabilityGroupIdentifier", "VulnerabilityGroupTitle",
                    "SecondaryVulnerabilityIdentifier", "VulnerabilityFamilyOrClass", "VulnerabilityVersion", "VulnerabilityRelease",
                    "VulnerabilityTitle", "VulnerabilityDescription", "RiskStatement", "FixText", "PublishedDate", "ModifiedDate",
                    "FixPublishedDate", "RawRisk", "CVSS_BaseScore", "CVSS_BaseVector", "CVSS_TemporalScore", "CVSS_TemporalVector",
                    "CheckContent", "FalsePositives", "FalseNegatives", "IsDocumentable", "Mitigations", "MitigationControl", "IsActive",
                    "PotentialImpacts", "ThirdPartyTools", "SecurityOverrideGuidance", "Overflow", "SeverityOverrideGuidance", "Overflow",
                    // VulnerabilityReferences Table
                    "Reference_ID", "Reference", "ReferenceType",
                    // VulnerabilitySources Table
                    "VulnerabilitySource_ID", "SourceName", "SourceSecondaryIdentifier", "VulnerabilitySourceFileName",
                    "SourceDescription", "SourceVersion", "SourceRelease",
                    // SCAP_Scores Table
                    "SCAP_Score_ID", "Score", "ScanDate", "Hardware_ID"
                };
                foreach (string parameter in parameters)
                { sqliteCommand.Parameters.Add(new SQLiteParameter(parameter, DBNull.Value)); }
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to insert SQLiteParameter placeholders into SQLiteCommand");
                throw exception;
            }
        }

        public void InsertParsedFileSource(SQLiteCommand sqliteCommand, Object.File file)
        {
            try
            {
                sqliteCommand.Parameters.Add(new SQLiteParameter("FindingSourceFileName", file.FileName));
                sqliteCommand.CommandText = Properties.Resources.InsertUniqueFindingSource;
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to insert unique finding source file '{file.FileName}'.");
                throw exception;
            }
        }

        public void InsertParsedFileSource(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = Properties.Resources.InsertUniqueFindingSource;
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to insert unique finding source file '{sqliteCommand.Parameters["FindingSourceFileName"].Value}'.");
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
                LogWriter.LogError($"Unable to insert SCAP score for '{sqliteCommand.Parameters["DiscoveredHostName"].Value}', '{sqliteCommand.Parameters["SourceName"].Value}'.");
                throw exception;
            }
        }

        public void InsertSoftware(SQLiteCommand sqliteCommand)
        {
            try
            {
                if (sqliteCommand.Parameters["FindingType"].Value.ToString().Equals("Fortify"))
                { sqliteCommand.Parameters["HasCustomCode"].Value = "True"; }
                else
                { sqliteCommand.Parameters["HasCustomCode"].Value = "False"; }
                sqliteCommand.CommandText = Properties.Resources.InsertSoftware;
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to insert software '{sqliteCommand.Parameters["DiscoveredSoftwareName"].Value}'.");
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
                LogWriter.LogError($"Unable to generate a new unique finding for '{sqliteCommand.Parameters["UniqueVulnerabilityIdentifier"].Value}', '{sqliteCommand.Parameters["DiscoveredHostName"].Value}', '{sqliteCommand.Parameters["ScanIP"].Value}'.");
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
                LogWriter.LogError($"Unable to insert vulnerability '{sqliteCommand.Parameters["UniqueVulnerabilityIdentifier"].Value}'.");
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
                LogWriter.LogError($"Unable to insert vulnerability source '{sqliteCommand.Parameters["SourceName"].Value}'.");
                throw exception;
            }
        }

        public void MapMitigationToGroup(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = Properties.Resources.MapMitigationToGroup;
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to map mitigation with Mitigation ID '{sqliteCommand.Parameters["MitigationOrCondition_ID"].Value}' to group with Group ID '{sqliteCommand.Parameters["Group_ID"]}' and vulnerability with Vulnerability ID '{sqliteCommand.Parameters["Vulnerability_ID"]}'.");
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
                LogWriter.LogError($"Unable to map host '{sqliteCommand.Parameters["DiscoveredHostName"].Value}' to group '{sqliteCommand.Parameters["Name"].Value}'.");
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
                LogWriter.LogError($"Unable to map software '{sqliteCommand.Parameters["DiscoveredSoftwareName"].Value}' to hardware '{sqliteCommand.Parameters["DiscoveredHostName"].Value}'.");
                throw exception;
            }
        }

        public void MapHardwareToVulnerabilitySource(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = Properties.Resources.MapHardwareToVulnerabilitySource;
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to map hardware '{sqliteCommand.Parameters["DiscoveredHostName"].Value}' to source '{sqliteCommand.Parameters["SourceName"].Value}'.");
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
                LogWriter.LogError($"Unable to map CCI '{sqliteCommand.Parameters["CCI"].Value}' to vulnerability '{sqliteCommand.Parameters["UniqueVulnerabilityIdentifier"].Value}'.");
                throw exception;
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
                LogWriter.LogError($"Unable to map vulnerability '{sqliteCommand.Parameters["UniqueVulnerabilityIdentifier"].Value}' to source '{sqliteCommand.Parameters["SourceName"].Value}'.");
                throw exception;
            }
        }

        public int SelectLastInsertRowId(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = "SELECT last_insert_rowid();";
                return int.Parse(sqliteCommand.ExecuteScalar().ToString());
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to select the last inserted row ID.");
                throw exception;
            }
        }

        public List<string> SelectUniqueVulnerabilityIdentifiersBySource(SQLiteCommand sqliteCommand)
        {
            try
            {
                List<string> vulnerabilityIds = new List<string>();
                sqliteCommand.CommandText = Properties.Resources.SelectUniqueVulnerabilityIdentiferBySource;
                using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
                {
                    if (sqliteDataReader.HasRows)
                    {
                        while (sqliteDataReader.Read())
                        { vulnerabilityIds.Add(sqliteDataReader["UniqueVulnerabilityIdentifier"].ToString()); }
                    }
                }
                return vulnerabilityIds;
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to generate a list of vulnerabilities associated with the vulnerability source associated with ID '{sqliteCommand.Parameters["VulnerabilitySource_ID"].Value}'.");
                throw exception;
            }
        }

        public void SelectVulnerabilitySourceName(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = Properties.Resources.SelectVulnerabilitySourceName;
                using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
                {
                    if (sqliteDataReader.HasRows)
                    {
                        while (sqliteDataReader.Read())
                        { sqliteCommand.Parameters["SourceName"].Value = sqliteDataReader["SourceName"].ToString(); }
                    }
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to retrieve the vulnerability source name for the vulnerability source associated with ID '{sqliteCommand.Parameters["VulnerabilitySource_ID"].Value}'.");
                throw exception;
            }
        }

        public void SelectHardware(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = Properties.Resources.SelectHardware;
                using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
                {
                    if (sqliteDataReader.HasRows)
                    {
                        while (sqliteDataReader.Read())
                        {
                            sqliteCommand.Parameters["DiscoveredHostName"].Value = sqliteDataReader["DiscoveredHostName"].ToString();
                            sqliteCommand.Parameters["FQDN"].Value = sqliteDataReader["FQDN"].ToString();
                            sqliteCommand.Parameters["NetBIOS"].Value = sqliteDataReader["NetBIOS"].ToString();
                            sqliteCommand.Parameters["ScanIP"].Value = sqliteDataReader["ScanIP"].ToString();
                        }
                    }
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to select the details for the hardware record associated with ID '{sqliteCommand.Parameters["Hardware_ID"].Value}'.");
                throw exception;
            }
        }

        public void SetCredentialedScanStatus(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = Properties.Resources.SetCredentialedScanStatus;
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to set the credentialed scan status for '{sqliteCommand.Parameters["ScanIP"].Value}'.");
                throw exception;
            }
        }

        public void UpdateMitigationOrCondition(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = Properties.Resources.UpdateMitigationOrCondition;
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to update MitigationOrCondition associated with ID '{sqliteCommand.Parameters["MitigationOrCondition_ID"].Value}'.");
                throw exception;
            }
        }

        public void UpdateUniqueFinding(SQLiteCommand sqliteCommand)
        {
            try
            {
                switch (sqliteCommand.Parameters["FindingType"].Value.ToString())
                {
                    case "ACAS":
                        {
                            sqliteCommand.CommandText = Properties.Resources.UpdateUniqueFindingFromAcas;
                            sqliteCommand.ExecuteNonQuery();
                            break;
                        }
                    case "CKL":
                        {
                            sqliteCommand.CommandText = Properties.Resources.UpdateUniqueFindingFromCkl;
                            sqliteCommand.ExecuteNonQuery();
                            break;
                        }
                    default:
                        { break; }
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to update the unique finding for '{sqliteCommand.Parameters["UniqueVulnerabilityIdentifier"].Value}', '{sqliteCommand.Parameters["DiscoveredHostName"].Value}', '{sqliteCommand.Parameters["ScanIP"].Value}'.");
                throw exception;
            }
        }

        public void UpdateUniqueFindingMitigationOrCondition(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = Properties.Resources.UpdateUniqueFindingMitigationOrCondition;
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to update MitigationOrCondition associated with ID '{sqliteCommand.Parameters["MitigationOrCondition_ID"].Value}' for the UniqueFinding with ID '{sqliteCommand.Parameters["UniqueFinding_ID"].Value}'.");
                throw exception;
            }
        }

        public void UpdateVulnerability(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = Properties.Resources.UpdateVulnerability;
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to insert vulnerability '{sqliteCommand.Parameters["UniqueVulnerabilityIdentifier"].Value}'.");
                throw exception;
            }
        }

        public void UpdateDeltaAnalysisFlags(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = Properties.Resources.UpdateDeltaAnalysisFlag;
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to update the delta analysis flag(s) for unique findings related to '{sqliteCommand.Parameters["UniqueVulnerabilityIdentifier"].Value}'.");
                throw exception;
            }
        }

        public void UpdateVulnerabilitySource(SQLiteCommand sqliteCommand)
        {
            try
            {
                switch (sqliteCommand.Parameters["FindingType"].Value.ToString())
                {
                    case "ACAS":
                        {
                            sqliteCommand.CommandText = Properties.Resources.UpdateVulnerabilitySourceFromAcas;
                            sqliteCommand.ExecuteNonQuery();
                            sqliteCommand.CommandText = Properties.Resources.DeleteAcasVulnerabilitiesMappedToUnknownVersion;
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
                LogWriter.LogError($"Unable to update vulnerability source '{sqliteCommand.Parameters["SourceName"].Value}'.");
                throw exception;
            }
        }

        public void UpdateRequiredReportSelected(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = Properties.Resources.UpdateRequiredReportIsSelected;
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to update the 'Is_Report_Selected' field for Report ID '{sqliteCommand.Parameters["Required_Report_ID"].Value}'");
                throw exception;
            }
        }

        private void MapVulnerabilityToIAControl(SQLiteCommand sqliteCommand)
        {
            try
            {

            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to vulnerability to IA Control.");
                throw exception;
            }
        }

        private string ReadDdl(string ddlResourceFile)
        {
            try
            {
                Assembly assembly = Assembly.GetExecutingAssembly();
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
                LogWriter.LogError($"Unable to read DDL Resource File '{ddlResourceFile}'.");
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
                            if (string.IsNullOrWhiteSpace(sqliteDataReader["SourceVersion"].ToString()))
                            { return true; }
                            Regex regex = new Regex(@"\D");
                            int newVersion;
                            int newRelease;
                            bool newVersionParsed = int.TryParse(regex.Replace(sqliteCommand.Parameters["SourceVersion"].Value.ToString(), string.Empty), out newVersion);
                            bool newReleaseParsed = int.TryParse(regex.Replace(sqliteCommand.Parameters["SourceRelease"].Value.ToString(), string.Empty), out newRelease);
                            int oldVersion;
                            int oldRelease;
                            bool oldVersionParsed = int.TryParse(regex.Replace(sqliteDataReader["SourceVersion"].ToString(), string.Empty), out oldVersion);
                            bool oldReleaseParsed = int.TryParse(regex.Replace(sqliteDataReader["SourceRelease"].ToString(), string.Empty), out oldRelease);
                            if (newVersionParsed && oldVersionParsed)
                            {
                                versionUpdated = (newVersion > oldVersion);
                                versionSame = (newVersion == oldVersion);
                            }
                            if (newReleaseParsed && oldReleaseParsed && (newRelease > oldRelease))
                            { releaseUpdated = true; }
                            if (versionUpdated || (versionSame && releaseUpdated))
                            { return true; }
                            sqliteCommand.Parameters["SourceVersion"].Value = sqliteDataReader["SourceVersion"].ToString();
                            sqliteCommand.Parameters["SourceRelease"].Value = sqliteDataReader["SourceRelease"].ToString();
                        }
                    }
                    return false;
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to determine if an update is required for vulnerability '{sqliteCommand.Parameters["SourceName"].Value}'.");
                throw exception;
            }
        }

        public string CompareVulnerabilityVersions(SQLiteCommand sqliteCommand)
        {
            try
            {
                bool versionsMatch = false;
                bool releasesMatch = false;
                bool ingestedVersionIsNewer = false;
                bool ingestedReleaseIsNewer = false;
                bool existingVersionIsNewer = false;
                bool existingReleaseIsNewer = false;
                sqliteCommand.CommandText = Properties.Resources.SelectVulnerabilityVersionAndRelease;
                using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
                {
                    if (!sqliteDataReader.HasRows) return "Record Not Found";
                    while (sqliteDataReader.Read())
                    {
                        if (string.IsNullOrWhiteSpace(sqliteDataReader["VulnerabilityVersion"].ToString()))
                        { return "Record Not Found"; }
                        Regex regex = new Regex(@"\D");
                        bool newVersionParsed = int.TryParse(regex.Replace(sqliteCommand.Parameters["VulnerabilityVersion"].Value.ToString(), string.Empty), out int newVersion);
                        bool newReleaseParsed = int.TryParse(regex.Replace(sqliteCommand.Parameters["VulnerabilityRelease"].Value.ToString(), string.Empty), out int newRelease);
                        bool oldVersionParsed = int.TryParse(regex.Replace(sqliteDataReader["VulnerabilityVersion"].ToString(), string.Empty), out int oldVersion);
                        bool oldReleaseParsed = int.TryParse(regex.Replace(sqliteDataReader["VulnerabilityRelease"].ToString(), string.Empty), out int oldRelease);
                        if (newVersionParsed && oldVersionParsed)
                        {
                            ingestedVersionIsNewer = (newVersion > oldVersion);
                            existingVersionIsNewer = (newVersion < oldVersion);
                            versionsMatch = (newVersion == oldVersion);
                        }
                        if (newReleaseParsed && oldReleaseParsed)
                        {
                            ingestedReleaseIsNewer = (newRelease > oldRelease);
                            existingReleaseIsNewer = (newRelease < oldRelease);
                            releasesMatch = (newRelease == oldRelease);
                        }
                        if (ingestedVersionIsNewer)
                        { return "Ingested Version Is Newer"; }
                        if (existingVersionIsNewer)
                        {
                            sqliteCommand.Parameters["VulnerabilityVersion"].Value = sqliteDataReader["VulnerabilityVersion"].ToString();
                            sqliteCommand.Parameters["VulnerabilityRelease"].Value = sqliteDataReader["VulnerabilityRelease"].ToString();
                            return "Existing Version Is Newer";
                        }
                        if (versionsMatch)
                        {
                            if (releasesMatch || (!oldReleaseParsed && !newReleaseParsed))
                            { return "Identical Versions"; }
                            if (ingestedReleaseIsNewer)
                            { return "Ingested Version Is Newer"; }
                            if (existingReleaseIsNewer)
                            {
                                sqliteCommand.Parameters["VulnerabilityVersion"].Value = sqliteDataReader["VulnerabilityVersion"].ToString();
                                sqliteCommand.Parameters["VulnerabilityRelease"].Value = sqliteDataReader["VulnerabilityRelease"].ToString();
                                return "Existing Version Is Newer";
                            }
                        }

                    }
                }
                return "Record Not Found";
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to compare vulnerability version information for '{sqliteCommand.Parameters["UniqueVulnerabilityIdentifier"].Value}' against current database information.");
                throw exception;
            }
        }

        public void UpdateVulnerabilityDates(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = Properties.Resources.UpdateVulnerabilityDates;
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to update the Modified Date for '{sqliteCommand.Parameters["UniqueVulnerabilityIdentifier"].Value}'.");
                throw exception;
            }
        }

        public void UpdateGroup(SQLiteCommand sqliteCommand)
        {

            try
            {
                sqliteCommand.CommandText = Properties.Resources.UpdateGroup;
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to update Group '{sqliteCommand.Parameters["Name"].Value}'.");
                throw exception;
            }
        }

        public void DeleteGroupsCCIsMappingByGroup(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = Properties.Resources.DeleteGroupsCCIsMappingByGroup;
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to delete GroupsCCIs mapping for Group with Group_ID '{sqliteCommand.Parameters["Group_ID"].Value}'.");
                throw exception;
            }
        }

        public void DeleteGroupsWaiversMappingByGroup(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = Properties.Resources.DeleteGroupsWaiversMappingByGroup;
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to delete GroupsWaivers mapping for Group with Group_ID '{sqliteCommand.Parameters["Group_ID"].Value}'.");
                throw exception;
            }
        }

        public void DeleteGroupsOverlaysMappingByGroup(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = Properties.Resources.DeleteGroupsOverlaysMappingByGroup;
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to delete GroupsOverlays mapping for Group with Group_ID '{sqliteCommand.Parameters["Group_ID"].Value}'.");
                throw exception;
            }
        }

        public void DeleteGroupsConnectedSystemsMappingByGroup(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = Properties.Resources.DeleteGroupsConnectedSystemsMappingByGroup;
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to delete GroupsConnectedSystems mapping for Group with Group_ID '{sqliteCommand.Parameters["Group_ID"].Value}'.");
                throw exception;
            }
        }

        public void DeleteGroupsMitigationsOrConditionsMappingByGroup(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = Properties.Resources.DeleteGroupsMitigationsOrConditionsMappingByGroup;
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to delete GroupsMitigationsOrConditions mapping for Group with Group_ID '{sqliteCommand.Parameters["Group_ID"].Value}'.");
                throw exception;
            }
        }

        public void DeleteGroupsConnectionsMappingByGroup(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = Properties.Resources.DeleteGroupsConnectionsMappingByGroup;
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to delete GroupsConnections mapping for Group with Group_ID '{sqliteCommand.Parameters["Group_ID"].Value}'.");
                throw exception;
            }
        }

        public void DeleteHardwareGroupsMappingByGroup(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = Properties.Resources.DeleteHardwareGroupsMappingByGroup;
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to delete HardwareGroups mapping for Group with Group_ID '{sqliteCommand.Parameters["Group_ID"].Value}'.");
                throw exception;
            }
        }

        public void DeleteGroups_IATA_StandardsMappingByGroup(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = Properties.Resources.DeleteGroups_IATA_StandardsMappingByGroup;
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to delete GroupsIATA_Standards mapping for Group with Group_ID '{sqliteCommand.Parameters["Group_ID"].Value}'.");
                throw exception;
            }
        }

        public void DeleteGroupsContactsMappingByGroup(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = Properties.Resources.DeleteGroupsContactsMappingByGroup;
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to delete GroupsContacts mapping for Group with Group_ID '{sqliteCommand.Parameters["Group_ID"].Value}'.");
                throw exception;
            }
        }

        public void DeleteGroup(SQLiteCommand sqliteCommand)
        {
            try
            {
                // Ensure that no mappings will be orphaned
                DeleteGroupsCCIsMappingByGroup(sqliteCommand);
                DeleteGroupsWaiversMappingByGroup(sqliteCommand);
                DeleteGroupsOverlaysMappingByGroup(sqliteCommand);
                DeleteGroupsConnectedSystemsMappingByGroup(sqliteCommand);
                DeleteGroupsMitigationsOrConditionsMappingByGroup(sqliteCommand);
                DeleteGroupsConnectionsMappingByGroup(sqliteCommand);
                DeleteHardwareGroupsMappingByGroup(sqliteCommand);
                DeleteGroups_IATA_StandardsMappingByGroup(sqliteCommand);
                DeleteGroupsContactsMappingByGroup(sqliteCommand);
                // Execute DeleteGroup Command
                sqliteCommand.CommandText = Properties.Resources.DeleteGroup;
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to delete Group with Group_ID '{sqliteCommand.Parameters["Group_ID"].Value}'.");
                throw exception;
            }
        }
    }
}
