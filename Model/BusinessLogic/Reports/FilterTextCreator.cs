using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;
using Vulnerator.Helper;

namespace Vulnerator.Model.BusinessLogic.Reports
{
    public class FilterTextCreator
    {
        private DdlReader _ddlReader = new DdlReader();
        private Assembly assembly = Assembly.GetExecutingAssembly();
        private string _storedProcedureBase = "Vulnerator.Resources.DdlFiles.StoredProcedures.";

        private bool GetUseGlobalValue(SQLiteCommand sqliteCommand, string columnName)
        {
            try
            {
                sqliteCommand.CommandText = _ddlReader.ReadDdl(_storedProcedureBase + "Select.ReportUseGlobalValueUserSettings", assembly);
                sqliteCommand.CommandText =
                    sqliteCommand.CommandText.Replace("[COLUMN_NAME]", "UseGlobalFindingTypeValue");
                
                using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
                {
                    if (sqliteDataReader.HasRows)
                    {
                        while (sqliteDataReader.Read())
                        {
                            if (sqliteDataReader["UseGlobalFindingTypeValue"] != null)
                            { return true; }

                            return false;
                        }
                    }

                    return false;
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to obtain user global filter requirements for '{columnName}'.");
                throw exception;
            }
        }

        public string FindingType(SQLiteCommand sqliteCommand, string displayedReportName)
        {
            try
            {
                sqliteCommand.Parameters.Add(new SQLiteParameter("DisplayedReportName", displayedReportName));
                if (GetUseGlobalValue(sqliteCommand, "UseGlobalFindingTypeValue"))
                { sqliteCommand.Parameters["DisplayedReportName"].Value = "Global"; }

                string filter = string.Empty;
                sqliteCommand.CommandText = _ddlReader.ReadDdl(_storedProcedureBase + "Select.RequiredFindingTypes.dml", assembly);
                using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
                {
                    if (!sqliteDataReader.HasRows)
                    { return filter; }

                    filter = "(UF.FindingType_ID IN (";
                    while (sqliteDataReader.Read())
                    {
                        filter += $"'{sqliteDataReader["FindingType_ID"]}', ";
                    }

                    filter = filter.Remove(filter.Length - 2);
                    filter += ")) ";
                    return filter;
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to obtain 'FindingType' filter requirements.");
                throw exception;
            }
        }

        public string Group(SQLiteCommand sqliteCommand, string displayedReportName)
        {
            try
            {
                sqliteCommand.Parameters.Add(new SQLiteParameter("DisplayedReportName", displayedReportName));
                if (GetUseGlobalValue(sqliteCommand, "UseGlobalGroupsValue"))
                { sqliteCommand.Parameters["DisplayedReportName"].Value = "Global"; }

                string filter = string.Empty;
                sqliteCommand.CommandText = _ddlReader.ReadDdl(_storedProcedureBase + "Select.RequiredGroups.dml", assembly);
                using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
                {
                    if (!sqliteDataReader.HasRows)
                    { return filter; }

                    filter = "(HG.Group_ID IN (";
                    while (sqliteDataReader.Read())
                    {
                        filter += $"'{sqliteDataReader["Group_ID"]}', ";
                    }

                    filter = filter.Remove(filter.Length - 2);
                    filter += ")) ";
                    return filter;
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to obtain 'Group' filter requirements.");
                throw exception;
            }
        }

        public string Severity(SQLiteCommand sqliteCommand, string displayedReportName)
        {
            try
            {
                sqliteCommand.Parameters.Add(new SQLiteParameter("DisplayedReportName", displayedReportName));
                if (GetUseGlobalValue(sqliteCommand, "UseGlobalSeverityValue"))
                { sqliteCommand.Parameters["DisplayedReportName"].Value = "Global"; }

                string filter = string.Empty;
                sqliteCommand.CommandText = _ddlReader.ReadDdl(_storedProcedureBase + "Select.RequiredSeverities.dml", assembly);
                using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
                {
                    if (!sqliteDataReader.HasRows)
                    { return filter; }

                    filter = "IN (";
                    while (sqliteDataReader.Read())
                    {
                        filter += $"'{sqliteDataReader["Severity"].ToString().Remove(0, 4)}', ";
                    }

                    filter = filter.Remove(filter.Length - 2);
                    filter += ")";
                    return filter;
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to obtain 'Severity' filter requirements.");
                throw exception;
            }
        }

        public string Status(SQLiteCommand sqliteCommand, string displayedReportName)
        {
            try
            {
                sqliteCommand.Parameters.Add(new SQLiteParameter("DisplayedReportName", displayedReportName));
                if (GetUseGlobalValue(sqliteCommand, "UseGlobalStatusValue"))
                { sqliteCommand.Parameters["DisplayedReportName"].Value = "Global"; }

                string filter = string.Empty;
                sqliteCommand.CommandText = _ddlReader.ReadDdl(_storedProcedureBase + "Select.RequiredStatuses.dml", assembly);
                using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
                {
                    if (!sqliteDataReader.HasRows)
                    { return filter; }

                    filter = "IN (";
                    while (sqliteDataReader.Read())
                    {
                        filter += $"'{sqliteDataReader["Status"]}', ";
                    }

                    filter = filter.Remove(filter.Length - 2);
                    filter += ")";
                    return filter;
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to obtain 'Status' filter requirements.");
                throw exception;
            }
        }

        public string RmfOverride(SQLiteCommand sqliteCommand, string displayedReportName)
        {
            try
            {
                sqliteCommand.Parameters.Add(new SQLiteParameter("DisplayedReportName", displayedReportName));
                if (GetUseGlobalValue(sqliteCommand, "UseGlobalRmfOverrideValue"))
                { sqliteCommand.Parameters["DisplayedReportName"].Value = "Global"; }

                sqliteCommand.CommandText = _ddlReader.ReadDdl(_storedProcedureBase + "Select.ReportRmfOverrideUserSettings.dml", assembly);
                using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
                {
                    if (!sqliteDataReader.HasRows)
                    { return string.Empty; }


                    return "LEFT JOIN (SELECT GMOCV.Group_ID, GMOCV.Vulnerability_ID, GMOCV.MitigationOrCondition_ID, MitigatedStatus, " +
                           "SeverityPervasiveness, ThreatRelevance, ThreatDescription, " +
                           "Likelihood, Impact, ImpactDescription, ResidualRisk, ResidualRiskAfterProposed, " +
                           "EstimatedCompletionDate FROM GroupsMitigationsOrConditionsVulnerabilities GMOCV LEFT JOIN MitigationsOrConditions MOC " +
                           "on GMOCV.MitigationOrCondition_ID = MOC.MitigationOrCondition_ID LEFT JOIN Groups G2 on GMOCV.Group_ID = G2.Group_ID " + 
                           $"WHERE GMOCV.Group_ID = {sqliteDataReader["Group_ID"]}) " +
                           "GroupsMitigationsOrConditionsVulnerabilities2 on (UF.Vulnerability_ID = GroupsMitigationsOrConditionsVulnerabilities2.Vulnerability_ID " +
                           "AND HG.Group_ID = GroupsMitigationsOrConditionsVulnerabilities2.Group_ID)";
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to obtain 'Status' filter requirements.");
                throw exception;
            }
        }
    }
}
