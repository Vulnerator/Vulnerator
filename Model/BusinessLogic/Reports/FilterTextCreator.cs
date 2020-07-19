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

        public string FindingType(string reportName, SQLiteCommand sqliteCommand)
        {
            try
            {
                string findingTypeFilter = string.Empty;
                sqliteCommand.CommandText = _ddlReader.ReadDdl(_storedProcedureBase + $"Select.{reportName}RequiredFindingTypes.dml", assembly);
                using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
                {
                    if (!sqliteDataReader.HasRows)
                    { return findingTypeFilter; }

                    findingTypeFilter = "(UF.FindingType_ID IN (";
                    while (sqliteDataReader.Read())
                    {
                        findingTypeFilter += $"'{sqliteDataReader["FindingType_ID"]}', ";
                    }

                    findingTypeFilter = findingTypeFilter.Remove(findingTypeFilter.Length - 2);
                    findingTypeFilter += ")) ";
                    return findingTypeFilter;
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to write findings to the 'POA&M' workbook.");
                throw exception;
            }
        }

        public string Severity(string reportName, SQLiteCommand sqliteCommand)
        {
            try
            {
                string severityFilter = string.Empty;
                sqliteCommand.CommandText = _ddlReader.ReadDdl(_storedProcedureBase + $"Select.{reportName}RequiredSeverities.dml", assembly);
                using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
                {
                    if (!sqliteDataReader.HasRows)
                    { return severityFilter; }

                    severityFilter = "IN (";
                    while (sqliteDataReader.Read())
                    {
                        severityFilter += $"'{sqliteDataReader["Severity"]}', ";
                    }

                    severityFilter = severityFilter.Remove(severityFilter.Length - 2);
                    severityFilter += ")";
                    return severityFilter;
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to write findings to the 'POA&M' workbook.");
                throw exception;
            }
        }

        public Tuple<string, List<string>> Status(string reportName, SQLiteCommand sqliteCommand)
        {
            try
            {
                string statusFilter = string.Empty;
                List<string> statusFilterList = new List<string>();
                sqliteCommand.CommandText = _ddlReader.ReadDdl(_storedProcedureBase + $"Select.{reportName}RequiredStatuses.dml", assembly);
                using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
                {
                    if (!sqliteDataReader.HasRows)
                    {
                        return Tuple.Create(statusFilter, statusFilterList);

                    }

                    statusFilter = "IN (";
                    while (sqliteDataReader.Read())
                    {
                        statusFilter += $"{sqliteDataReader["Status"]}, ";
                        statusFilterList.Add($"%{sqliteDataReader["Status"]}%");
                    }

                    statusFilter = statusFilter.Remove(statusFilter.Length - 2);
                    statusFilter += ")";
                    return Tuple.Create(statusFilter, statusFilterList);
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to write findings to the 'POA&M' workbook.");
                throw exception;
            }
        }
    }
}
