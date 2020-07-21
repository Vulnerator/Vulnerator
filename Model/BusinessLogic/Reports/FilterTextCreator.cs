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

        public string FindingType(SQLiteCommand sqliteCommand)
        {
            try
            {
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

        public string Group(SQLiteCommand sqliteCommand)
        {
            try
            {
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

        public string Severity(SQLiteCommand sqliteCommand)
        {
            try
            {
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

        public string Status(SQLiteCommand sqliteCommand)
        {
            try
            {
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
    }
}
