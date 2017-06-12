using log4net;
using System;
using System.Collections.Generic;
using System.Data.SQLite;
using Vulnerator.Model.Object;

namespace Vulnerator.Model.DataAccess
{
    public class DatabaseInterface
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(Logger));

        public int InsertVulnerabilitySource(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = Properties.Resources.InsertVulnerabilitySource;
                foreach (SQLiteParameter parameter in sqliteCommand.Parameters)
                {
                    if (sqliteCommand.Parameters.IndexOf(parameter) == 0)
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(44, "@" + parameter.ParameterName); }
                    else
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(44, "@" + parameter.ParameterName + ", "); }

                }
                foreach (SQLiteParameter parameter in sqliteCommand.Parameters)
                {
                    if (sqliteCommand.Parameters.IndexOf(parameter) == 0)
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(34, parameter.ParameterName); }
                    else
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(34, parameter.ParameterName + ", "); }
                }
                sqliteCommand.ExecuteNonQuery();
                sqliteCommand.Parameters.Clear();
                sqliteCommand.CommandText = "SELECT last_insert_rowid();";
                return int.Parse(sqliteCommand.ExecuteScalar().ToString());
            }
            catch (Exception exception)
            {
                log.Error("Unable to insert vulnerability source.");
                throw exception;
            }
        }

        public void UpdateVulnerabilitySource(SQLiteCommand sqliteCommand, int lastVulnerabilitySourceId)
        {
            try
            {
                sqliteCommand.Parameters.Add(new SQLiteParameter("Vulnerability_Source_ID", lastVulnerabilitySourceId));
                sqliteCommand.CommandText = Properties.Resources.UpdateVulnerabilitySource;
                foreach (SQLiteParameter parameter in sqliteCommand.Parameters)
                {
                    if (parameter.ParameterName.Equals("Vulnerability_ID"))
                    { continue; }
                    if (sqliteCommand.Parameters.IndexOf(parameter) == 0)
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(32, string.Format("{0} = @{0}", parameter.ParameterName)); }
                    else
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(32, string.Format("{0} = @{0}, ", parameter.ParameterName)); }
                }
                sqliteCommand.ExecuteNonQuery();
                sqliteCommand.Parameters.Clear();
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to update vulnerability source \"{0}\".", sqliteCommand.Parameters["Source_Name"].Value.ToString()));
                throw exception;
            }
        }

        public int InsertVulnerability(SQLiteCommand sqliteCommand, int lastVulnerabilitySourceId)
        {
            try
            {
                sqliteCommand.CommandText = Properties.Resources.InsertVulnerability;
                foreach (SQLiteParameter parameter in sqliteCommand.Parameters)
                {
                    if (sqliteCommand.Parameters.IndexOf(parameter) == 0)
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(39, "@" + parameter.ParameterName); }
                    else
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(39, "@" + parameter.ParameterName + ", "); }

                }
                foreach (SQLiteParameter parameter in sqliteCommand.Parameters)
                {
                    if (sqliteCommand.Parameters.IndexOf(parameter) == 0)
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(29, parameter.ParameterName); }
                    else
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(29, parameter.ParameterName + ", "); }
                }
                sqliteCommand.ExecuteNonQuery();
                sqliteCommand.Parameters.Clear();
                sqliteCommand.CommandText = "SELECT last_insert_rowid();";
                return int.Parse(sqliteCommand.ExecuteScalar().ToString());
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to insert vulnerability \"{0}\".", sqliteCommand.Parameters["Unique_Vulnerability_Identifier"].Value.ToString()));
                throw exception;
            }
        }

        public int UpdateVulnerability(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = Properties.Resources.UpdateVulnerability;
                foreach (SQLiteParameter parameter in sqliteCommand.Parameters)
                {
                    if (parameter.ParameterName.Equals("Vulnerability_ID"))
                    { continue; }
                    if (sqliteCommand.Parameters.IndexOf(parameter) == 0)
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(27, string.Format("{0} = @{0}", parameter.ParameterName)); }
                    else
                    { sqliteCommand.CommandText = sqliteCommand.CommandText.Insert(27, string.Format("{0} = @{0}, ", parameter.ParameterName)); }

                }
                sqliteCommand.ExecuteNonQuery();
                int vulnerabilityId = int.Parse(sqliteCommand.Parameters["Vulnerability_ID"].Value.ToString());
                sqliteCommand.Parameters.Clear();
                return vulnerabilityId;
            }
            catch (Exception exception)
            {
                log.Error("Unable to insert vulnerability.");
                throw exception;
            }
        }

        public void MapVulnerabilityToCCI(SQLiteCommand sqliteCommand, List<string> ccis, int lastVulnerabilityId)
        {
            try
            {
                sqliteCommand.CommandText = Properties.Resources.MapVulnerabilityToCci;
                foreach (string cci in ccis)
                {
                    sqliteCommand.Parameters.Add(new SQLiteParameter("Vulnerability_ID", lastVulnerabilityId));
                    sqliteCommand.Parameters.Add(new SQLiteParameter("CCI", cci));
                    sqliteCommand.ExecuteNonQuery();
                    sqliteCommand.Parameters.Clear();
                }
                ccis.Clear();
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to map vulnerability to CCI \"{0}\".", sqliteCommand.Parameters["cci"].Value.ToString()));
                log.Debug("Exception details: " + exception);
            }
        }

        public void MapVulnerabilityToSource(SQLiteCommand sqliteCommand, int vulnerabilityId, int sourceId)
        {
            try
            {
                sqliteCommand.Parameters.Add(new SQLiteParameter("Vulnerability_ID", vulnerabilityId));
                sqliteCommand.Parameters.Add(new SQLiteParameter("Vulnerability_Source_ID", sourceId));
                SQLiteCommand clonedCommand = (SQLiteCommand)sqliteCommand.Clone();
                clonedCommand.CommandText = Properties.Resources.VerifyVulnerabilitySourceMapping;
                sqliteCommand.CommandText = Properties.Resources.MapVulnerabilityToSource;
                using (SQLiteDataReader sqliteDataReader = clonedCommand.ExecuteReader())
                {
                    if (!sqliteDataReader.HasRows)
                    { sqliteCommand.ExecuteNonQuery(); }
                }
                sqliteCommand.Parameters.Clear();
            }
            catch (Exception exception)
            {
                log.Error("Unable to map vulnerability to source.");
                log.Debug("Exception details: " + exception);
            }
        }
    }
}
