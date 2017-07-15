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

        public void InsertVulnerabilitySource(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = Properties.Resources.InsertVulnerabilitySource;
                sqliteCommand.ExecuteNonQuery();
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
                sqliteCommand.CommandText = Properties.Resources.UpdateVulnerabilitySource;
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to update vulnerability source \"{0}\".", sqliteCommand.Parameters["Source_Name"].Value.ToString()));
                throw exception;
            }
        }

        public void InsertVulnerability(SQLiteCommand sqliteCommand, int lastVulnerabilitySourceId)
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
                sqliteCommand.CommandText = Properties.Resources.UpdateVulnerability;
                sqliteCommand.ExecuteNonQuery();
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
                    sqliteCommand.Parameters.Add(new SQLiteParameter("CCI", cci));
                    sqliteCommand.ExecuteNonQuery();
                    sqliteCommand.Parameters["CCI"].Value = string.Empty;
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
                sqliteCommand.CommandText = Properties.Resources.MapVulnerabilityToSource;
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to map vulnerability \"{0}\" to source \"{1}\".", vulnerabilityId, sourceId));
                log.Debug("Exception details: " + exception);
            }
        }
    }
}
