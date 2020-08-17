using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Vulnerator.Model.Object;
using Vulnerator.Model.DataAccess;
using log4net;
using System.Data.SQLite;
using Vulnerator.Helper;

namespace Vulnerator.Model.BusinessLogic
{
    public class AssociateStig
    {
        private DatabaseInterface databaseInterface = new DatabaseInterface();

        public void ToHardware(int vulnerabilitySourceId, int hardwareId)
        {
            try
            {
                if (!DatabaseBuilder.sqliteConnection.State.Equals("Open"))
                { DatabaseBuilder.sqliteConnection.Open(); }
                using (SQLiteTransaction sqliteTransaction = DatabaseBuilder.sqliteConnection.BeginTransaction())
                {
                    using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                    {
                        databaseInterface.InsertParameterPlaceholders(sqliteCommand);
                        PrepareUniqueFinding(sqliteCommand);
                        sqliteCommand.Parameters["Hardware_ID"].Value = hardwareId;
                        sqliteCommand.Parameters["VulnerabilitySource_ID"].Value = vulnerabilitySourceId;
                        List<string> vulnerabilities = databaseInterface.SelectUniqueVulnerabilityIdentifiersBySource(sqliteCommand);
                        databaseInterface.SelectHardware(sqliteCommand);
                        databaseInterface.InsertParsedFileSource(sqliteCommand);
                        databaseInterface.SelectVulnerabilitySourceName(sqliteCommand);
                        databaseInterface.MapHardwareToVulnerabilitySource(sqliteCommand);
                        foreach (string vulnerability in vulnerabilities)
                        {
                            sqliteCommand.Parameters["UniqueVulnerabilityIdentifier"].Value = vulnerability;
                            databaseInterface.UpdateUniqueFinding(sqliteCommand);
                            databaseInterface.InsertUniqueFinding(sqliteCommand);
                        }
                    }
                    sqliteTransaction.Commit();
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to associate STIG with VulnerabilitySource_ID '{vulnerabilitySourceId}' to hardware asset with Hardware_ID '{hardwareId}'");
                throw exception;
            }
            finally
            {
                if (!DatabaseBuilder.sqliteConnection.State.Equals(ConnectionState.Closed))
                { DatabaseBuilder.sqliteConnection.Close(); }
            }
        }

        private void PrepareUniqueFinding(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.Parameters["Status"].Value = "Not Reviewed";
                sqliteCommand.Parameters["LastObserved"].Value = DateTime.Now.ToShortDateString();
                sqliteCommand.Parameters["DeltaAnalysisIsRequired"].Value = "False";
                sqliteCommand.Parameters["Approval_Status"].Value = "Not Approved";
                sqliteCommand.Parameters["FirstDiscovered"].Value = DateTime.Now.ToShortDateString();
                sqliteCommand.Parameters["Classification"].Value = "Unclassified";
                sqliteCommand.Parameters["FindingType"].Value = "CKL";
                sqliteCommand.Parameters["FindingSourceFileName"].Value =
                    $"Vulnerator Associated - {DateTime.Now.ToShortDateString()}";
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to prepare the SQLiteCommand to insert a new unique finding.");
                throw exception;
            }
        }
    }
}
