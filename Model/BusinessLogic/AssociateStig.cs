using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Vulnerator.Model.Object;
using Vulnerator.Model.DataAccess;
using log4net;
using System.Data.SQLite;

namespace Vulnerator.Model.BusinessLogic
{
    public class AssociateStig
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(Logger));
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
                        sqliteCommand.Parameters["Vulnerability_Source_ID"].Value = vulnerabilitySourceId;
                        List<string> vulnerabilities = databaseInterface.SelectUniqueVulnerabilityIdentifiersBySource(sqliteCommand);
                        databaseInterface.SelectHardware(sqliteCommand);
                        databaseInterface.InsertParsedFileSource(sqliteCommand);
                        databaseInterface.SelectVulnerabilitySourceName(sqliteCommand);
                        databaseInterface.MapHardwareToVulnerabilitySource(sqliteCommand);
                        foreach (string vulnerability in vulnerabilities)
                        {
                            sqliteCommand.Parameters["Unique_Vulnerability_Identifier"].Value = vulnerability;
                            databaseInterface.UpdateUniqueFinding(sqliteCommand);
                            databaseInterface.InsertUniqueFinding(sqliteCommand);
                        }
                    }
                    sqliteTransaction.Commit();
                }
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to associate STIG to hardware asset"));
                throw exception;
            }
            finally
            {
                if (!DatabaseBuilder.sqliteConnection.State.Equals("Closed"))
                { DatabaseBuilder.sqliteConnection.Close(); }
            }
        }

        private void PrepareUniqueFinding(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.Parameters["Status"].Value = "Not Reviewed";
                sqliteCommand.Parameters["Last_Observed"].Value = DateTime.Now.ToShortDateString();
                sqliteCommand.Parameters["Delta_Analysis_Required"].Value = "False";
                sqliteCommand.Parameters["Approval_Status"].Value = "Not Approved";
                sqliteCommand.Parameters["First_Discovered"].Value = DateTime.Now.ToShortDateString();
                sqliteCommand.Parameters["Classification"].Value = "Unclassified";
                sqliteCommand.Parameters["Finding_Type"].Value = "CKL";
                sqliteCommand.Parameters["Finding_Source_File_Name"].Value =
                    $"Vulnerator Associated - {DateTime.Now.ToShortDateString()}";
            }
            catch (Exception exception)
            {
                log.Error(string.Format("Unable to prepare the SQLiteCommand to insert a new unique finding."));
                throw exception;
            }
        }
    }
}
