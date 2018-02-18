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
    public class StigAssociator
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(Logger));
        private DatabaseInterface databaseInterface = new DatabaseInterface();

        public void StigToHardware(int vulnerabilitySourceId)
        {
            try
            {
                if (!DatabaseBuilder.sqliteConnection.State.Equals("Open"))
                { DatabaseBuilder.sqliteConnection.Open(); }
                using (SQLiteTransaction sqliteTransaction = DatabaseBuilder.sqliteConnection.BeginTransaction())
                {
                    using (SQLiteCommand sqliteCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                    {

                    }
                }
            }
            catch (Exception exception)
            {
                log.Error(string.Format(""));
                throw exception;
            }
        }
    }
}
