using log4net;
using System;
using System.Data.SQLite;
using System.IO;
using System.Reflection;
using Vulnerator.Model.Object;

namespace Vulnerator.Model.DataAccess
{
    public class DatabaseBuilder
    {
        private Assembly assembly = Assembly.GetExecutingAssembly();
        private static string databasePath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        private static string databaseFile = databasePath + @"\Vulnerator\Vulnerator.sqlite";
        public static string databaseConnection = @"Data Source = " + databaseFile + @"; Version=3;";
        private static readonly ILog log = LogManager.GetLogger(typeof(Logger));
        public static SQLiteConnection sqliteConnection = new SQLiteConnection(databaseConnection);
        public SQLiteTransaction sqLiteTransaction;

        public DatabaseBuilder()
        {
            if (System.IO.File.Exists(databaseFile))
            { CheckDatabase(); }
            else
            { CreateDatabase(); }
        }

        private void CheckDatabase()
        {
            try
            {
                int currentVersion = 0;
                int latestVersion = 1;
                sqliteConnection.Open();
                using (SQLiteCommand sqliteCommand = new SQLiteCommand("PRAGMA user_version", sqliteConnection))
                { currentVersion = int.Parse(sqliteCommand.ExecuteScalar().ToString()); }
                sqliteConnection.Close();
                if (currentVersion == latestVersion)
                { return; }
                else
                {
                    using (SQLiteCommand sqliteCommand = new SQLiteCommand("", sqliteConnection))
                    {
                        for (int i = currentVersion; i <= latestVersion; i++)
                        { UpdateDatabase(i); }
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to verify the version of the Vulnerator Database.");
                log.Debug("Exception details:", exception);
            }
        }

        private void UpdateDatabase(int version)
        {
            try
            {
                switch (version)
                {
                    case 0:
                        {
                            System.IO.File.Delete(databaseFile);
                            CreateDatabase();
                            break;
                        }
                    default:
                        { break; }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to update the Vulnerator Database.");
                log.Debug("Exception details:", exception);
            }
        }

        private void CreateDatabase()
        {
            try
            {
                SQLiteConnection.CreateFile(databaseFile);
                sqliteConnection.Open();
                using (SQLiteCommand sqliteCommand = new SQLiteCommand(DdlTextReader("Vulnerator.Resources.DdlFiles.CreateDatabase.ddl"), sqliteConnection))
                { sqliteCommand.ExecuteNonQuery(); }
                log.Info("Findings database created successfully.");
            }
            catch (Exception exception)
            {
                log.Error("Findings database creation failed.");
                log.Debug("Exception details:", exception);
            }
        }

        public string DdlTextReader(string ddlResourceFile)
        {
            string ddlText = string.Empty;
            using (Stream stream = assembly.GetManifestResourceStream(ddlResourceFile))
            {
                using (StreamReader streamReader = new StreamReader(stream))
                { ddlText = streamReader.ReadToEnd(); }
            }
            return ddlText;
        }
    }
}