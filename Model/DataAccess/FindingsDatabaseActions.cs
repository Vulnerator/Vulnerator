using log4net;
using System;
using System.Data.SQLite;
using System.IO;
using Vulnerator.Model.ModelHelper;
using Vulnerator.Model.Object;

namespace Vulnerator.Model.DataAccess
{
    public class FindingsDatabaseActions
    {
        private static string findingsDatabaseFilePath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        private static string findingsDatabaseFile = findingsDatabaseFilePath + @"\Vulnerator\Findings.sqlite";
        public static string findingsDatabaseConnection = @"Data Source = " + findingsDatabaseFilePath + @"\Vulnerator\Findings.sqlite; Version=3;";
        private static readonly ILog log = LogManager.GetLogger(typeof(Logger));
        public static SQLiteConnection sqliteConnection = new SQLiteConnection(findingsDatabaseConnection);
        public SQLiteTransaction sqLiteTransaction;

        public FindingsDatabaseActions()
        { CreateFindingsDatabase(); }

        private void CreateFindingsDatabase()
        {
            try
            {
                log.Info("Creating findings database.");
                if (System.IO.File.Exists(findingsDatabaseFile) && !findingsDatabaseFile.IsFileInUse())
                { System.IO.File.Delete(findingsDatabaseFile); }
                SQLiteConnection.CreateFile(findingsDatabaseFile);
                sqliteConnection.Open();
                using (SQLiteCommand sqliteCommand = new SQLiteCommand("", sqliteConnection))
                {
                    CreateScapScoresTable(sqliteCommand);
                    CreateAssetsTable(sqliteCommand);
                    CreateFileNamesTable(sqliteCommand);
                    CreateVulnerabilityTable(sqliteCommand);
                    CreateUniqueFindingTable(sqliteCommand);
                    CreateGroupsTable(sqliteCommand);
                    CreateFindingTypesTable(sqliteCommand);
                    CreateVulnerabilitySourcesTable(sqliteCommand);
                    CreateFindingStatusTable(sqliteCommand);
                    InsertFindingTypes(sqliteCommand);
                    InsertFindingStatuses(sqliteCommand);
                }
                log.Info("Findings database created successfully.");
            }
            catch(Exception exception)
            {
                log.Error("Findings database creation failed.");
                log.Debug("Exception details:", exception);
            }
        }
        
        public void RefreshFindingsDatabase()
        {
            try
            {
                log.Info("Refreshing findings database.");
                using (SQLiteCommand sqliteCommand = new SQLiteCommand("", sqliteConnection))
                {
                    sqliteCommand.CommandText = "SELECT COUNT(*) FROM Assets;";
                    if (Convert.ToInt32(sqliteCommand.ExecuteScalar()) >= 1)
                    {
                        DropFindingsDatabaseTableIndex(sqliteCommand);
                        DropFindingsDatabaseTables(sqliteCommand);
                        CreateScapScoresTable(sqliteCommand);
                        CreateAssetsTable(sqliteCommand);
                        CreateFileNamesTable(sqliteCommand);
                        CreateVulnerabilityTable(sqliteCommand);
                        CreateUniqueFindingTable(sqliteCommand);
                        CreateGroupsTable(sqliteCommand);
                        CreateFindingTypesTable(sqliteCommand);
                        CreateVulnerabilitySourcesTable(sqliteCommand);
                        CreateFindingStatusTable(sqliteCommand);
                        InsertFindingTypes(sqliteCommand);
                        InsertFindingStatuses(sqliteCommand);
                    }
                }
                log.Info("Findings database refeshed successfully.");
            }
            catch (Exception exception)
            {
                log.Error("Findings database refresh failed.");
                log.Debug("Exception details:", exception);
            }
        }

        private void CreateScapScoresTable(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = "CREATE TABLE ScapScores (" +
                    "ScapScore INTEGER, AssetIndex INTEGER, SourceIndex INTEGER);";
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                log.Error("Unable to create ScapScores table.");
                throw exception;
            }
        }

        private void CreateAssetsTable(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = "CREATE TABLE Assets (" +
                    "AssetIndex INTEGER PRIMARY KEY, AssetIdToReport TEXT UNIQUE ON CONFLICT IGNORE, " +
                    "HostName TEXT, IpAddress TEXT, OperatingSystem TEXT, IsCredentialed TEXT, " +
                    "Found21745 TEXT, Found26917 TEXT, GroupIndex INTEGER NOT NULL, " +
                    "FOREIGN KEY(GroupIndex) REFERENCES Groups(GroupIndex) ON UPDATE CASCADE);";
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                log.Error("Unable to create Assets table.");
                throw exception;
            }
        }

        private void CreateFileNamesTable(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = "CREATE TABLE FileNames (" +
                    "FileNameIndex INTEGER PRIMARY KEY, FileName TEXT UNIQUE ON CONFLICT IGNORE);";
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                log.Error("Unable to create FileNames table.");
                throw exception;
            }
        }

        private void CreateVulnerabilitySourcesTable(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = "CREATE TABLE VulnerabilitySources (" +
                    "SourceIndex INTEGER PRIMARY KEY, Source TEXT, Version TEXT, Release TEXT);";
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                log.Error("Unable to create VulnerabilitySources table.");
                throw exception;
            }
        }

        private void CreateVulnerabilityTable(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = "CREATE TABLE Vulnerability (" +
                    "VulnerabilityIndex INTEGER PRIMARY KEY, VulnId TEXT, StigId TEXT, " +
                    "VulnTitle TEXT, Description TEXT, RiskStatement TEXT, IaControl TEXT, " +
                    "NistControl TEXT, CPEs TEXT, CrossReferences TEXT, CheckContent TEXT, " +
                    "IavmNumber TEXT, FixText TEXT, PluginPublishedDate TEXT, " +
                    "PluginModifiedDate TEXT, PatchPublishedDate TEXT, Age TEXT, " +
                    "RawRisk TEXT, Impact TEXT, RuleId TEXT UNIQUE ON CONFLICT IGNORE, CciNumber TEXT);";
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                log.Error("Unable to create Vulnerability table.");
                throw exception;
            }
        }

        private void CreateUniqueFindingTable(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = "CREATE TABLE UniqueFinding (" +
                    "Comments TEXT, FindingDetails TEXT, PluginOutput TEXT, LastObserved TEXT, " +
                    "FindingTypeIndex INTEGER NOT NULL, SourceIndex INTEGER NOT NULL, " +
                    "FileNameIndex INTEGER NOT NULL, VulnerabilityIndex INTEGER NOT NULL, " +
                    "StatusIndex INTEGER NOT NULL, AssetIndex INTEGER NOT NULL, " +
                    "FOREIGN KEY(FindingTypeIndex) REFERENCES FindingTypes(FindingTypeIndex) ON UPDATE CASCADE, " +
                    "FOREIGN KEY(SourceIndex) REFERENCES VulnerabilitySources(SourceIndex) ON UPDATE CASCADE, " +
                    "FOREIGN KEY(FileNameIndex) REFERENCES FileNames(FileNameIndex) ON UPDATE CASCADE, " +
                    "FOREIGN KEY(VulnerabilityIndex) REFERENCES Vulnerability(VulnerabilityIndex) ON UPDATE CASCADE, " +
                    "FOREIGN KEY(StatusIndex) REFERENCES FindingStatuses(StatusIndex) ON UPDATE CASCADE, " +
                    "FOREIGN KEY(AssetIndex) REFERENCES Assets(AssetIndex) ON UPDATE CASCADE);";
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                log.Error("Unable to create UniqueFinding table.");
                throw exception;
            }
        }

        private void CreateGroupsTable(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = "CREATE TABLE Groups (" +
                    "GroupIndex INTEGER PRIMARY KEY, GroupName TEXT UNIQUE ON CONFLICT IGNORE);";
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                log.Error("Unable to create Groups table.");
                throw exception;
            }
        }

        private void CreateFindingTypesTable(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = "CREATE TABLE FindingTypes (" +
                     "FindingTypeIndex INTEGER PRIMARY KEY, FindingType TEXT UNIQUE ON CONFLICT IGNORE);";
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                log.Error("Unable to create FindingTypes table.");
                throw exception;
            }
        }

        private void CreateFindingStatusTable(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = "CREATE TABLE FindingStatuses (" +
                    "StatusIndex INTEGER PRIMARY KEY, Status TEXT UNIQUE ON CONFLICT IGNORE);";
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                log.Error("Unable to create FindingStatuses table.");
                throw exception;
            }
        }

        private void InsertFindingTypes(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = "INSERT INTO FindingTypes VALUES (NULL, 'ACAS'); " +
                    "INSERT INTO FindingTypes VALUES (NULL, 'CKL');" +
                    "INSERT INTO FindingTypes VALUES (NULL, 'XCCDF');" +
                    "INSERT INTO FindingTypes VALUES (NULL, 'WASSP');" +
                    "INSERT INTO FindingTypes VALUES (NULL, 'FPR');";
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                log.Error("Unable to insert initial finding types.");
                throw exception;
            }
        }

        private void InsertFindingStatuses(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = "INSERT INTO FindingStatuses VALUES (NULL, 'Ongoing');" +
                    "INSERT INTO FindingStatuses VALUES (NULL, 'Not Reviewed');" +
                    "INSERT INTO FindingStatuses VALUES (NULL, 'Not Applicable');" +
                    "INSERT INTO FindingStatuses VALUES (NULL, 'Error');" +
                    "INSERT INTO FindingStatuses VALUES (NULL, 'Informational');" +
                    "INSERT INTO FindingStatuses VALUES (NULL, 'Completed');";
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                log.Error("Unable to insert statuses.");
                throw exception;
            }
        }

        private void DropFindingsDatabaseTableIndex(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = "DROP INDEX IF EXISTS Assets.index_asset; " +
                    "DROP INDEX IF EXISTS Vulnerability.index_vulnid; " +
                    "DROP INDEX IF EXISTS Vulnerability.index_impact; " +
                    "DROP INDEX IF EXISTS Vulnerability.index_rawrisk;";
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                log.Error("Unable to drop Findings table index.");
                throw exception;
            }
        }

        private void DropFindingsDatabaseTables(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = "DROP TABLE IF EXISTS UniqueFinding; " +
                    "DROP TABLE IF EXISTS ScapScores; " +
                    "DROP TABLE IF EXISTS Assets; " +
                    "DROP TABLE IF EXISTS Groups; " +
                    "DROP TABLE IF EXISTS FileNames; " +
                    "DROP TABLE IF EXISTS Vulnerability; " +
                    "DROP TABLE IF EXISTS FindingTypes; " +
                    "DROP TABLE IF EXISTS FindingStatuses; " +
                    "DROP TABLE IF EXISTS VulnerabilitySources;";
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                log.Error("Unable to drop tables from the Findings database.");
                throw exception;
            }
        }

        public void DeleteFindingsDatabase()
        {
            if (sqliteConnection.State.ToString().Equals("Open"))
            { sqliteConnection.Close(); }
            System.IO.File.Delete(findingsDatabaseFile);
        }

        public void IndexDatabase()
        {
            try
            {
                using (SQLiteCommand sqlitecommand = sqliteConnection.CreateCommand())
                {
                    string indexAsset = "CREATE INDEX index_asset ON Assets (AssetIdToReport);";
                    string indexVulnerability = "CREATE INDEX index_vulnid ON Vulnerability (VulnId);";
                    string indexImpact = "CREATE INDEX index_impact ON Vulnerability (Impact);";
                    string indexRawRisk = "CREATE INDEX index_rawrisk ON Vulnerability (RawRisk);";
                    sqlitecommand.CommandText = indexAsset + indexVulnerability + indexImpact + indexRawRisk;
                    sqlitecommand.ExecuteNonQuery();
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to create indexes on Findings database.");
                throw exception;
            }
        }
    }
}
