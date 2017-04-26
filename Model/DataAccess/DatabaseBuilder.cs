using log4net;
using System;
using System.Data.SQLite;
using Vulnerator.Model.Object;

namespace Vulnerator.Model.DataAccess
{
    public class DatabaseBuilder
    {
        private static string databasePath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
        private static string databaseFile = databasePath + @"\Vulnerator\Vulnerator.sqlite";
        public static string databaseConnection = @"Data Source = " + databaseFile + @"; Version=3;";
        private static readonly ILog log = LogManager.GetLogger(typeof(Logger));
        public static SQLiteConnection sqliteConnection = new SQLiteConnection(databaseConnection);
        public SQLiteTransaction sqLiteTransaction;

        public DatabaseBuilder()
        {
            if (!System.IO.File.Exists(databaseFile))
            { CreateDatabase(); }
        }

        private void CreateDatabase()
        {
            try
            {
                SQLiteConnection.CreateFile(databaseFile);
                sqliteConnection.Open();
                using (SQLiteCommand sqliteCommand = new SQLiteCommand("", sqliteConnection))
                {
                    DdlTest(sqliteCommand);
                    //CreateScapScoresTable(sqliteCommand);
                    //CreateAssetsTable(sqliteCommand);
                    //CreateFileNamesTable(sqliteCommand);
                    //CreateVulnerabilityTable(sqliteCommand);
                    //CreateUniqueFindingTable(sqliteCommand);
                    //CreateGroupsTable(sqliteCommand);
                    //CreateFindingTypesTable(sqliteCommand);
                    //CreateVulnerabilitySourcesTable(sqliteCommand);
                    //CreateFindingStatusTable(sqliteCommand);
                    //InsertFindingTypes(sqliteCommand);
                    //InsertFindingStatuses(sqliteCommand);
                }
                log.Info("Findings database created successfully.");
            }
            catch (Exception exception)
            {
                log.Error("Findings database creation failed.");
                log.Debug("Exception details:", exception);
            }
        }

        private void DdlTest(SQLiteCommand sqliteCommand)
        {
            sqliteCommand.CommandText = "CREATE TABLE Accessibility (Accessibility_ID INTEGER NOT NULL IDENTITY NOT FOR REPLICATION,LogicalAccess NVARCHAR(25) NOT NULL, PhysicalAccess NVARCHAR(25) NOT NULL, AvScan NVARCHAR(25) NOT NULL, DodinConnectionPeriodicity NVARCHAR(25) NOT NULL) ON \"default\" GO";
            sqliteCommand.ExecuteNonQuery();
        }

        private void CreateScapScoresTable(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = "CREATE TABLE ScapScores (" +
                    "ScapScoreIndex INTEGER PRIMARY KEY, ScapScore INTEGER NOT NULL, " +
                    "AssetIndex INTEGER NOT NULL, SourceIndex INTEGER NOT NULL), " +
                    "FOREIGN KEY(AssetIndex) REFERENCES Assets(AssetIndex) ON UPDATE CASCADE, " +
                    "FOREIGN KEY(SourceIndex) REFERENCES VulnerabilitySources(SourceIndex) ON UPDATE CASCADE; " +
                    "CREATE INDEX scapscore_index ON ScapScores(ScapScoreIndex);";
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
                    "AssetIndex INTEGER PRIMARY KEY, AssetIdToReport TEXT NOT NULL UNIQUE ON CONFLICT IGNORE, " +
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
                    "FileNameIndex INTEGER PRIMARY KEY, FileName TEXT NOT NULL UNIQUE ON CONFLICT IGNORE, " +
                    "FilePath TEXT NOT NULL UNIQUE ON CONFLICT IGNORE, IsCurrent TEXT NOT NULL, GroupIndex INTEGER NOT NULL, " +
                    "FOREIGN KEY(GroupIndex) REFERENCES Groups(GroupIndex) ON UPDATE CASCADE); " +
                    "CREATE INDEX file_index ON FileNames(FileNameIndex);";
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
                    "SourceIndex INTEGER PRIMARY KEY, Source TEXT NOT NULL, Version TEXT, Release TEXT); " +
                    "CREATE INDEX source_index ON VulnerabilitySources(SourceIndex);";
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
                    "VulnerabilityIndex INTEGER PRIMARY KEY, VulnId TEXT NOT NULL, StigId TEXT, " +
                    "VulnTitle TEXT, Description TEXT, RiskStatement TEXT, IaControl TEXT, " +
                    "NistControl TEXT, CPEs TEXT, CrossReferences TEXT, CheckContent TEXT, " +
                    "IavmNumber TEXT, FixText TEXT, PluginPublishedDate TEXT, " +
                    "PluginModifiedDate TEXT, PatchPublishedDate TEXT, Age TEXT, " +
                    "RawRisk TEXT, Impact TEXT, RuleId TEXT UNIQUE ON CONFLICT IGNORE, " +
                    "CciNumber TEXT, NessusFamily TEXT, SecurityObjective TEXT); " +
                    "CREATE INDEX vuln_index ON Vulnerability(VulnerabilityIndex);";
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
                    "UniqueFindingIndex INTEGER PRIMARY KEY, Comments TEXT, FindingDetails TEXT, PluginOutput TEXT, " +
                    "FirstDiscovered TEXT, LastObserved TEXT, ApprovalStatus TEXT NOT NULL, " +
                    "FindingTypeIndex INTEGER NOT NULL, SourceIndex INTEGER NOT NULL, FileNameIndex INTEGER NOT NULL, " +
                    "VulnerabilityIndex INTEGER NOT NULL, StatusIndex INTEGER NOT NULL, AssetIndex INTEGER NOT NULL, " +
                    "FOREIGN KEY(FindingTypeIndex) REFERENCES FindingTypes(FindingTypeIndex) ON UPDATE CASCADE, " +
                    "FOREIGN KEY(SourceIndex) REFERENCES VulnerabilitySources(SourceIndex) ON UPDATE CASCADE, " +
                    "FOREIGN KEY(FileNameIndex) REFERENCES FileNames(FileNameIndex) ON UPDATE CASCADE, " +
                    "FOREIGN KEY(VulnerabilityIndex) REFERENCES Vulnerability(VulnerabilityIndex) ON UPDATE CASCADE, " +
                    "FOREIGN KEY(StatusIndex) REFERENCES FindingStatuses(StatusIndex) ON UPDATE CASCADE, " +
                    "FOREIGN KEY(AssetIndex) REFERENCES FindingStatuses(AssetIndex) ON UPDATE CASCADE); " +
                    "CREATE INDEX uniquefinding_index ON UniqueFinding(UniqueFindingIndex);";
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
                    "GroupIndex INTEGER PRIMARY KEY, " +
                    "ProjectName TEXT NOT NULL UNIQUE ON CONFLICT IGNORE, " +
                    "AccreditationName TEXT); " +
                    "CREATE INDEX group_index ON Groups(GroupIndex);";
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
                     "FindingTypeIndex INTEGER PRIMARY KEY, " +
                     "FindingType TEXT NOT NULL UNIQUE ON CONFLICT IGNORE); " +
                     "CREATE INDEX findingtype_index ON FindingTypes(FindingTypeIndex);";
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
                    "StatusIndex INTEGER PRIMARY KEY, Status TEXT UNIQUE ON CONFLICT IGNORE); " +
                    "CREATE INDEX status_index ON FindingStatuses(StatusIndex);";
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                log.Error("Unable to create FindingStatuses table.");
                throw exception;
            }
        }

        private void CreateUserGroupsTable(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = "CREATE TABLE UserGroups (" +
                    "GroupIndex INTEGER PRIMARY KEY, GroupName Text NOT NULL, " +
                    "UserIndex INTEGER, AssetIndex INTEGER); CREATE INDEX " +
                    "usergroup_index on UserGroups(GroupIndex);";
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                log.Error("Unable to create UserGroups table.");
                throw exception;
            }
        }

        private void CreateWindowsUsersTable(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = "CREATE TABLE WindowsUsers (" +
                    "UserIndex INTEGER PRIMARY KEY, IsGuest TEXT, IsDomainAccount TEXT, " +
                    "IsLocalAccount TEXT, DomainDisabled TEXT, DomainAutoDisabled TEXT, " +
                    "DomainCantChangePw TEXT, DomainNeverChangePw TEXT, DomainNoLogon TEXT, " +
                    "DomainPwNoExpire TEXT, LocalDisabled TEXT, LocalAutoDisabled TEXT, " +
                    "LocalCantChangePw TEXT, LocalNeverChangePw TEXT, LocalNoLogon TEXT, " +
                    "LocalPwNoExpire TEXT);" +
                    "CREATE INDEX usergroup_index on UserGroups(GroupIndex);";
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                log.Error("Unable to create WindowsUsers table.");
                throw exception;
            }
        }

        private void CreatePoamAndRarInputsTable(SQLiteCommand sqliteCommand)
        {
            try
            {
                sqliteCommand.CommandText = "CREATE TABLE PoamAndRarInputs (" +
                    "PoamAndRarIndex INTEGER PRIMARY KEY, ";
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                log.Error("Unable to create PoamAndRarInputs table.");
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
                    "INSERT INTO FindingTypes VALUES (NULL, 'Fortify');" +
                    "INSERT INTO FindingTypes VALUES (NULL, 'WebInspect');";
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
                    "INSERT INTO FindingStatuses VALUES (NULL, 'Completed');" +
                    "INSERT INTO FindingStatuses VALUES (NULL, 'False Positive');";
                sqliteCommand.ExecuteNonQuery();
            }
            catch (Exception exception)
            {
                log.Error("Unable to insert statuses.");
                throw exception;
            }
        }
    }
}
