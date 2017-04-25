using log4net;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Data.SQLite;
using System.IO;
using System.Linq;
using Vulnerator.Model.BusinessLogic;
using Vulnerator.ViewModel;

namespace Vulnerator.Model.DataAccess
{
    /// <summary>
    /// Class containing all methods utilized to update the database utilized by Vulnerator
    /// </summary>
    public class VulneratorDatabaseActions
    {
        private static string vulneratorDatabaseFilePath = ConfigAlter.ReadSettingsFromDictionary("tbMitDbLocation");
        private static string vulneratorDatabaseConnection = @"Data Source = " + vulneratorDatabaseFilePath + "; Version=3;";
        private GuiActions guiActions = new GuiActions();
        private static readonly ILog log = LogManager.GetLogger(typeof(Logger));

        /// <summary>
        /// Create the database in which Vulnerator stores mitigation, system, project, and
        /// email preference information
        /// </summary>
        public void CreateVulneratorDatabase()
        {
            try
            {
                if (!File.Exists(vulneratorDatabaseFilePath))
                {
                    log.Info("Creating Vulnerator application database.");
                    SQLiteConnection.CreateFile(vulneratorDatabaseFilePath);
                    using (SQLiteConnection sqliteConnection = new SQLiteConnection(vulneratorDatabaseConnection))
                    {
                        sqliteConnection.Open();
                        using (SQLiteCommand sqliteCommand = new SQLiteCommand("", sqliteConnection))
                        {
                            sqliteCommand.CommandText = "CREATE TABLE SystemGroups(GroupName NVARCHAR(100) NOT NULL PRIMARY KEY, MacLevel NVARCHAR(3))";
                            sqliteCommand.ExecuteNonQuery();
                            sqliteCommand.CommandText = "CREATE TABLE Mitigations(VulnerabilityId NVARCHAR(50), FindingStatus NVARCHAR(30), FindingText NVARCHAR(2000), " +
                                "GroupName NVARCHAR(100), FOREIGN KEY (GroupName) REFERENCES SystemGroups(GroupName))";
                            sqliteCommand.ExecuteNonQuery();
                            sqliteCommand.CommandText = "CREATE TABLE Systems(SystemHostName NVARCHAR(100), SystemIpAddress NVARCHAR(50), GroupName NVARCHAR(100), " +
                                "FOREIGN KEY (GroupName) REFERENCES SystemGroups(GroupName))";
                            sqliteCommand.ExecuteNonQuery();
                            sqliteCommand.CommandText = "CREATE TABLE PointsOfContact(Name NVARCHAR(100), Title NVARCHAR(100), Email NVARCHAR(100), FilterOneInclusion NVARCHAR(5), " +
                                "FilterTwoInclusion NVARCHAR(5), FilterThreeInclusion NVARCHAR(5), FilterFourInclusion NVARCHAR(5), SystemHostName NVARCHAR(100), " +
                                "SystemIpAddress NVARCHAR(50), GroupName NVARCHAR(100), FOREIGN KEY (GroupName) REFERENCES SystemGroups(GroupName))";
                            sqliteCommand.ExecuteNonQuery();
                            sqliteCommand.CommandText = "CREATE TABLE EmailText(FilterOne NVARCHAR(2000), FilterTwo NVARCHAR(2000), FilterThree NVARCHAR(2000), FilterFour NVARCHAR(2000))";
                            sqliteCommand.ExecuteNonQuery();
                        }
                        sqliteConnection.Close();
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to create Vulnerator application database.");
                log.Debug("Exception details: " + exception);
            }
        }

        /// <summary>
        /// Initially populates the AsyncObservableCollections utilized to display the relevant information on application startup or when the database source is changed
        /// </summary>
        /// <param name="mainWindowViewModel">MainWindowViewModel class housing all GUI elements to be updated</param>
        public void PopulateGuiLists(MainWindowViewModel mainWindowViewModel)
        {
            try
            {
                using (SQLiteConnection sqliteConnection = new SQLiteConnection(vulneratorDatabaseConnection))
                {
                    sqliteConnection.Open();
                    using (SQLiteCommand sqliteCommand = new SQLiteCommand("SELECT * FROM Mitigations", sqliteConnection))
                    {
                        PopulateMitigationList(sqliteCommand, mainWindowViewModel);
                        PopulateUpdatableSystemGroupList(sqliteCommand, mainWindowViewModel);
                        PopulateContactList(sqliteCommand, mainWindowViewModel);
                        PopulateMonitoredSystemList(sqliteCommand, mainWindowViewModel);
                        PopulateUpdatableMonitoredSystemList(sqliteCommand, mainWindowViewModel);
                        PopulateContactTitleList(sqliteCommand, mainWindowViewModel);
                    }
                    sqliteConnection.Close();
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to populate GUI lists.");
                throw exception;
            }
        }

        private void PopulateMitigationList(SQLiteCommand sqliteCommand, MainWindowViewModel mainWindowViewModel)
        {
            try
            {
                using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
                {
                    while (sqliteDataReader.Read())
                    {
                        mainWindowViewModel.MitigationList.Add(
                            new MitigationItem(
                                sqliteDataReader.GetString(0),
                                sqliteDataReader.GetString(3),
                                sqliteDataReader.GetString(1),
                                sqliteDataReader.GetString(2),
                                false));
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to populate mitigation list.");
                throw exception;
            }
        }

        private void PopulateUpdatableSystemGroupList(SQLiteCommand sqliteCommand, MainWindowViewModel mainWindowViewModel)
        {
            try
            {
                sqliteCommand.CommandText = "SELECT * FROM SystemGroups";
                using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
                {
                    while (sqliteDataReader.Read())
                    {
                        mainWindowViewModel.SystemGroupList.Add(new SystemGroup(sqliteDataReader.GetString(0)));
                        mainWindowViewModel.SystemGroupListForUpdating.Add(new UpdatableSystemGroup(sqliteDataReader.GetString(0)));
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to populate updatable system group list.");
                throw exception;
            }
        }

        private void PopulateContactList(SQLiteCommand sqliteCommand, MainWindowViewModel mainWindowViewModel)
        {
            try
            {
                sqliteCommand.CommandText = "SELECT PointsOfContact.Name, PointsOfContact.Title, PointsOfContact.Email, PointsOfContact.SystemHostName, " +
                                "PointsOfContact.SystemIpAddress, SystemGroups.GroupName FROM PointsOfContact INNER JOIN SystemGroups ON PointsOfContact.GroupName = SystemGroups.GroupName";
                using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
                {
                    while (sqliteDataReader.Read())
                    {
                        mainWindowViewModel.ContactList.Add(
                            new Contact(
                                sqliteDataReader.GetString(0),
                                sqliteDataReader.GetString(5),
                                sqliteDataReader.GetString(2),
                                sqliteDataReader.GetString(1),
                                sqliteDataReader.GetString(4),
                                sqliteDataReader.GetString(3),
                                false));
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to populate contact list.");
                throw exception;
            }
        }

        private void PopulateMonitoredSystemList(SQLiteCommand sqliteCommand, MainWindowViewModel mainWindowViewModel)
        {
            try
            {
                sqliteCommand.CommandText = "SELECT SystemHostName, SystemIpAddress FROM Systems GROUP BY SystemHostName, SystemIpAddress";
                using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
                {
                    while (sqliteDataReader.Read())
                    {
                        mainWindowViewModel.MonitoredSystemList.Add(
                            new MonitoredSystem(
                                sqliteDataReader.GetString(0) + " : " +
                                sqliteDataReader.GetString(1)));
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to populate monitored system list.");
                throw exception;
            }
        }

        private void PopulateUpdatableMonitoredSystemList(SQLiteCommand sqliteCommand, MainWindowViewModel mainWindowViewModel)
        {
            try
            {
                sqliteCommand.CommandText = "SELECT GroupName, SystemHostName, SystemIpAddress FROM Systems GROUP BY GroupName, SystemHostName, SystemIpAddress";
                using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
                {
                    while (sqliteDataReader.Read())
                    {
                        mainWindowViewModel.MonitoredSystemListForUpdating.Add(
                            new UpdatableMonitoredSystem(
                                sqliteDataReader.GetString(0) + " : " +
                                sqliteDataReader.GetString(1) + " : " +
                                sqliteDataReader.GetString(2)));
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to populate updatable monitored system list.");
                throw exception;
            }
        }

        private void PopulateContactTitleList(SQLiteCommand sqliteCommand, MainWindowViewModel mainWindowViewModel)
        {
            try
            {
                sqliteCommand.CommandText = "SELECT DISTINCT Title FROM PointsOfContact";
                using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
                {
                    while (sqliteDataReader.Read())
                    {
                        mainWindowViewModel.ContactTitleList.Add(
                            new ContactTitle(sqliteDataReader.GetString(0)));
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to populate contact title list.");
                throw exception;
            }
        }

        /// <summary>
        /// Imports a "Mitigations.txt" file into the "Mitigations" table of the provided database
        /// </summary>
        /// <param name="mitigationsTextFile">File name of the "Mitigations.txt" file to be imported</param>
        /// <param name="systemGroupName">The name of the group that the vulnerabilities in the "Mitigations.txt" file belong to</param>
        /// <param name="systemGroupMacLevel">The MAC level of the group that the vulnerabilities in the "Mitigations.txt" file belong to</param>
        /// <param name="vulnerabilityStatus">The status of the vulnerabilities being imported</param>
        /// <param name="mainWindowViewModel">MainWindowViewModel class housing all GUI elements to be updated</param>
        /// <returns>string value</returns>
        public string ImportMitigations(string mitigationsTextFile, string systemGroupName, string vulnerabilityStatus, MainWindowViewModel mainWindowViewModel)
        {
            try
            {
                log.Info("Importing mitigation statements into database.");
                using (SQLiteConnection sqliteConnection = new SQLiteConnection(vulneratorDatabaseConnection))
                {
                    sqliteConnection.Open();

                    string lookupAndInsertGroupInDatabaseResult = LookupAndInsertGroupInDatabase(sqliteConnection, systemGroupName);
                    if (!lookupAndInsertGroupInDatabaseResult.Contains("Success"))
                    { return lookupAndInsertGroupInDatabaseResult; }
                    guiActions.InsertGroupInObservableCollections(systemGroupName, mainWindowViewModel);

                    foreach (string line in File.ReadLines(mitigationsTextFile))
                    {
                        if (line.StartsWith("#"))
                        {
                            string[] separatedIdsFromMitigationText = line.Split('|');
                            string[] individualVulnerabilityIds = separatedIdsFromMitigationText[0].Split(' ');
                            string mitigationText = separatedIdsFromMitigationText[1].Trim();

                            foreach (string vulnerabilityId in individualVulnerabilityIds)
                            {
                                string finalVulnerabilityIdForWriting;
                                vulnerabilityId.Trim();
                                if (vulnerabilityId.StartsWith("#"))
                                { finalVulnerabilityIdForWriting = vulnerabilityId.Replace("#", string.Empty); }
                                else
                                { finalVulnerabilityIdForWriting = vulnerabilityId; }

                                string mitigationLookupAndInsertResult = LookupAndInsertMitigationInDatabase(sqliteConnection, finalVulnerabilityIdForWriting, systemGroupName, vulnerabilityStatus, mitigationText);
                                if (!mitigationLookupAndInsertResult.Contains("Success"))
                                { return mitigationLookupAndInsertResult; }

                                mainWindowViewModel.MitigationList.Add(new MitigationItem(finalVulnerabilityIdForWriting, systemGroupName, vulnerabilityStatus, mitigationText, false));
                            }
                        }
                    }
                    sqliteConnection.Close();
                }
                return "Mitigation import successful";
            }
            catch (Exception exception)
            {
                log.Error("Unable to import mitigation statements into database.");
                log.Debug("Exception details: " + exception);
                return "Mitigation addition failed; see log for details";
            }
        }

        /// <summary>
        /// Adds a mitigation item to the "Mitigations" table
        /// </summary>
        /// <param name="vulnerabilityIdNumbers">Vulnerability ID number(s) that the mitigation applies to</param>
        /// <param name="vulnerabilityStatus">The status of the vulnerability</param>
        /// <param name="systemGroupName">The name of the group that the vulnerability belongs to</param>
        /// <param name="systemGroupMacLevel">The MAC level of the Group that the system belongs to</param>
        /// <param name="findingText">The mitigation / remediation text</param>
        /// <param name="mainWindowViewModel">MainWindowViewModel class housing all GUI elements to be updated</param>
        /// <returns>string value</returns>
        public string AddMitigation(string vulnerabilityIdNumbers, string vulnerabilityStatus, string systemGroupName, string findingText, MainWindowViewModel mainWindowViewModel)
        {
            try
            {
                log.Info("Adding mitigation statements to database.");
                using (SQLiteConnection SQLiteConnection = new SQLiteConnection(vulneratorDatabaseConnection))
                {
                    SQLiteConnection.Open();
                    using (SQLiteCommand sqliteCommand = new SQLiteCommand(
                        "", SQLiteConnection))
                    {
                        sqliteCommand.Parameters.Add(new SQLiteParameter("GroupName", systemGroupName));

                        string lookupAndInsertGroupResult = LookupAndInsertGroupInDatabase(SQLiteConnection, systemGroupName);
                        if (!lookupAndInsertGroupResult.Contains("Success"))
                        { return lookupAndInsertGroupResult; }

                        guiActions.InsertGroupInObservableCollections(systemGroupName, mainWindowViewModel);

                        if (vulnerabilityIdNumbers.Contains("\r\n"))
                        {
                            string[] stringSeparators = new string[] { "\r\n" };
                            List<string> separatedVulnerabilityIdList = vulnerabilityIdNumbers.Split(stringSeparators, StringSplitOptions.None).ToList<string>();
                            foreach (string vulnerabilityId in separatedVulnerabilityIdList)
                            {
                                string mitigationLookupAndInsertResult = LookupAndInsertMitigationInDatabase(SQLiteConnection, vulnerabilityId, systemGroupName, vulnerabilityStatus, findingText);
                                if (!mitigationLookupAndInsertResult.Contains("Success"))
                                { return mitigationLookupAndInsertResult; }
                                if (!string.IsNullOrWhiteSpace(vulnerabilityId))
                                { mainWindowViewModel.MitigationList.Add(new MitigationItem(vulnerabilityId, systemGroupName, vulnerabilityStatus, findingText, false)); }
                            }
                        }
                        else
                        {
                            string mitigationLookupAndInsertResult = LookupAndInsertMitigationInDatabase(SQLiteConnection, vulnerabilityIdNumbers, systemGroupName, vulnerabilityStatus, findingText);
                            if (!mitigationLookupAndInsertResult.Contains("Success"))
                            { return mitigationLookupAndInsertResult; }

                            if (!string.IsNullOrWhiteSpace(vulnerabilityIdNumbers))
                            { mainWindowViewModel.MitigationList.Add(new MitigationItem(vulnerabilityIdNumbers, systemGroupName, vulnerabilityStatus, findingText, false)); }
                        }
                    }

                    SQLiteConnection.Close();
                }

                return "Mitigation addition successful";
            }
            catch (Exception exception)
            {
                log.Error("Unable to add mitigation statements to database.");
                log.Debug("Exception details: " + exception);
                return "Mitigation addition failed; see log for details";
            }
        }

        /// <summary>
        /// Updates mitigation within the "Mitigation" table
        /// </summary>
        /// <param name="vulnerabilityIdNumber">ID Number of the vulnerability to be updated</param>
        /// <param name="updatedVulnerabilityStatus">Updated vulnerability status</param>
        /// <param name="currentSystemGroupName">Group name of the vulnerability prior to its update</param>
        /// <param name="updatedSystemGroupName">Group name of the vulnerability after its update</param>
        /// <param name="updatedSystemGroupMacLevel">MAC level of the vulnerability after its update</param>
        /// <param name="updatedFindingText">Mitigation text of the vulnerability after its update</param>
        /// <param name="mainWindowViewModel">MainWindowViewModel class housing all GUI elements to be updated</param>
        /// <returns>string value</returns>
        public string UpdateMitigation(string vulnerabilityIdNumber, string updatedVulnerabilityStatus, string currentSystemGroupName, string updatedSystemGroupName,
            string updatedFindingText, MainWindowViewModel mainWindowViewModel)
        {
            string[] currentMitigationData = new string[4];

            try
            {
                log.Info("Updating mitigation statements in database.");
                using (SQLiteConnection SQLiteConnection = new SQLiteConnection(vulneratorDatabaseConnection))
                {
                    SQLiteConnection.Open();
                    using (SQLiteCommand sqliteCommand = new SQLiteCommand("", SQLiteConnection))
                    {
                        sqliteCommand.CommandText = "SELECT * FROM Mitigations WHERE VulnerabilityId = @vulnerabilityIdNumber AND GroupName = @currentSystemGroupName";
                        sqliteCommand.Parameters.Add(new SQLiteParameter("vulnerabilityIdNumber", vulnerabilityIdNumber));
                        sqliteCommand.Parameters.Add(new SQLiteParameter("currentSystemGroupName", currentSystemGroupName));

                        using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
                        {
                            while (sqliteDataReader.Read())
                            {
                                currentMitigationData[0] = sqliteDataReader.GetString(0);
                                currentMitigationData[1] = sqliteDataReader.GetString(1);
                                currentMitigationData[2] = sqliteDataReader.GetString(2);
                                currentMitigationData[3] = sqliteDataReader.GetString(3);
                            }
                        }
                        if (!string.IsNullOrWhiteSpace(updatedSystemGroupName))
                        {
                            sqliteCommand.Parameters.Add(new SQLiteParameter("updatedSystemGroupName", updatedSystemGroupName));

                            string lookupAndInsertGroupResult = LookupAndInsertGroupInDatabase(SQLiteConnection, updatedSystemGroupName);
                            if (!lookupAndInsertGroupResult.Contains("Success"))
                            { return lookupAndInsertGroupResult; }
                            guiActions.InsertGroupInObservableCollections(updatedSystemGroupName, mainWindowViewModel);
                        }
                        else
                        { sqliteCommand.Parameters.Add(new SQLiteParameter("updatedSystemGroupName", currentMitigationData[3])); }

                        if (!string.IsNullOrWhiteSpace(updatedVulnerabilityStatus))
                        { sqliteCommand.Parameters.Add(new SQLiteParameter("updatedVulnerabilityStatus", updatedVulnerabilityStatus)); }
                        else
                        { sqliteCommand.Parameters.Add(new SQLiteParameter("updatedVulnerabilityStatus", currentMitigationData[1])); }

                        if (!string.IsNullOrWhiteSpace(updatedFindingText))
                        { sqliteCommand.Parameters.Add(new SQLiteParameter("updatedFindingText", updatedFindingText)); }
                        else
                        { sqliteCommand.Parameters.Add(new SQLiteParameter("updatedFindingText", currentMitigationData[2])); }

                        sqliteCommand.CommandText = "UPDATE Mitigations SET FindingStatus = @updatedVulnerabilityStatus, FindingText = @updatedFindingText, GroupName = @updatedSystemGroupName " +
                            "WHERE VulnerabilityId = @vulnerabilityIdNumber AND GroupName = @currentSystemGroupName";

                        sqliteCommand.ExecuteNonQuery();
                    }
                    SQLiteConnection.Close();
                }

                guiActions.UpdateMitigationObservableCollection(vulnerabilityIdNumber, currentSystemGroupName, updatedFindingText, updatedVulnerabilityStatus, updatedSystemGroupName,
                    mainWindowViewModel);

                return "Mitigation update successful";
            }
            catch (Exception exception)
            {
                log.Error("Unable to update mitigations in database.");
                log.Debug("Exception details: " + exception);
                return "Mitigation updated failed; see log for details";
            }
        }

        /// <summary>
        /// Deletes mitigation(s) from the "Mitigation" table
        /// </summary>
        /// <param name="mitigationList">The MitigationsList AsyncObservableCollection list being updated for the GUI to display</param>
        /// <returns>string value</returns>
        public string DeleteMitigation(AsyncObservableCollection<MitigationItem> mitigationList)
        {
            try
            {
                log.Info("Deleting mitigation statements from database.");
                ArrayList arrayList = new ArrayList();
                using (SQLiteConnection SQLiteConnection = new SQLiteConnection(vulneratorDatabaseConnection))
                {
                    SQLiteConnection.Open();
                    foreach (MitigationItem mitigationItem in mitigationList)
                    {
                        if (mitigationItem.IsChecked)
                        {
                            using (SQLiteCommand sqliteCommand = new SQLiteCommand(
                                "DELETE FROM Mitigations WHERE VulnerabilityId=@VulnerabilityId AND GroupName=@GroupName", SQLiteConnection))
                            {
                                sqliteCommand.Parameters.Add(new SQLiteParameter("VulnerabilityId", mitigationItem.MitigationVulnerabilityId));
                                sqliteCommand.Parameters.Add(new SQLiteParameter("GroupName", mitigationItem.MitigationGroupName));
                                sqliteCommand.ExecuteNonQuery();
                            }
                            arrayList.Add(mitigationItem);
                        }
                    }
                    SQLiteConnection.Close();
                }

                foreach (MitigationItem mitigationItem in arrayList)
                { mitigationList.Remove(mitigationItem); }

                return "Mitigation deletion successful";
            }
            catch (Exception exception)
            {
                log.Error("Unable to delete mitigation statements from database.");
                log.Debug("Exception details: " + exception);
                return "Mitigation deletion failed; see log for details";
            }
        }

        /// <summary>
        /// Adds a contact to the "PointsOfContact" table
        /// </summary>
        /// <param name="ContactName">Name of the contact to be added</param>
        /// <param name="contactTitle">Title of the contact to be added</param>
        /// <param name="ContactEmail">Email of the contact to be added</param>
        /// <param name="contactSystemName">Hostname of the system the added contact will be associated with</param>
        /// <param name="contactSystemIp">IP address of the system the added contact will be associated with</param>
        /// <param name="contactGroupName">System group the system the added contact will be associated with</param>
        /// <param name="contactGroupMacLevel">MAC level of the system group the system the added contact will be associated with</param>
        /// <param name="mainWindowViewModel">MainWindowViewModel class housing all GUI elements to be updated</param>
        /// <returns>string value</returns>
        public string AddContact(string contactName, string contactTitle, string contactEmail, string contactSystemName, string contactSystemIp, string contactGroupName,
            MainWindowViewModel mainWindowViewModel)
        {
            try
            {
                log.Info("Adding contact record to database.");
                vulneratorDatabaseFilePath = ConfigAlter.ReadSettingsFromDictionary("tbMitDbLocation");
                vulneratorDatabaseConnection = @"Data Source = " + vulneratorDatabaseFilePath;

                using (SQLiteConnection sqliteConnection = new SQLiteConnection(vulneratorDatabaseConnection))
                {
                    sqliteConnection.Open();

                    string lookupAndInsertGroupResult = LookupAndInsertGroupInDatabase(sqliteConnection, contactGroupName);
                    if (!lookupAndInsertGroupResult.Contains("Success"))
                    { return lookupAndInsertGroupResult; }
                    guiActions.InsertGroupInObservableCollections(contactGroupName, mainWindowViewModel);

                    if (contactSystemName.Contains(":"))
                    {
                        string[] ipAddressDelimiter = new string[] { " : " };
                        if (string.IsNullOrWhiteSpace(contactSystemIp))
                        { contactSystemIp = contactSystemName.Split(ipAddressDelimiter, StringSplitOptions.None)[1].Trim(); }
                        contactSystemName = contactSystemName.Split(ipAddressDelimiter, StringSplitOptions.None)[0].Trim();
                    }

                    List<SQLiteParameter> filterPreferences = ObtainContactFilteringPreferences(sqliteConnection, contactTitle);
                    if (filterPreferences == null)
                    { return "A database error has occurred; see the log for further details"; }

                    string systemLookupAndInsertionResult = LookupAndInsertSystemInDatabase(sqliteConnection, contactSystemName, contactSystemIp, contactGroupName, mainWindowViewModel);
                    if (!systemLookupAndInsertionResult.Equals("Success"))
                    { return systemLookupAndInsertionResult; }

                    guiActions.InsertSystemInObservableCollections(contactSystemName, contactSystemIp, contactGroupName, mainWindowViewModel);

                    string contactLookupAndInsertionResult = LookupAndInsertContactInDatabase(sqliteConnection, contactName, contactTitle, contactEmail, contactGroupName,
                        contactSystemName, contactSystemIp, filterPreferences);
                    if (!contactLookupAndInsertionResult.Equals("Success"))
                    { return contactLookupAndInsertionResult; }

                    guiActions.InsertContactInObservableCollection(contactName, contactTitle, contactEmail, contactGroupName, contactSystemName, contactSystemIp, mainWindowViewModel);
                    guiActions.InsertTitleInObservableCollection(contactTitle, mainWindowViewModel);
                    
                    sqliteConnection.Close();
                }

                return "Contact addition successful";
            }
            catch (Exception exception)
            {
                log.Error("Unable to add contact to database.");
                log.Debug("Exception details: " + exception);
                return "Contact addition failed; see log for details";
            }
        }

        /// <summary>
        /// Updates a contact in the "PointsOfContact" table
        /// </summary>
        /// <param name="selectedContactToUpdate">Contact class whose information is to be updated</param>
        /// <param name="updateContactParameters">Class containing the updated information for the Contact</param>
        /// <param name="mainWindowViewModel">MainWindowViewModel class housing all GUI elements to be updated</param>
        /// <returns>string value</returns>
        public string UpdateContact(Contact selectedContactToUpdate, UpdateContactParameters updateContactParameters, MainWindowViewModel mainWindowViewModel)
        {
            try
            {
                log.Info("Updating contact record in database.");
                using (SQLiteConnection sqliteConnection = new SQLiteConnection(vulneratorDatabaseConnection))
                {
                    sqliteConnection.Open();

                    using (SQLiteCommand SQLiteCommand = new SQLiteCommand(
                        "", sqliteConnection))
                    {
                        SQLiteCommand.Parameters.Add(new SQLiteParameter("currentContactName", selectedContactToUpdate.ContactName));
                        SQLiteCommand.Parameters.Add(new SQLiteParameter("currentContactGroupName", selectedContactToUpdate.ContactGroupName));
                        SQLiteCommand.Parameters.Add(new SQLiteParameter("currentContactSystemName", selectedContactToUpdate.ContactSystemName));
                        SQLiteCommand.Parameters.Add(new SQLiteParameter("updatedContactName", updateContactParameters.NewName));
                        SQLiteCommand.Parameters.Add(new SQLiteParameter("updatedContactTitle", updateContactParameters.NewTitle));
                        SQLiteCommand.Parameters.Add(new SQLiteParameter("updatedContactEmail", updateContactParameters.NewEmail));
                        SQLiteCommand.Parameters.Add(new SQLiteParameter("updatedContactGroupName", updateContactParameters.NewGroupName));
                        SQLiteCommand.Parameters.Add(new SQLiteParameter("updatedContactSystemIp", updateContactParameters.NewSystemIp));
                        SQLiteCommand.Parameters.Add(new SQLiteParameter("updatedContactSystemName", updateContactParameters.NewSystemName));

                        if (!selectedContactToUpdate.ContactGroupName.Equals(updateContactParameters.NewGroupName))
                        {
                            string lookupAndInsertGroupResult = LookupAndInsertGroupInDatabase(sqliteConnection, updateContactParameters.NewGroupName);
                            if (!lookupAndInsertGroupResult.Contains("Success"))
                            { return lookupAndInsertGroupResult; }
                            guiActions.InsertGroupInObservableCollections(updateContactParameters.NewGroupName, mainWindowViewModel);
                        }

                        string ipToHostNameVerification = VerifyIpToSingleHostName(sqliteConnection, updateContactParameters.NewSystemName, updateContactParameters.NewSystemIp, updateContactParameters.NewGroupName);
                        if (!ipToHostNameVerification.Equals("No collisions"))
                        { return ipToHostNameVerification; }

                        if (!selectedContactToUpdate.ContactSystemName.Equals(updateContactParameters.NewSystemName))
                        {
                            string systemLookupResult = LookupAndInsertSystemInDatabase(sqliteConnection, updateContactParameters.NewSystemName,
                                updateContactParameters.NewSystemIp, updateContactParameters.NewGroupName, mainWindowViewModel);
                            if (!systemLookupResult.Equals("Success"))
                            { return systemLookupResult; }
                            guiActions.InsertSystemInObservableCollections(updateContactParameters.NewSystemName, updateContactParameters.NewSystemIp, updateContactParameters.NewGroupName, mainWindowViewModel);
                        }

                        SQLiteCommand.CommandText = "UPDATE PointsOfContact SET Name = @updatedContactName, Title = @updatedContactTitle, Email = @updatedContactEmail, " +
                            "SystemHostName = @updatedContactSystemName, GroupName = @updatedContactGroupName WHERE Name = @currentContactName AND GroupName = @currentContactGroupName " +
                            "AND SystemHostName = @currentContactSystemName";
                        SQLiteCommand.ExecuteNonQuery();
                        var existingContact = mainWindowViewModel.ContactList.FirstOrDefault(x =>
                            x.ContactName.Equals(selectedContactToUpdate.ContactName) &&
                            x.ContactSystemName.Equals(selectedContactToUpdate.ContactSystemName) &&
                            x.ContactGroupName.Equals(selectedContactToUpdate.ContactGroupName));
                        if (existingContact != null)
                        {
                            if (!existingContact.ContactName.Equals(updateContactParameters.NewName))
                            { existingContact.ContactName = updateContactParameters.NewName; }

                            if (!existingContact.ContactTitle.Equals(updateContactParameters.NewTitle))
                            { existingContact.ContactTitle = updateContactParameters.NewTitle; }

                            if (!existingContact.ContactEmail.Equals(updateContactParameters.NewEmail))
                            { existingContact.ContactEmail = updateContactParameters.NewEmail; }

                            if (!existingContact.ContactGroupName.Equals(updateContactParameters.NewGroupName))
                            { existingContact.ContactGroupName = updateContactParameters.NewGroupName; }

                            if (!existingContact.ContactSystemIp.Equals(updateContactParameters.NewSystemIp))
                            { existingContact.ContactSystemIp = updateContactParameters.NewSystemIp; }

                            if (!existingContact.ContactSystemName.Equals(updateContactParameters.NewSystemName))
                            { existingContact.ContactSystemName = updateContactParameters.NewSystemName; }
                        }
                    }
                    sqliteConnection.Close();
                }

                return "Contact update successful";
            }
            catch (Exception exception)
            {
                log.Error("Unable to update contact record in database.");
                log.Debug("Exception details: " + exception);
                return "Contact update failed; see log for details";
            }
        }

        /// <summary>
        /// Deletes contact(s) from the PointsOfContact table
        /// </summary>
        /// <param name="contactList">The Contact AsyncObservableCollection list being updated for the GUI to display</param>
        /// <returns>string value</returns>
        public string DeleteContact(AsyncObservableCollection<Contact> contactList)
        {
            try
            {
                log.Info("Deleting contact records from database.");
                ArrayList arrayList = new ArrayList();
                using (SQLiteConnection sqliteConnection = new SQLiteConnection(vulneratorDatabaseConnection))
                {
                    sqliteConnection.Open();

                    using (SQLiteCommand sqliteCommand = new SQLiteCommand(
                        "DELETE FROM PointsOfContact WHERE Name = @Name AND Title = @Title AND GroupName = @GroupName AND SystemHostName = @SystemName " +
                        "AND SystemIpAddress = @SystemIp", sqliteConnection))
                    {
                        foreach (Contact contact in contactList)
                        {
                            if (contact.IsChecked)
                            {
                                arrayList.Add(contact);
                                sqliteCommand.Parameters.Add(new SQLiteParameter("Name", contact.ContactName));
                                sqliteCommand.Parameters.Add(new SQLiteParameter("GroupName", contact.ContactGroupName));
                                sqliteCommand.Parameters.Add(new SQLiteParameter("Title", contact.ContactTitle));
                                sqliteCommand.Parameters.Add(new SQLiteParameter("SystemName", contact.ContactSystemName));
                                sqliteCommand.Parameters.Add(new SQLiteParameter("SystemIp", contact.ContactSystemIp));
                                sqliteCommand.ExecuteNonQuery();
                                sqliteCommand.Parameters.Clear();
                            }
                        }
                    }

                    sqliteConnection.Close();
                }

                foreach (Contact contact in arrayList)
                { contactList.Remove(contact); }
                arrayList.Clear();

                return "Contact deletion successful";
            }
            catch (Exception exception)
            {
                log.Error("Unable to delete contact records from database.");
                log.Debug("Exception details: " + exception);
                return "Contact deletion failed; see log for details";
            }
        }

        /// <summary>
        /// Updates existing groups across the entire database utilized by Vulnerator
        /// </summary>
        /// <param name="currentGroup">Name / MAC Level of the group to be updated</param>
        /// <param name="updatedGroupName">Updated name for the group being modified</param>
        /// <param name="updateGroupMacLevel">Updated Mac Level for the group being modified</param>
        /// <param name="mainWindowViewModel">MainWindowViewModel class housing all GUI elements to be updated</param>
        /// <returns>string value</returns>
        public string UpdateGroup(string currentGroup, string updatedGroupName, MainWindowViewModel mainWindowViewModel)
        {
            try
            {
                log.Info("Updating group in database.");
                vulneratorDatabaseFilePath = ConfigAlter.ReadSettingsFromDictionary("tbMitDbLocation");
                vulneratorDatabaseConnection = @"Data Source = " + vulneratorDatabaseFilePath;

                using (SQLiteConnection sqliteConnection = new SQLiteConnection(vulneratorDatabaseConnection))
                {
                    sqliteConnection.Open();

                    using (SQLiteCommand sqliteCommand = new SQLiteCommand(
                        "", sqliteConnection))
                    {
                        string currentGroupMacLevel = currentGroup.Split(':')[1].Trim();
                        currentGroup = currentGroup.Split(':')[0].Trim();
                        sqliteCommand.Parameters.Add(new SQLiteParameter("CurrentGroupName", currentGroup));
                        sqliteCommand.Parameters.Add(new SQLiteParameter("UpdatedGroupName", updatedGroupName));

                        if (!currentGroup.Equals(updatedGroupName))
                        {
                            if (!string.IsNullOrWhiteSpace(updatedGroupName))
                            {
                                string lookupGroupResult = LookupAndInsertGroupInDatabase(sqliteConnection, updatedGroupName);
                                if (!lookupGroupResult.Equals("Success"))
                                { return lookupGroupResult; }

                                sqliteCommand.CommandText = "UPDATE Systems SET GroupName = @UpdatedGroupName WHERE GroupName = @CurrentGroupName";
                                sqliteCommand.ExecuteNonQuery();
                                sqliteCommand.CommandText = "UPDATE PointsOfContact SET GroupName = @UpdatedGroupName WHERE GroupName = @CurrentGroupName";
                                sqliteCommand.ExecuteNonQuery();
                                sqliteCommand.CommandText = "UPDATE Mitigations SET GroupName = @UpdatedGroupName WHERE GroupName = @CurrentGroupName";
                                sqliteCommand.ExecuteNonQuery();
                                sqliteCommand.CommandText = "DELETE FROM SystemGroups WHERE GroupName = @CurrentGroupName";
                                sqliteCommand.ExecuteNonQuery();
                            }
                            else
                            { return "Please enter a new name for the selected group"; }
                        }
                    }

                    sqliteConnection.Close();
                }

                guiActions.UpdateGroupObservableCollections(currentGroup, updatedGroupName, mainWindowViewModel);
                guiActions.UpdateGroupInSystemObservableCollection(currentGroup, updatedGroupName, mainWindowViewModel);

                foreach (MitigationItem mitigationItem in mainWindowViewModel.MitigationList)
                {
                    if (mitigationItem.MitigationGroupName.Equals(currentGroup))
                    { mitigationItem.MitigationGroupName = updatedGroupName; }
                }

                foreach (Contact contact in mainWindowViewModel.ContactList)
                {
                    if (contact.ContactGroupName.Equals(currentGroup))
                    {
                        contact.ContactGroupName = updatedGroupName;
                    }
                }

                return "Group update successful";
            }
            catch (Exception exception)
            {
                log.Error("Unable to update group in database.");
                log.Debug("Exception details: " + exception);
                return "Group update failed; see log for details";
            }
        }

        /// <summary>
        /// Deletes a group from the database in which Vulnerator stores mitigation, system, project, and email preference information
        /// </summary>
        /// <param name="groupToDelete">Name of the SystemGroup to be deleted</param>
        /// <param name="mainWindowViewModel">MainWindowViewModel class housing all GUI elements to be updated</param>
        /// <returns>string value</returns>
        public string DeleteGroup(string groupToDelete, MainWindowViewModel mainWindowViewModel)
        {
            try
            {
                log.Info("Deleting group from database.");
                string[] delimiterArray = new string[] { ": MAC" };

                using (SQLiteConnection sqliteConnection = new SQLiteConnection(vulneratorDatabaseConnection))
                {
                    sqliteConnection.Open();

                    using (SQLiteCommand sqliteCommand = new SQLiteCommand(
                        "", sqliteConnection))
                    {
                        sqliteCommand.Parameters.Add(new SQLiteParameter("GroupName", groupToDelete.Split(delimiterArray, StringSplitOptions.None)[0].Trim()));
                        sqliteCommand.CommandText = "SELECT COUNT(1) FROM PointsOfContact WHERE GroupName = @GroupName";
                        if ((long)sqliteCommand.ExecuteScalar() != 0)
                        { return "Unable to delete group; please ensure no contacts are associated with \"" + groupToDelete.Split(delimiterArray, StringSplitOptions.None)[0].Trim() + "\""; }

                        sqliteCommand.CommandText = "SELECT COUNT(1) FROM Systems WHERE GroupName = @GroupName";
                        if ((long)sqliteCommand.ExecuteScalar() != 0)
                        { return "Unable to delete group; please ensure no systems are associated with \"" + groupToDelete.Split(delimiterArray, StringSplitOptions.None)[0].Trim() + "\""; }

                        sqliteCommand.CommandText = "SELECT COUNT(1) FROM Mitigations WHERE GroupName = @GroupName";
                        if ((long)sqliteCommand.ExecuteScalar() != 0)
                        { return "Unable to delete group; please ensure no mitigations are associated with \"" + groupToDelete.Split(delimiterArray, StringSplitOptions.None)[0].Trim() + "\""; }

                        sqliteCommand.CommandText = "DELETE FROM SystemGroups WHERE GroupName = @GroupName";
                        sqliteCommand.ExecuteNonQuery();
                    }

                    sqliteConnection.Close();
                }

                var existingSystemGroup = mainWindowViewModel.SystemGroupList.FirstOrDefault(x => x.GroupName.Contains(groupToDelete));
                if (existingSystemGroup != null)
                {
                    mainWindowViewModel.SystemGroupList.Remove(existingSystemGroup);
                }

                var existingUpdatableSystemGroup = mainWindowViewModel.SystemGroupListForUpdating.FirstOrDefault(x => x.GroupName.Contains(groupToDelete));
                if (existingUpdatableSystemGroup != null)
                {
                    mainWindowViewModel.SystemGroupListForUpdating.Remove(existingUpdatableSystemGroup);
                }

                return "Group deletion successful";
            }
            catch (Exception exception)
            {
                log.Error("Unable to delete group from database.");
                log.Debug("Exception details: " + exception);
                return "Group deletion failed; see log for details";
            }
        }

        /// <summary>
        /// Updates existing systems across the entire database utilized by Vulnerator
        /// </summary>
        /// <param name="currentSystem">Host name / IP address of the system to be updated</param>
        /// <param name="updateSystemParameters">UpdateSystemParameters class containing the new group, name, and IP address of the system to be updated</param>
        /// <param name="mainWindowViewModel">MainWindowViewModel class housing all GUI elements to be updated</param>
        /// <returns>string value</returns>
        public string UpdateSystem(string currentSystem, UpdateSystemParameters updateSystemParameters, MainWindowViewModel mainWindowViewModel)
        {
            try
            {
                log.Info("Updating system record in database.");
                vulneratorDatabaseFilePath = ConfigAlter.ReadSettingsFromDictionary("tbMitDbLocation");
                vulneratorDatabaseConnection = @"Data Source = " + vulneratorDatabaseFilePath;
                string trimmedCurrentSystemGroup = currentSystem.Split(':')[0].Trim();
                string trimmedCurrentSystemName = currentSystem.Split(':')[1].Trim();
                string trimmedCurrentSystemIp = currentSystem.Split(':')[2].Trim();
                using (SQLiteConnection sqliteConnection = new SQLiteConnection(vulneratorDatabaseConnection))
                {
                    sqliteConnection.Open();

                    using (SQLiteCommand sqliteCommand = new SQLiteCommand(
                        "", sqliteConnection))
                    {
                        sqliteCommand.Parameters.Add(new SQLiteParameter("CurrentSystemGroup", trimmedCurrentSystemGroup));
                        sqliteCommand.Parameters.Add(new SQLiteParameter("CurrentSystemName", trimmedCurrentSystemName));
                        sqliteCommand.Parameters.Add(new SQLiteParameter("CurrentSystemIp", trimmedCurrentSystemIp));
                        sqliteCommand.Parameters.Add(new SQLiteParameter("UpdatedSystemGroup", updateSystemParameters.UpdatedSystemGroup.Trim()));
                        sqliteCommand.Parameters.Add(new SQLiteParameter("UpdatedSystemName", updateSystemParameters.UpdatedSystemName.Trim()));
                        sqliteCommand.Parameters.Add(new SQLiteParameter("UpdatedSystemIp", updateSystemParameters.UpdatedSystemIP.Trim()));

                        sqliteCommand.CommandText = "SELECT COUNT(1) FROM Systems WHERE SystemHostName = @UpdatedSystemName AND SystemIpAddress = @UpdatedSystemIp AND GroupName = @UpdatedSystemGroup";
                        if ((long)sqliteCommand.ExecuteScalar() != 0)
                        {
                            return "\"" + updateSystemParameters.UpdatedSystemName.Trim() + "\" already exists with the IP address \"" + updateSystemParameters.UpdatedSystemIP.Trim() + "\" in \"" + updateSystemParameters.UpdatedSystemGroup.Trim() +
                                "\"; please provide a different system group, name, or IP";
                        }

                        sqliteCommand.CommandText = "SELECT COUNT(1) FROM Systems WHERE SystemIpAddress = @UpdatedSystemIp and GroupName = @UpdatedSystemGroup";
                        if ((long)sqliteCommand.ExecuteScalar() != 0)
                        {
                            return "A system with the IP address \"" + updateSystemParameters.UpdatedSystemIP.Trim() + "\" already exists in \"" + updateSystemParameters.UpdatedSystemGroup.Trim() + "\"; please provide a different IP address or select a new group";
                        }

                        sqliteCommand.CommandText = "UPDATE Systems SET SystemHostName = @UpdatedSystemName, SystemIpAddress = @UpdatedSystemIp, GroupName = @UpdatedSystemGroup WHERE " +
                            "SystemHostName = @CurrentSystemName AND SystemIpAddress = @CurrentSystemIp AND GroupName = @CurrentSystemGroup";
                        sqliteCommand.ExecuteNonQuery();
                        sqliteCommand.CommandText = "UPDATE PointsOfContact SET SystemHostName = @UpdatedSystemName, SystemIpAddress = @UpdatedSystemIp, GroupName = @UpdatedSystemGroup WHERE " +
                            "SystemHostName = @CurrentSystemName AND SystemIpAddress = @CurrentSystemIp AND GroupName = @CurrentSystemGroup";
                        sqliteCommand.ExecuteNonQuery();
                    }

                    sqliteConnection.Close();
                }

                var existingSystem = mainWindowViewModel.MonitoredSystemList.FirstOrDefault(x => x.SystemNameAndIp.Contains(trimmedCurrentSystemName) && x.SystemNameAndIp.Contains(trimmedCurrentSystemIp));
                if (existingSystem != null)
                {
                    existingSystem.SystemNameAndIp = updateSystemParameters.UpdatedSystemName.Trim() + " : " + updateSystemParameters.UpdatedSystemIP.Trim();
                }

                var existingUpdateSystem = mainWindowViewModel.MonitoredSystemListForUpdating.FirstOrDefault(x => x.SystemGroupAndNameAndIp.Equals(currentSystem));
                if (existingUpdateSystem != null)
                {
                    existingUpdateSystem.SystemGroupAndNameAndIp = updateSystemParameters.UpdatedSystemGroup.Trim() + " : " + updateSystemParameters.UpdatedSystemName.Trim() + " : " + updateSystemParameters.UpdatedSystemIP.Trim();
                }

                foreach (Contact contact in mainWindowViewModel.ContactList)
                {
                    if (contact.ContactSystemName.Equals(trimmedCurrentSystemName) && contact.ContactSystemIp.Equals(trimmedCurrentSystemIp) && contact.ContactGroupName.Equals(trimmedCurrentSystemGroup))
                    {
                        contact.ContactGroupName = updateSystemParameters.UpdatedSystemGroup;
                        contact.ContactSystemName = updateSystemParameters.UpdatedSystemName;
                        contact.ContactSystemIp = updateSystemParameters.UpdatedSystemIP;
                    }
                }

                return "System update successful";
            }
            catch (Exception exception)
            {
                log.Info("Unable to updated system record in database.");
                log.Debug("Exception details: " + exception);
                return "System update failed; see log for details";
            }
        }

        public string DeleteSystem(string systemToDelete, MainWindowViewModel mainWindowViewModel)
        {
            try
            {
                log.Info("Deleting system record from database.");
                vulneratorDatabaseFilePath = ConfigAlter.ReadSettingsFromDictionary("tbMitDbLocation");
                vulneratorDatabaseConnection = @"Data Source = " + vulneratorDatabaseFilePath;
                string systemName = systemToDelete.Split(':')[1].Trim();
                string systemIp = systemToDelete.Split(':')[2].Trim();
                string systemGroup = systemToDelete.Split(':')[0].Trim();

                using (SQLiteConnection sqliteConnection = new SQLiteConnection(vulneratorDatabaseConnection))
                {
                    sqliteConnection.Open();

                    using (SQLiteCommand sqliteCommand = new SQLiteCommand("", sqliteConnection))
                    {
                        sqliteCommand.Parameters.Add(new SQLiteParameter("SystemGroup", systemGroup));
                        sqliteCommand.Parameters.Add(new SQLiteParameter("SystemName", systemName));
                        sqliteCommand.Parameters.Add(new SQLiteParameter("SystemIp", systemIp));

                        sqliteCommand.CommandText = "SELECT COUNT(1) FROM PointsOfContact WHERE SystemHostName = @SystemName AND SystemIpAddress = @SystemIp AND GroupName = @SystemGroup";
                        if ((long)sqliteCommand.ExecuteScalar() != 0)
                        {
                            return "One or more contact(s) associated with \"" + systemName + "\" (IP address \"" + systemIp + "\") in \"" + systemGroup +
                                "\"; please remove all associations to the system and try again.";
                        }

                        sqliteCommand.CommandText = "DELETE FROM Systems WHERE SystemHostName = @SystemName AND SystemIpAddress = @SystemIp AND GroupName = @SystemGroup";
                        sqliteCommand.ExecuteNonQuery();

                        var comboBoxListedSystem = mainWindowViewModel.MonitoredSystemListForUpdating.FirstOrDefault(x => x.SystemGroupAndNameAndIp.Contains(systemGroup + " : " + systemName + " : " + systemIp));
                        if (comboBoxListedSystem != null)
                        {
                            mainWindowViewModel.MonitoredSystemListForUpdating.Remove(comboBoxListedSystem);
                        }

                        var existingSystem = mainWindowViewModel.MonitoredSystemList.FirstOrDefault(x => x.SystemNameAndIp.Contains(systemName + " : " + systemIp));
                        if (existingSystem != null)
                        {
                            mainWindowViewModel.MonitoredSystemList.Remove(existingSystem);
                        }
                    }

                    sqliteConnection.Close();
                }

                return "System deletion successful";
            }
            catch (Exception exception)
            {
                log.Error("Unable to delete system record from database.");
                log.Debug("Exception details: " + exception);
                return "System delection failed; see log for details";
            }
        }

        private string LookupAndInsertGroupInDatabase(SQLiteConnection sqliteConnection, string groupName)
        {
            try
            {
                log.Info("Verifying group exists in database.");
                using (SQLiteCommand sqliteCommand = new SQLiteCommand(
                    "SELECT COUNT(1) FROM SystemGroups WHERE GroupName = @GroupName", sqliteConnection))
                {
                    sqliteCommand.Parameters.Add(new SQLiteParameter("GroupName", groupName));
                    if ((long)sqliteCommand.ExecuteScalar() == 0)
                    {
                        log.Info("Group does not exist; adding group to database.");
                        sqliteCommand.CommandText = "INSERT INTO SystemGroups VALUES (@GroupName, NULL)";
                        sqliteCommand.ExecuteNonQuery();
                        return "Success";
                    }
                    else
                    { return "Success"; }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to verify group existence / add group to database.");
                log.Debug("Exception details: " + exception);
                return "A database error has occurred; see the log for further details";
            }
        }

        private string LookupAndInsertSystemInDatabase(SQLiteConnection sqliteConnection, string systemName, string systemIp, string groupName, MainWindowViewModel mainWindowViewModel)
        {
            try
            {
                log.Info("Verifying system exists in database.");
                using (SQLiteCommand sqliteCommand = new SQLiteCommand("", sqliteConnection))
                {
                    systemIp = systemIp.Trim();
                    groupName = groupName.Trim();
                    systemName = systemName.Trim();
                    sqliteCommand.Parameters.Add(new SQLiteParameter("SystemIpAddress", systemIp));
                    sqliteCommand.Parameters.Add(new SQLiteParameter("GroupName", groupName));
                    sqliteCommand.Parameters.Add(new SQLiteParameter("SystemName", systemName));
                    sqliteCommand.CommandText = "SELECT SystemHostName FROM Systems WHERE SystemIpAddress = @SystemIpAddress AND GroupName = @GroupName";
                    using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
                    {
                        while (sqliteDataReader.Read())
                        {
                            if (!sqliteDataReader.GetString(0).Equals(systemName))
                            { return "\"" + groupName + "\" already contains a system with the IP address \"" + systemIp + "\""; }
                        }
                    }

                    sqliteCommand.CommandText = "SELECT COUNT(1) FROM Systems WHERE SystemHostName = @SystemName AND SystemIpAddress = @SystemIpAddress AND " +
                        "GroupName = @GroupName";
                    if ((long)sqliteCommand.ExecuteScalar() == 0)
                    {
                        if (!string.IsNullOrWhiteSpace(systemIp))
                        {
                            log.Info("System does not exist; adding group to database.");
                            sqliteCommand.CommandText = "INSERT INTO Systems VALUES (@SystemName, @SystemIpAddress, @GroupName)";
                            sqliteCommand.ExecuteNonQuery();
                        }
                        else
                        { return "\"" + systemName + "\" could not be found in \"" + groupName + "\"; please enter an IP address"; }
                    }
                }
                return "Success";
            }
            catch (Exception exception)
            {
                log.Error("Unable to verify system existence / add system to database.");
                log.Debug("Exception details: " + exception);
                return "A database error has occurred; see the log for further details";
            }
        }

        private string LookupAndInsertMitigationInDatabase(SQLiteConnection sqliteConnection, string vulnerabilityId, string groupName, string status, string findingText)
        {
            try
            {
                log.Info("Verifying mitigation exists in database.");
                using (SQLiteCommand sqliteCommand = new SQLiteCommand("", sqliteConnection))
                {
                    sqliteCommand.CommandText = "SELECT COUNT(1) FROM Mitigations WHERE VulnerabilityId = @vulnerabilityId AND GroupName = @GroupName";
                    sqliteCommand.Parameters.Add(new SQLiteParameter("vulnerabilityId", vulnerabilityId));
                    sqliteCommand.Parameters.Add(new SQLiteParameter("GroupName", groupName));

                    if ((long)sqliteCommand.ExecuteScalar() != 0)
                    { return "\"" + groupName + "\" already contains a mitigation for Vulnerability ID " + "\"" + vulnerabilityId + "\""; }
                    else
                    {
                        log.Info("Mitigation does not exist; adding group to database.");
                        sqliteCommand.CommandText = "INSERT INTO Mitigations VALUES (@VulnerabilityId, @FindingStatus, @FindingText, @GroupName)";
                        sqliteCommand.Parameters.Add(new SQLiteParameter("FindingStatus", status));
                        sqliteCommand.Parameters.Add(new SQLiteParameter("FindingText", findingText));
                        sqliteCommand.ExecuteNonQuery();
                        return "Success";
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to verify mitigation existence / add mitigation to database.");
                log.Debug("Exception details: " + exception);
                return "A database error has occurred; see the log for further details";
            }
        }

        private string LookupAndInsertContactInDatabase(SQLiteConnection sqliteConnection, string contactName, string title, string email, string groupName,
            string systemName, string systemIp, List<SQLiteParameter> filterPreferences)
        {
            try
            {
                log.Info("Verifying contact exists in database.");
                using (SQLiteCommand sqliteCommand = new SQLiteCommand("", sqliteConnection))
                {
                    sqliteCommand.Parameters.Add(new SQLiteParameter("ContactName", contactName));
                    sqliteCommand.Parameters.Add(new SQLiteParameter("ContactTitle", title));
                    sqliteCommand.Parameters.Add(new SQLiteParameter("SystemName", systemName));
                    sqliteCommand.Parameters.Add(new SQLiteParameter("SystemIpAddress", systemIp));
                    sqliteCommand.Parameters.Add(new SQLiteParameter("GroupName", groupName));
                    sqliteCommand.Parameters.Add(new SQLiteParameter("ContactEmail", email));
                    sqliteCommand.CommandText = "SELECT COUNT(1) FROM PointsOfContact WHERE Name = @ContactName AND Title = @ContactTitle AND SystemHostName = @SystemName " +
                            "AND SystemIpAddress = @SystemIpAddress AND GroupName = @GroupName";
                    if ((long)sqliteCommand.ExecuteScalar() == 0)
                    {
                        log.Info("Contact does not exist; adding group to database.");
                        sqliteCommand.Parameters.Add(filterPreferences[0]);
                        sqliteCommand.Parameters.Add(filterPreferences[1]);
                        sqliteCommand.Parameters.Add(filterPreferences[2]);
                        sqliteCommand.Parameters.Add(filterPreferences[3]);
                        sqliteCommand.CommandText = "INSERT INTO PointsOfContact VALUES(@ContactName, @ContactTitle, @ContactEmail, @FilterOne, @FilterTwo, @FilterThree, " +
                            "@FilterFour, @SystemName, @SystemIpAddress, @GroupName)";
                        sqliteCommand.ExecuteNonQuery();
                    }
                    else
                    { return "\"" + contactName + "\" already exists for \"" + systemName + "\" in \"" + groupName + "\""; }
                }
                return "Success";
            }
            catch (Exception exception)
            {
                log.Error("Unable to verify contact existence / add contact to database.");
                log.Debug("Exception details: " + exception);
                return "A database error has occurred; see the log for further details";
            }
        }

        private string VerifyIpToSingleHostName(SQLiteConnection sqliteConnection, string hostName, string ipAddress, string groupName)
        {
            try
            {
                log.Info("Verifying no IP/host name collisions exist for " + ipAddress + " & " + hostName + " in " + groupName + ".");
                using (sqliteConnection)
                {
                    using (SQLiteCommand sqliteCommand = new SQLiteCommand("SELECT SystemHostName FROM Systems WHERE SystemIpAddress = @IpAddress AND GroupName = @GroupName",
                        sqliteConnection))
                    {
                        sqliteCommand.Parameters.Add(new SQLiteParameter("IpAddress", ipAddress));
                        sqliteCommand.Parameters.Add(new SQLiteParameter("GroupName", groupName));
                        using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
                        {
                            while (sqliteDataReader.Read())
                            {
                                if (!sqliteDataReader[0].Equals(hostName))
                                { return "A system with the IP address \"" + ipAddress + "\" already exists in \"" + groupName + "\", please provide a new host name"; }
                            }
                        }
                        return "No collisions";
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to verify that no collisions exist.");
                log.Debug("Exception details: " + exception);
                return "A database error has occurred; see the log for further details";
            }
        }

        private List<SQLiteParameter> ObtainContactFilteringPreferences(SQLiteConnection sqliteConnection, string contactTitle)
        {
            try
            {
                log.Info("Obtaining user contact filtering preferences.");
                List<SQLiteParameter> sqliteParameterList = new List<SQLiteParameter>();
                using (SQLiteCommand sqliteCommand = new SQLiteCommand("", sqliteConnection))
                {
                    sqliteCommand.CommandText = "SELECT COUNT(1) FROM PointsOfContact WHERE Title = @ContactTitle";
                    sqliteCommand.Parameters.Add(new SQLiteParameter("ContactTitle", contactTitle));
                    if ((long)sqliteCommand.ExecuteScalar() != 0)
                    {
                        sqliteCommand.CommandText = "SELECT TOP(1) FilterOneInclusion, FilterTwoInclusion, FilterThreeInclusion, FilterFourInclusion FROM " +
                            "PointsOfContact WHERE Title = @ContactTitle";
                        using (SQLiteDataReader sqliteDataReader = sqliteCommand.ExecuteReader())
                        {
                            while (sqliteDataReader.Read())
                            {
                                sqliteParameterList.Add(new SQLiteParameter("FilterOne", sqliteDataReader.GetString(0)));
                                sqliteParameterList.Add(new SQLiteParameter("FilterTwo", sqliteDataReader.GetString(1)));
                                sqliteParameterList.Add(new SQLiteParameter("FilterThree", sqliteDataReader.GetString(2)));
                                sqliteParameterList.Add(new SQLiteParameter("FilterFour", sqliteDataReader.GetString(3)));
                            }
                        }
                    }
                    else
                    {
                        sqliteParameterList.Add(new SQLiteParameter("FilterOne", "False"));
                        sqliteParameterList.Add(new SQLiteParameter("FilterTwo", "False"));
                        sqliteParameterList.Add(new SQLiteParameter("FilterThree", "False"));
                        sqliteParameterList.Add(new SQLiteParameter("FilterFour", "False"));
                    }
                }

                return sqliteParameterList;
            }
            catch (Exception exception)
            {
                log.Error("Unable to obtain user contact filtering preferences.");
                log.Debug("Exception details: " + exception);
                return null;
            }
        }
    }

    public class GuiActions
    {
        private static readonly ILog log = LogManager.GetLogger(typeof(Logger));

        public void InsertGroupInObservableCollections(string groupName, MainWindowViewModel mainWindowViewModel)
        {
            try
            {
                var existingGroupName = mainWindowViewModel.SystemGroupList.FirstOrDefault(x => x.GroupName.Contains(groupName));
                if (existingGroupName == null)
                { mainWindowViewModel.SystemGroupList.Add(new SystemGroup(groupName)); }

                var existingUpdatableGroupName = mainWindowViewModel.SystemGroupListForUpdating.FirstOrDefault(x => x.GroupName.Equals(groupName));
                if (existingUpdatableGroupName == null)
                { mainWindowViewModel.SystemGroupListForUpdating.Add(new UpdatableSystemGroup(groupName)); }
            }
            catch (Exception exception)
            {
                log.Error("Unable to insert group into ObservableCollections.");
                throw exception;
            }
        }

        public void UpdateGroupObservableCollections(string currentGroupName, string updatedGroupName, MainWindowViewModel mainWindowViewModel)
        {
            try
            {
                var existingGroup = mainWindowViewModel.SystemGroupList.FirstOrDefault(x => x.GroupName.Contains(currentGroupName));
                if (existingGroup != null)
                { existingGroup.GroupName = updatedGroupName; }

                var existingUpdateGroup = mainWindowViewModel.SystemGroupListForUpdating.FirstOrDefault(x => x.GroupName.Contains(currentGroupName));
                if (existingUpdateGroup != null)
                { existingUpdateGroup.GroupName = updatedGroupName; }
            }
            catch (Exception exception)
            {
                log.Error("Unable to update group in ObservableCollections.");
                throw exception;
            }
        }

        public void UpdateMitigationObservableCollection(string vulnerabityId, string currentSystemGroupName, string updatedFindingText, string updatedVulnerabilityStatus,
            string updatedSystemGroupName, MainWindowViewModel mainWindowViewModel)
        {
            try
            {
                var mitigationItemToUpdate = mainWindowViewModel.MitigationList.FirstOrDefault(x => (x.MitigationVulnerabilityId.Equals(vulnerabityId)) &&
                        (x.MitigationGroupName.Equals(currentSystemGroupName)));
                if (mitigationItemToUpdate != null)
                {
                    if (!string.IsNullOrWhiteSpace(updatedFindingText))
                    { mitigationItemToUpdate.MitigationText = updatedFindingText; }
                    if (!string.IsNullOrWhiteSpace(updatedVulnerabilityStatus))
                    { mitigationItemToUpdate.MitigationStatus = updatedVulnerabilityStatus; }
                    if (!string.IsNullOrWhiteSpace(updatedSystemGroupName))
                    { mitigationItemToUpdate.MitigationGroupName = updatedSystemGroupName; }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to update mitigation ObservableCollection.");
                throw exception;
            }
        }

        public void InsertSystemInObservableCollections(string systemName, string systemIp, string groupName, MainWindowViewModel mainWindowViewModel)
        {
            try
            {
                systemIp = systemIp.Trim();
                groupName = groupName.Trim();
                systemName = systemName.Trim();
                var existingSystem = mainWindowViewModel.MonitoredSystemList.FirstOrDefault(x => x.SystemNameAndIp.Contains(systemName) &&
                                    x.SystemNameAndIp.Contains(systemIp));
                if (existingSystem == null)
                { mainWindowViewModel.MonitoredSystemList.Add(new MonitoredSystem(systemName + " : " + systemIp)); }

                var existingUpdateSystem = mainWindowViewModel.MonitoredSystemListForUpdating.FirstOrDefault(x => x.SystemGroupAndNameAndIp.Contains(groupName) &&
                    x.SystemGroupAndNameAndIp.Contains(systemIp) && x.SystemGroupAndNameAndIp.Contains(systemName));
                if (existingUpdateSystem == null)
                { mainWindowViewModel.MonitoredSystemListForUpdating.Add(new UpdatableMonitoredSystem(groupName + " : " + systemName + " : " + systemIp)); }
            }
            catch (Exception exception)
            {
                log.Error("Unable to insert system into ObservableCollections.");
                throw exception;
            }
        }

        public void UpdateGroupInSystemObservableCollection(string currentGroupName, string updatedGroupName, MainWindowViewModel mainWindowViewModel)
        {
            try
            {
                foreach (UpdatableMonitoredSystem updateContactSystem in mainWindowViewModel.MonitoredSystemListForUpdating)
                {
                    if (updateContactSystem.SystemGroupAndNameAndIp.Contains(currentGroupName))
                    {
                        updateContactSystem.SystemGroupAndNameAndIp = updatedGroupName.Trim() + " : " + updateContactSystem.SystemGroupAndNameAndIp.Split(':')[1].Trim() +
                            " : " + updateContactSystem.SystemGroupAndNameAndIp.Split(':')[2].Trim();
                    }
                }
            }
            catch (Exception exception)
            {
                log.Error("Unable to update group in ObservableCollection.");
                throw exception;
            }
        }

        public void InsertContactInObservableCollection(string contactName, string title, string email, string groupName,
            string systemName, string systemIp, MainWindowViewModel mainWindowViewModel)
        {
            try
            {
                var existingContact = mainWindowViewModel.ContactList.FirstOrDefault(x => x.ContactName.Equals(contactName) && x.ContactTitle.Equals(title) &&
                                x.ContactGroupName.Equals(groupName) && x.ContactSystemName.Equals(systemName) && x.ContactSystemIp.Equals(systemIp));
                if (existingContact == null)
                { mainWindowViewModel.ContactList.Add(new Contact(contactName, groupName, email, title, systemIp, systemName, false)); }
            }
            catch (Exception exception)
            {
                log.Error("Unable to insert contact into ObservableCollection.");
                throw exception;
            }
        }

        public void InsertTitleInObservableCollection(string title, MainWindowViewModel mainWindowViewModel)
        {
            try
            {
                var existingTitle = mainWindowViewModel.ContactTitleList.FirstOrDefault(x => x.ContactTitleName.Equals(title));
                if (existingTitle == null)
                { mainWindowViewModel.ContactTitleList.Add(new ContactTitle(title)); }
            }
            catch (Exception exception)
            {
                log.Error("Unable to insert title into ObservableCollection.");
                throw exception;
            }
        }
    }
}