using System;
using System.Data;
using System.Data.SQLite;
using Vulnerator.Helper;

namespace Vulnerator.Model.DataAccess
{
    /// <summary>
    /// The edits the Configuration Management Hardware and Software tabs make, as plain synchronous database calls (the
    /// tabs run them on a background worker, the tests call them directly). Every method runs in one transaction and
    /// throws <see cref="InvalidOperationException"/> with a message for the user when the edit is not possible.
    /// </summary>
    public static class AssetEditor
    {
        // ----- Hardware -----------------------------------------------------------------------------------------

        /// <summary>Adds a host entered by hand (filed in the "All" group so the reports include it). Returns its ID.</summary>
        public static long AddHardware(Entity.Hardware hardware, long? lifecycleStatusId)
        {
            string name = (hardware?.DisplayedHostName ?? string.Empty).Trim();
            if (name.Length == 0)
            { throw new InvalidOperationException("Enter a host name first."); }
            return Run(command =>
            {
                command.CommandText = "SELECT COUNT(*) FROM Hardware WHERE DiscoveredHostName = @Name COLLATE NOCASE";
                command.Parameters.AddWithValue("@Name", name);
                if (Convert.ToInt64(command.ExecuteScalar()) > 0)
                { throw new InvalidOperationException($"A host named '{name}' already exists."); }
                command.CommandText =
                    "INSERT INTO Hardware (DisplayedHostName, DiscoveredHostName, ScanIP, Found21745, Found26917, IsVirtualServer, NIAP_Level, " +
                    "Manufacturer, ModelNumber, IsIA_Enabled, SerialNumber, Role, LifecycleStatus_ID, OperatingSystem) " +
                    "VALUES (@Name, @Name, @ScanIP, 'False', 'False', @IsVirtualServer, @NIAP_Level, @Manufacturer, @ModelNumber, @IsIA_Enabled, " +
                    "@SerialNumber, @Role, @LifecycleStatus_ID, @OperatingSystem)";
                AddHardwareFields(command, hardware, lifecycleStatusId);
                command.ExecuteNonQuery();
                long id = LastId(command);
                command.Parameters.Clear();
                command.Parameters.AddWithValue("@Hardware_ID", id);
                command.CommandText = "INSERT INTO HardwareGroups (Hardware_ID, Group_ID) SELECT @Hardware_ID, Group_ID FROM Groups WHERE GroupName = 'All'";
                command.ExecuteNonQuery();
                if (!string.IsNullOrWhiteSpace(hardware.ScanIP))
                { MapIp(command, id, hardware.ScanIP.Trim()); }
                return id;
            });
        }

        /// <summary>Saves a host's editable fields. The discovered host name (how imports find the host) is not changed.</summary>
        public static void UpdateHardware(Entity.Hardware hardware, long? lifecycleStatusId)
        {
            if (hardware == null || hardware.Hardware_ID == 0)
            { throw new InvalidOperationException("Select a host first."); }
            if (string.IsNullOrWhiteSpace(hardware.DisplayedHostName))
            { throw new InvalidOperationException("The host name cannot be empty."); }
            Run(command =>
            {
                command.CommandText =
                    "UPDATE Hardware SET DisplayedHostName = @Name, ScanIP = @ScanIP, IsVirtualServer = @IsVirtualServer, NIAP_Level = @NIAP_Level, " +
                    "Manufacturer = @Manufacturer, ModelNumber = @ModelNumber, IsIA_Enabled = @IsIA_Enabled, SerialNumber = @SerialNumber, " +
                    "Role = @Role, LifecycleStatus_ID = @LifecycleStatus_ID, OperatingSystem = @OperatingSystem WHERE Hardware_ID = @Hardware_ID";
                command.Parameters.AddWithValue("@Name", hardware.DisplayedHostName.Trim());
                command.Parameters.AddWithValue("@Hardware_ID", hardware.Hardware_ID);
                AddHardwareFields(command, hardware, lifecycleStatusId);
                command.ExecuteNonQuery();
                return 0L;
            });
        }

        /// <summary>Deletes a host with its findings, addresses, groups, software and port links.</summary>
        public static void DeleteHardware(long hardwareId)
        {
            Run(command =>
            {
                command.Parameters.AddWithValue("@Id", hardwareId);
                command.CommandText = string.Join(" ",
                    "DELETE FROM PortProtocolServiceEvidence WHERE HardwarePortProtocolService_ID IN (SELECT HardwarePortProtocolService_ID FROM HardwarePortsProtocolsServices WHERE Hardware_ID = @Id);",
                    "DELETE FROM HardwareSoftwarePortsProtocolsServicesBoundaries WHERE HardwareSoftwarePortProtocolService_ID IN (SELECT HSPPS.HardwareSoftwarePortProtocolService_ID FROM HardwareSoftwarePortsProtocolsServices HSPPS JOIN HardwarePortsProtocolsServices HPPS ON HSPPS.HardwarePortProtocolService_ID = HPPS.HardwarePortProtocolService_ID WHERE HPPS.Hardware_ID = @Id);",
                    "DELETE FROM HardwareSoftwarePortsProtocolsServices WHERE HardwarePortProtocolService_ID IN (SELECT HardwarePortProtocolService_ID FROM HardwarePortsProtocolsServices WHERE Hardware_ID = @Id);",
                    "DELETE FROM HardwarePortsProtocolsServices WHERE Hardware_ID = @Id;",
                    "DELETE FROM HardwareContacts WHERE Hardware_ID = @Id;",
                    "DELETE FROM HardwareEnumeratedWindowsGroups WHERE Hardware_ID = @Id;",
                    "DELETE FROM HardwareGroups WHERE Hardware_ID = @Id;",
                    "DELETE FROM Hardware_IP_Addresses WHERE Hardware_ID = @Id;",
                    "DELETE FROM Hardware_MAC_Addresses WHERE Hardware_ID = @Id;",
                    "DELETE FROM HardwareLocations WHERE Hardware_ID = @Id;",
                    "DELETE FROM SoftwareHardware WHERE Hardware_ID = @Id;",
                    "DELETE FROM SCAP_Scores WHERE Hardware_ID = @Id;",
                    "DELETE FROM PoamsUniqueFindings WHERE UniqueFinding_ID IN (SELECT UniqueFinding_ID FROM UniqueFindings WHERE Hardware_ID = @Id);",
                    "DELETE FROM UniqueFindingsMitigationsOrConditions WHERE UniqueFinding_ID IN (SELECT UniqueFinding_ID FROM UniqueFindings WHERE Hardware_ID = @Id);",
                    "DELETE FROM UniqueFindings WHERE Hardware_ID = @Id;",
                    "DELETE FROM HardwareIdentifiers WHERE Hardware_ID = @Id;",
                    "DELETE FROM DeviceRegistry WHERE Hardware_ID = @Id;",
                    "DELETE FROM Hardware WHERE Hardware_ID = @Id;");
                command.ExecuteNonQuery();
                return 0L;
            });
        }

        public static void AddIpAddress(long hardwareId, string ipAddress)
        {
            if (string.IsNullOrWhiteSpace(ipAddress))
            { throw new InvalidOperationException("Enter an IP address first."); }
            Run(command => { MapIp(command, hardwareId, ipAddress.Trim()); return 0L; });
        }

        public static void RemoveIpAddress(long hardwareId, long ipAddressId)
        { Delete("DELETE FROM Hardware_IP_Addresses WHERE Hardware_ID = @A AND IP_Address_ID = @B", hardwareId, ipAddressId); }

        /// <summary>
        /// Saves another name for the device, so imports with that name land on it. Refused when another record already
        /// has that name (merge the records instead) or the name is the device's own.
        /// </summary>
        public static void AddAlias(long hardwareId, string alias)
        {
            string name = (alias ?? string.Empty).Trim();
            if (name.Length == 0)
            { throw new InvalidOperationException("Enter the other name first."); }
            if (name.Length > 500)
            { throw new InvalidOperationException("The name is too long."); }
            Run(command =>
            {
                command.Parameters.AddWithValue("@Id", hardwareId);
                command.Parameters.AddWithValue("@Name", name);
                command.CommandText = "SELECT DiscoveredHostName FROM Hardware WHERE Hardware_ID = @Id";
                object own = command.ExecuteScalar();
                if (own == null || own is DBNull)
                { throw new InvalidOperationException("The hardware record no longer exists; refresh the list."); }
                if (string.Equals(Convert.ToString(own), name, StringComparison.OrdinalIgnoreCase))
                { throw new InvalidOperationException("That is already this device's name."); }
                command.CommandText = "SELECT DisplayedHostName FROM Hardware WHERE Hardware_ID <> @Id AND DiscoveredHostName = @Name COLLATE NOCASE LIMIT 1";
                object other = command.ExecuteScalar();
                if (other != null && !(other is DBNull))
                { throw new InvalidOperationException($"Another hardware record ('{other}') has the name '{name}'. Tick both records and use Merge Ticked Hardware instead."); }
                command.CommandText = "INSERT INTO HardwareIdentifiers (Hardware_ID, IdentifierType, IdentifierValue) VALUES (@Id, 'Alias', @Name)";
                command.ExecuteNonQuery();
                return 0L;
            });
        }

        /// <summary>Forgets one saved name of the device; later imports with that name are matched as usual again.</summary>
        public static void RemoveAlias(long hardwareId, string alias)
        {
            Run(command =>
            {
                command.Parameters.AddWithValue("@Id", hardwareId);
                command.Parameters.AddWithValue("@Name", alias ?? string.Empty);
                command.CommandText = "DELETE FROM HardwareIdentifiers WHERE Hardware_ID = @Id AND IdentifierType = 'Alias' AND IdentifierValue = @Name";
                command.ExecuteNonQuery();
                return 0L;
            });
        }

        public static void AddMacAddress(long hardwareId, string macAddress)
        {
            if (string.IsNullOrWhiteSpace(macAddress))
            { throw new InvalidOperationException("Enter a MAC address first."); }
            Run(command =>
            {
                command.Parameters.AddWithValue("@Mac", macAddress.Trim());
                command.Parameters.AddWithValue("@Hardware_ID", hardwareId);
                command.CommandText = "INSERT INTO MAC_Addresses (MAC_Address) VALUES (@Mac); " +
                                      "INSERT INTO Hardware_MAC_Addresses (Hardware_ID, MAC_Address_ID) SELECT @Hardware_ID, MAC_Address_ID FROM MAC_Addresses WHERE MAC_Address = @Mac;";
                command.ExecuteNonQuery();
                return 0L;
            });
        }

        public static void RemoveMacAddress(long hardwareId, long macAddressId)
        { Delete("DELETE FROM Hardware_MAC_Addresses WHERE Hardware_ID = @A AND MAC_Address_ID = @B", hardwareId, macAddressId); }

        public static void AddGroup(long hardwareId, long groupId)
        { Delete("INSERT INTO HardwareGroups (Hardware_ID, Group_ID) VALUES (@A, @B)", hardwareId, groupId); }

        public static void RemoveGroup(long hardwareId, long groupId)
        { Delete("DELETE FROM HardwareGroups WHERE Hardware_ID = @A AND Group_ID = @B", hardwareId, groupId); }

        public static void AddSoftwareToHardware(long hardwareId, long softwareId)
        { Delete("INSERT INTO SoftwareHardware (Hardware_ID, Software_ID) VALUES (@A, @B)", hardwareId, softwareId); }

        public static void RemoveSoftwareFromHardware(long hardwareId, long softwareId)
        { Delete("DELETE FROM SoftwareHardware WHERE Hardware_ID = @A AND Software_ID = @B", hardwareId, softwareId); }

        public static void AddPortProtocolService(long hardwareId, long portProtocolServiceId)
        { Delete("INSERT INTO HardwarePortsProtocolsServices (Hardware_ID, PortProtocolService_ID) VALUES (@A, @B)", hardwareId, portProtocolServiceId); }

        public static void RemovePortProtocolService(long hardwareId, long portProtocolServiceId)
        {
            Delete(
                "DELETE FROM PortProtocolServiceEvidence WHERE HardwarePortProtocolService_ID IN (SELECT HardwarePortProtocolService_ID FROM HardwarePortsProtocolsServices WHERE Hardware_ID = @A AND PortProtocolService_ID = @B); " +
                "DELETE FROM HardwareSoftwarePortsProtocolsServicesBoundaries WHERE HardwareSoftwarePortProtocolService_ID IN (SELECT HSPPS.HardwareSoftwarePortProtocolService_ID FROM HardwareSoftwarePortsProtocolsServices HSPPS JOIN HardwarePortsProtocolsServices HPPS ON HSPPS.HardwarePortProtocolService_ID = HPPS.HardwarePortProtocolService_ID WHERE HPPS.Hardware_ID = @A AND HPPS.PortProtocolService_ID = @B); " +
                "DELETE FROM HardwareSoftwarePortsProtocolsServices WHERE HardwarePortProtocolService_ID IN (SELECT HardwarePortProtocolService_ID FROM HardwarePortsProtocolsServices WHERE Hardware_ID = @A AND PortProtocolService_ID = @B); " +
                "DELETE FROM HardwarePortsProtocolsServices WHERE Hardware_ID = @A AND PortProtocolService_ID = @B;",
                hardwareId, portProtocolServiceId);
        }

        // ----- Software -----------------------------------------------------------------------------------------

        /// <summary>Adds a software item entered by hand. Returns its ID.</summary>
        public static long AddSoftware(Entity.Software software)
        {
            string name = (software?.DisplayedSoftwareName ?? string.Empty).Trim();
            if (name.Length == 0)
            { throw new InvalidOperationException("Enter a software name first."); }
            return Run(command =>
            {
                command.CommandText = "SELECT COUNT(*) FROM Software WHERE DiscoveredSoftwareName = @Name COLLATE NOCASE";
                command.Parameters.AddWithValue("@Name", name);
                if (Convert.ToInt64(command.ExecuteScalar()) > 0)
                { throw new InvalidOperationException($"Software named '{name}' already exists."); }
                command.CommandText =
                    "INSERT INTO Software (DiscoveredSoftwareName, DisplayedSoftwareName, SoftwareAcronym, SoftwareVersion, SoftwareDescription, " +
                    "SoftwareFunction, DADMS_ID, DADMS_Disposition, DADMS_LastDateAuthorized, HasCustomCode, IA_OrIA_Enabled, IsOS_OrFirmware, " +
                    "FAM_Accepted, ExternallyAuthorized, ReportInAccreditationGlobal, ApprovedForBaselineGlobal, BaselineApproverGlobal) " +
                    "VALUES (@Name, @Name, @SoftwareAcronym, @SoftwareVersion, @SoftwareDescription, @SoftwareFunction, @DADMS_ID, @DADMS_Disposition, " +
                    "@DADMS_LastDateAuthorized, @HasCustomCode, @IA_OrIA_Enabled, @IsOS_OrFirmware, @FAM_Accepted, @ExternallyAuthorized, " +
                    "@ReportInAccreditationGlobal, @ApprovedForBaselineGlobal, @BaselineApproverGlobal)";
                AddSoftwareFields(command, software);
                command.ExecuteNonQuery();
                return LastId(command);
            });
        }

        /// <summary>Saves a software item's editable fields (the discovered name, used by imports, is not changed).</summary>
        public static void UpdateSoftware(Entity.Software software)
        {
            if (software == null || software.Software_ID == 0)
            { throw new InvalidOperationException("Select a software item first."); }
            if (string.IsNullOrWhiteSpace(software.DisplayedSoftwareName))
            { throw new InvalidOperationException("The software name cannot be empty."); }
            Run(command =>
            {
                command.CommandText =
                    "UPDATE Software SET DisplayedSoftwareName = @Name, SoftwareAcronym = @SoftwareAcronym, SoftwareVersion = @SoftwareVersion, " +
                    "SoftwareDescription = @SoftwareDescription, SoftwareFunction = @SoftwareFunction, DADMS_ID = @DADMS_ID, " +
                    "DADMS_Disposition = @DADMS_Disposition, DADMS_LastDateAuthorized = @DADMS_LastDateAuthorized, HasCustomCode = @HasCustomCode, " +
                    "IA_OrIA_Enabled = @IA_OrIA_Enabled, IsOS_OrFirmware = @IsOS_OrFirmware, FAM_Accepted = @FAM_Accepted, " +
                    "ExternallyAuthorized = @ExternallyAuthorized, ReportInAccreditationGlobal = @ReportInAccreditationGlobal, " +
                    "ApprovedForBaselineGlobal = @ApprovedForBaselineGlobal, BaselineApproverGlobal = @BaselineApproverGlobal " +
                    "WHERE Software_ID = @Software_ID";
                command.Parameters.AddWithValue("@Name", software.DisplayedSoftwareName.Trim());
                command.Parameters.AddWithValue("@Software_ID", software.Software_ID);
                AddSoftwareFields(command, software);
                command.ExecuteNonQuery();
                return 0L;
            });
        }

        /// <summary>Deletes a software item with its host links, port links and the findings recorded against it.</summary>
        public static void DeleteSoftware(long softwareId)
        {
            Run(command =>
            {
                command.Parameters.AddWithValue("@Id", softwareId);
                command.CommandText = string.Join(" ",
                    "DELETE FROM HardwareSoftwarePortsProtocolsServicesBoundaries WHERE HardwareSoftwarePortProtocolService_ID IN (SELECT HardwareSoftwarePortProtocolService_ID FROM HardwareSoftwarePortsProtocolsServices WHERE Software_ID = @Id);",
                    "DELETE FROM HardwareSoftwarePortsProtocolsServices WHERE Software_ID = @Id;",
                    "DELETE FROM SoftwareHardware WHERE Software_ID = @Id;",
                    "DELETE FROM SoftwareContacts WHERE Software_ID = @Id;",
                    "DELETE FROM SoftwareDADMS_Networks WHERE Software_ID = @Id;",
                    "DELETE FROM PoamsUniqueFindings WHERE UniqueFinding_ID IN (SELECT UniqueFinding_ID FROM UniqueFindings WHERE Software_ID = @Id);",
                    "DELETE FROM UniqueFindingsMitigationsOrConditions WHERE UniqueFinding_ID IN (SELECT UniqueFinding_ID FROM UniqueFindings WHERE Software_ID = @Id);",
                    "DELETE FROM UniqueFindings WHERE Software_ID = @Id;",
                    "DELETE FROM Software WHERE Software_ID = @Id;");
                command.ExecuteNonQuery();
                return 0L;
            });
        }

        // ----- Helpers ------------------------------------------------------------------------------------------

        private static void MapIp(SQLiteCommand command, long hardwareId, string ip)
        {
            command.Parameters.Clear();
            command.Parameters.AddWithValue("@Ip", ip);
            command.Parameters.AddWithValue("@Hardware_ID", hardwareId);
            command.CommandText = "INSERT INTO IP_Addresses (IP_Address) VALUES (@Ip); " +
                                  "INSERT INTO Hardware_IP_Addresses (Hardware_ID, IP_Address_ID) SELECT @Hardware_ID, IP_Address_ID FROM IP_Addresses WHERE IP_Address = @Ip;";
            command.ExecuteNonQuery();
        }

        private static void AddHardwareFields(SQLiteCommand command, Entity.Hardware h, long? lifecycleStatusId)
        {
            command.Parameters.AddWithValue("@Name", (h.DisplayedHostName ?? string.Empty).Trim());
            command.Parameters.AddWithValue("@ScanIP", Value(h.ScanIP));
            command.Parameters.AddWithValue("@IsVirtualServer", Value(h.IsVirtualServer));
            command.Parameters.AddWithValue("@NIAP_Level", Value(h.NIAP_Level));
            command.Parameters.AddWithValue("@Manufacturer", Value(h.Manufacturer));
            command.Parameters.AddWithValue("@ModelNumber", Value(h.ModelNumber));
            command.Parameters.AddWithValue("@IsIA_Enabled", Value(h.IsIA_Enabled));
            command.Parameters.AddWithValue("@SerialNumber", Value(h.SerialNumber));
            command.Parameters.AddWithValue("@Role", Value(h.Role));
            command.Parameters.AddWithValue("@LifecycleStatus_ID", lifecycleStatusId.HasValue ? (object)lifecycleStatusId.Value : DBNull.Value);
            command.Parameters.AddWithValue("@OperatingSystem", Value(h.OperatingSystem));
        }

        private static void AddSoftwareFields(SQLiteCommand command, Entity.Software s)
        {
            command.Parameters.AddWithValue("@SoftwareAcronym", Value(s.SoftwareAcronym));
            command.Parameters.AddWithValue("@SoftwareVersion", Value(s.SoftwareVersion));
            command.Parameters.AddWithValue("@SoftwareDescription", Value(s.SoftwareDescription));
            command.Parameters.AddWithValue("@SoftwareFunction", Value(s.SoftwareFunction));
            command.Parameters.AddWithValue("@DADMS_ID", Value(s.DADMS_ID));
            command.Parameters.AddWithValue("@DADMS_Disposition", Value(s.DADMS_Disposition));
            SQLiteParameter date = new SQLiteParameter("@DADMS_LastDateAuthorized", DbType.DateTime)
            { Value = s.DADMS_LastDateAuthorized.HasValue ? (object)s.DADMS_LastDateAuthorized.Value : DBNull.Value };
            command.Parameters.Add(date);
            command.Parameters.AddWithValue("@HasCustomCode", Value(s.HasCustomCode));
            command.Parameters.AddWithValue("@IA_OrIA_Enabled", Value(s.IA_OrIA_Enabled));
            command.Parameters.AddWithValue("@IsOS_OrFirmware", Value(s.IsOS_OrFirmware));
            command.Parameters.AddWithValue("@FAM_Accepted", Value(s.FAM_Accepted));
            command.Parameters.AddWithValue("@ExternallyAuthorized", Value(s.ExternallyAuthorized));
            command.Parameters.AddWithValue("@ReportInAccreditationGlobal", Value(s.ReportInAccreditationGlobal));
            command.Parameters.AddWithValue("@ApprovedForBaselineGlobal", Value(s.ApprovedForBaselineGlobal));
            command.Parameters.AddWithValue("@BaselineApproverGlobal", Value(s.BaselineApproverGlobal));
        }

        private static object Value(string text)
        { return string.IsNullOrWhiteSpace(text) ? (object)DBNull.Value : text.Trim(); }

        private static long LastId(SQLiteCommand command)
        {
            command.CommandText = "SELECT last_insert_rowid()";
            return Convert.ToInt64(command.ExecuteScalar());
        }

        private static void Delete(string sql, long a, long b)
        {
            Run(command =>
            {
                command.CommandText = sql;
                command.Parameters.AddWithValue("@A", a);
                command.Parameters.AddWithValue("@B", b);
                command.ExecuteNonQuery();
                return 0L;
            });
        }

        private static long Run(Func<SQLiteCommand, long> action)
        {
            bool wasOpen = DatabaseBuilder.sqliteConnection.State == ConnectionState.Open;
            if (!wasOpen)
            { DatabaseBuilder.sqliteConnection.Open(); }
            try
            {
                using (SQLiteTransaction transaction = DatabaseBuilder.sqliteConnection.BeginTransaction())
                {
                    long result;
                    using (SQLiteCommand command = DatabaseBuilder.sqliteConnection.CreateCommand())
                    { result = action(command); }
                    transaction.Commit();
                    return result;
                }
            }
            catch (InvalidOperationException)
            { throw; }
            catch (Exception exception)
            {
                LogWriter.LogErrorWithDebug("Configuration Management edit failed.", exception);
                throw new InvalidOperationException("The change could not be saved: " + exception.Message, exception);
            }
            finally
            {
                if (!wasOpen)
                { DatabaseBuilder.sqliteConnection.Close(); }
            }
        }
    }
}
