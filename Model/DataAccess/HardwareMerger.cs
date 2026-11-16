using System;
using System.Collections.Generic;
using System.Data;
using System.Data.SQLite;
using System.Globalization;
using System.IO;
using System.Linq;
using Vulnerator.Helper;

namespace Vulnerator.Model.DataAccess
{
    /// <summary>
    /// Merges hardware records that are the same device (Configuration Management &gt; Hardware &gt; Merge). Everything
    /// on the merged records moves to the kept record: findings, IP and MAC addresses, groups, software, ports, SCAP
    /// scores, contacts, locations, submitted STIG releases and identifiers. When both records have the same finding
    /// (same rule or plugin, source and instance), the one observed last is kept, with the POA&amp;M and mitigation links
    /// of both. Blank fields of the kept record (FQDN, NetBIOS, OS, ...) are filled from the merged ones. The merged
    /// records' names become aliases of the kept record, so later imports with those names land on it.
    /// All in one transaction; it cannot be undone (back the database up first).
    /// </summary>
    public static class HardwareMerger
    {
        public sealed class Result
        {
            public int RecordsMerged { get; internal set; }
            public int FindingsMoved { get; internal set; }
            public int DuplicateFindingsCombined { get; internal set; }
            public List<string> Aliases { get; } = new List<string>();
        }

        private static readonly string[] FillColumns = { "FQDN", "NetBIOS", "ScanIP", "OperatingSystem", "Manufacturer", "ModelNumber", "SerialNumber", "Role", "NIAP_Level" };

        private static readonly string[] SimpleTables =
        {
            "HardwareContacts", "HardwareEnumeratedWindowsGroups", "HardwareGroups", "Hardware_IP_Addresses", "Hardware_MAC_Addresses",
            "HardwareLocations", "SoftwareHardware", "SCAP_Scores"
        };

        /// <summary>Merges <paramref name="mergeIds"/> into <paramref name="keepId"/>, using the shared database connection.</summary>
        public static Result Merge(long keepId, IEnumerable<long> mergeIds)
        {
            List<long> others = (mergeIds ?? new long[0]).Where(id => id != keepId).Distinct().ToList();
            if (others.Count == 0)
            { throw new InvalidOperationException("Pick at least two hardware records to merge."); }
            SQLiteConnection connection = DatabaseBuilder.sqliteConnection;
            bool wasOpen = connection.State == ConnectionState.Open;
            if (!wasOpen) connection.Open();
            try
            {
                using (SQLiteTransaction transaction = connection.BeginTransaction())
                {
                    Result result = new Result();
                    string keepName = Scalar(connection, transaction, "SELECT DiscoveredHostName FROM Hardware WHERE Hardware_ID = @K", keepId, 0);
                    if (keepName == null)
                    { throw new InvalidOperationException("The record to keep no longer exists; refresh the Hardware list."); }
                    foreach (long mergeId in others)
                    {
                        MergeOne(connection, transaction, keepId, keepName, mergeId, result);
                        result.RecordsMerged++;
                    }
                    transaction.Commit();
                    LogWriter.LogStatusUpdate($"Merged {result.RecordsMerged} hardware record(s) into '{keepName}': {result.FindingsMoved} finding(s) moved, " +
                                              $"{result.DuplicateFindingsCombined} duplicate finding(s) combined; aliases: {string.Join(", ", result.Aliases)}.");
                    return result;
                }
            }
            catch (InvalidOperationException)
            { throw; }
            catch (Exception exception)
            {
                LogWriter.LogErrorWithDebug("Hardware merge failed.", exception);
                throw new InvalidOperationException("The records could not be merged (nothing was changed): " + exception.Message, exception);
            }
            finally
            {
                if (!wasOpen) connection.Close();
            }
        }

        private static void MergeOne(SQLiteConnection connection, SQLiteTransaction transaction, long keepId, string keepName, long mergeId, Result result)
        {
            Dictionary<string, string> merged = Row(connection, transaction, mergeId);
            if (merged == null)
            { throw new InvalidOperationException("A record to merge no longer exists; refresh the Hardware list."); }

            // Names of the merged record become aliases of the kept one; its identifiers move with it.
            foreach (string name in new[] { "DiscoveredHostName", "DisplayedHostName", "FQDN", "NetBIOS" }.Select(c => (merged[c] ?? string.Empty).Trim())
                         .Where(n => n.Length > 0 && !string.Equals(n, keepName, StringComparison.Ordinal)).Distinct(StringComparer.OrdinalIgnoreCase))
            {
                Execute(connection, transaction, "INSERT INTO HardwareIdentifiers (Hardware_ID, IdentifierType, IdentifierValue) VALUES (@K, 'Alias', @V)", keepId, mergeId, name);
                result.Aliases.Add(name);
            }
            Execute(connection, transaction, "UPDATE HardwareIdentifiers SET Hardware_ID = @K WHERE Hardware_ID = @M", keepId, mergeId);
            Execute(connection, transaction, "DELETE FROM HardwareIdentifiers WHERE Hardware_ID = @K AND IdentifierType = 'Alias' AND IdentifierValue = @V", keepId, mergeId, keepName);

            // Fill the kept record's blank fields.
            foreach (string column in FillColumns)
            {
                Execute(connection, transaction,
                    $"UPDATE Hardware SET {column} = (SELECT {column} FROM Hardware WHERE Hardware_ID = @M) WHERE Hardware_ID = @K AND (TRIM(IFNULL({column}, '')) = '')", keepId, mergeId);
            }

            // Findings both records have: keep the one observed last, with both records' POA&M and mitigation links.
            List<long[]> pairs = new List<long[]>();
            using (SQLiteCommand command = Command(connection, transaction,
                       "SELECT K.UniqueFinding_ID, M.UniqueFinding_ID, K.LastObserved, M.LastObserved FROM UniqueFindings K " +
                       "JOIN UniqueFindings M ON M.Hardware_ID = @M AND K.Vulnerability_ID = M.Vulnerability_ID AND K.VulnerabilitySource_ID = M.VulnerabilitySource_ID " +
                       "AND K.FindingType_ID = M.FindingType_ID AND K.InstanceIdentifier IS M.InstanceIdentifier " +
                       "WHERE K.Hardware_ID = @K", keepId, mergeId))
            using (SQLiteDataReader reader = command.ExecuteReader())
            {
                while (reader.Read())
                {
                    long keepFinding = reader.GetInt64(0), mergeFinding = reader.GetInt64(1);
                    DateTime? keepSeen = HardwareScanDates.ToDate(reader.IsDBNull(2) ? null : reader.GetValue(2));
                    DateTime? mergeSeen = HardwareScanDates.ToDate(reader.IsDBNull(3) ? null : reader.GetValue(3));
                    bool mergeIsNewer = mergeSeen.HasValue && (!keepSeen.HasValue || mergeSeen.Value > keepSeen.Value);
                    pairs.Add(mergeIsNewer ? new[] { mergeFinding, keepFinding } : new[] { keepFinding, mergeFinding });
                }
            }
            HashSet<long> removed = new HashSet<long>();
            foreach (long[] pair in pairs)
            {
                long winner = pair[0], loser = pair[1];
                if (removed.Contains(loser) || removed.Contains(winner)) continue;
                Execute(connection, transaction, "UPDATE OR IGNORE PoamsUniqueFindings SET UniqueFinding_ID = @K WHERE UniqueFinding_ID = @M", winner, loser);
                Execute(connection, transaction, "UPDATE OR IGNORE UniqueFindingsMitigationsOrConditions SET UniqueFinding_ID = @K WHERE UniqueFinding_ID = @M", winner, loser);
                Execute(connection, transaction,
                    "UPDATE UniqueFindings SET MitigationOrCondition_ID = (SELECT MitigationOrCondition_ID FROM UniqueFindings WHERE UniqueFinding_ID = @M) " +
                    "WHERE UniqueFinding_ID = @K AND MitigationOrCondition_ID IS NULL", winner, loser);
                Execute(connection, transaction, "DELETE FROM PoamsUniqueFindings WHERE UniqueFinding_ID = @M", winner, loser);
                Execute(connection, transaction, "DELETE FROM UniqueFindingsMitigationsOrConditions WHERE UniqueFinding_ID = @M", winner, loser);
                Execute(connection, transaction, "DELETE FROM UniqueFindings WHERE UniqueFinding_ID = @M", winner, loser);
                removed.Add(loser);
                result.DuplicateFindingsCombined++;
            }
            result.FindingsMoved += Execute(connection, transaction, "UPDATE OR IGNORE UniqueFindings SET Hardware_ID = @K WHERE Hardware_ID = @M", keepId, mergeId);
            if (Count(connection, transaction, "SELECT COUNT(*) FROM UniqueFindings WHERE Hardware_ID = @M", keepId, mergeId) > 0)
            { throw new InvalidOperationException("Some findings could not be moved to the kept record."); }

            // Ports, protocols and services: a port both records have keeps the kept record's entry, with both records' evidence and software links.
            Execute(connection, transaction,
                "UPDATE OR IGNORE HardwareSoftwarePortsProtocolsServices SET HardwarePortProtocolService_ID = " +
                "(SELECT K.HardwarePortProtocolService_ID FROM HardwarePortsProtocolsServices K JOIN HardwarePortsProtocolsServices M ON M.PortProtocolService_ID = K.PortProtocolService_ID " +
                " WHERE K.Hardware_ID = @K AND M.HardwarePortProtocolService_ID = HardwareSoftwarePortsProtocolsServices.HardwarePortProtocolService_ID) " +
                "WHERE HardwarePortProtocolService_ID IN (SELECT M.HardwarePortProtocolService_ID FROM HardwarePortsProtocolsServices M JOIN HardwarePortsProtocolsServices K " +
                " ON K.PortProtocolService_ID = M.PortProtocolService_ID AND K.Hardware_ID = @K WHERE M.Hardware_ID = @M)", keepId, mergeId);
            Execute(connection, transaction,
                "UPDATE OR IGNORE PortProtocolServiceEvidence SET HardwarePortProtocolService_ID = " +
                "(SELECT K.HardwarePortProtocolService_ID FROM HardwarePortsProtocolsServices K JOIN HardwarePortsProtocolsServices M ON M.PortProtocolService_ID = K.PortProtocolService_ID " +
                " WHERE K.Hardware_ID = @K AND M.HardwarePortProtocolService_ID = PortProtocolServiceEvidence.HardwarePortProtocolService_ID) " +
                "WHERE HardwarePortProtocolService_ID IN (SELECT M.HardwarePortProtocolService_ID FROM HardwarePortsProtocolsServices M JOIN HardwarePortsProtocolsServices K " +
                " ON K.PortProtocolService_ID = M.PortProtocolService_ID AND K.Hardware_ID = @K WHERE M.Hardware_ID = @M)", keepId, mergeId);
            const string duplicatePorts = "SELECT M.HardwarePortProtocolService_ID FROM HardwarePortsProtocolsServices M JOIN HardwarePortsProtocolsServices K " +
                                          "ON K.PortProtocolService_ID = M.PortProtocolService_ID AND K.Hardware_ID = @K WHERE M.Hardware_ID = @M";
            Execute(connection, transaction, "DELETE FROM PortProtocolServiceEvidence WHERE HardwarePortProtocolService_ID IN (" + duplicatePorts + ")", keepId, mergeId);
            Execute(connection, transaction,
                "DELETE FROM HardwareSoftwarePortsProtocolsServicesBoundaries WHERE HardwareSoftwarePortProtocolService_ID IN " +
                "(SELECT HardwareSoftwarePortProtocolService_ID FROM HardwareSoftwarePortsProtocolsServices WHERE HardwarePortProtocolService_ID IN (" + duplicatePorts + "))", keepId, mergeId);
            Execute(connection, transaction, "DELETE FROM HardwareSoftwarePortsProtocolsServices WHERE HardwarePortProtocolService_ID IN (" + duplicatePorts + ")", keepId, mergeId);
            Execute(connection, transaction, "DELETE FROM HardwarePortsProtocolsServices WHERE HardwarePortProtocolService_ID IN (" + duplicatePorts + ")", keepId, mergeId);
            Execute(connection, transaction, "UPDATE HardwarePortsProtocolsServices SET Hardware_ID = @K WHERE Hardware_ID = @M", keepId, mergeId);

            // Plain link tables: move what the kept record does not have yet, drop the rest.
            foreach (string table in SimpleTables)
            {
                if (!TableExists(connection, transaction, table)) continue;
                Execute(connection, transaction, $"UPDATE OR IGNORE {table} SET Hardware_ID = @K WHERE Hardware_ID = @M", keepId, mergeId);
                Execute(connection, transaction, $"DELETE FROM {table} WHERE Hardware_ID = @M", keepId, mergeId);
            }

            // Submitted STIG releases are recorded by host name.
            if (TableExists(connection, transaction, "StigSubmissions"))
            {
                Execute(connection, transaction, "UPDATE OR REPLACE StigSubmissions SET DiscoveredHostName = @V WHERE DiscoveredHostName = (SELECT DiscoveredHostName FROM Hardware WHERE Hardware_ID = @M)",
                    keepId, mergeId, keepName);
            }

            Execute(connection, transaction, "DELETE FROM Hardware WHERE Hardware_ID = @M", keepId, mergeId);
        }

        /// <summary>Copies the database file next to it ("&lt;name&gt;.before-merge-yyyyMMdd-HHmmss.sqlite"). Returns the copy's path.</summary>
        public static string BackUpDatabase()
        {
            string database = Properties.Settings.Default.Database;
            if (string.IsNullOrWhiteSpace(database) || !File.Exists(database))
            { throw new InvalidOperationException("The database file was not found, so it could not be backed up."); }
            if (DatabaseBuilder.sqliteConnection.State == ConnectionState.Open)
            { throw new InvalidOperationException("The database is busy; wait for the current task to finish and try again."); }
            string folder = Path.GetDirectoryName(Path.GetFullPath(database));
            string backup = Path.Combine(folder, Path.GetFileNameWithoutExtension(database) + ".before-merge-" +
                                                 DateTime.Now.ToString("yyyyMMdd-HHmmss", CultureInfo.InvariantCulture) + Path.GetExtension(database));
            File.Copy(database, backup, false);
            return backup;
        }

        private static Dictionary<string, string> Row(SQLiteConnection connection, SQLiteTransaction transaction, long id)
        {
            using (SQLiteCommand command = Command(connection, transaction, "SELECT DiscoveredHostName, DisplayedHostName, FQDN, NetBIOS FROM Hardware WHERE Hardware_ID = @M", 0, id))
            using (SQLiteDataReader reader = command.ExecuteReader())
            {
                if (!reader.Read()) return null;
                Dictionary<string, string> row = new Dictionary<string, string>();
                for (int i = 0; i < reader.FieldCount; i++)
                { row[reader.GetName(i)] = reader.IsDBNull(i) ? null : Convert.ToString(reader.GetValue(i), CultureInfo.InvariantCulture); }
                return row;
            }
        }

        private static bool TableExists(SQLiteConnection connection, SQLiteTransaction transaction, string table)
        {
            using (SQLiteCommand command = Command(connection, transaction, "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = @V", 0, 0, table))
            { return Convert.ToInt64(command.ExecuteScalar(), CultureInfo.InvariantCulture) > 0; }
        }

        private static SQLiteCommand Command(SQLiteConnection connection, SQLiteTransaction transaction, string sql, long keepId, long mergeId, string value = null)
        {
            SQLiteCommand command = connection.CreateCommand();
            command.Transaction = transaction;
            command.CommandText = sql;
            command.Parameters.AddWithValue("@K", keepId);
            command.Parameters.AddWithValue("@M", mergeId);
            command.Parameters.AddWithValue("@V", (object)value ?? DBNull.Value);
            return command;
        }

        private static int Execute(SQLiteConnection connection, SQLiteTransaction transaction, string sql, long keepId, long mergeId, string value = null)
        {
            using (SQLiteCommand command = Command(connection, transaction, sql, keepId, mergeId, value))
            { return command.ExecuteNonQuery(); }
        }

        private static long Count(SQLiteConnection connection, SQLiteTransaction transaction, string sql, long keepId, long mergeId)
        {
            using (SQLiteCommand command = Command(connection, transaction, sql, keepId, mergeId))
            { return Convert.ToInt64(command.ExecuteScalar(), CultureInfo.InvariantCulture); }
        }

        private static string Scalar(SQLiteConnection connection, SQLiteTransaction transaction, string sql, long keepId, long mergeId)
        {
            using (SQLiteCommand command = Command(connection, transaction, sql, keepId, mergeId))
            {
                object value = command.ExecuteScalar();
                return value == null || value is DBNull ? null : Convert.ToString(value, CultureInfo.InvariantCulture);
            }
        }
    }
}
