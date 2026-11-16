using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.Globalization;
using System.IO;
using Vulnerator.Helper;

namespace Vulnerator.Model.DataAccess
{
    /// <summary>
    /// Keeps one hardware record per device across ACAS and STIG imports. Two kinds of identifier are stored in
    /// HardwareIdentifiers:
    /// <list type="bullet">
    /// <item><b>AcasHostId</b> - the Tenable Security Center host ID from the .nessus host properties (the tag named
    /// in Settings, "TAG" by default). It stays the same when the device's name or IP changes, so ACAS results with
    /// a known ID always land on the same record.</item>
    /// <item><b>Alias</b> - another name for the device, saved when records are merged (for example W01.Contoso
    /// typed in a checklist for the ACAS host W01.Contoso.com). Later imports with that name land on the kept record.</item>
    /// </list>
    /// Every import goes through <see cref="DatabaseInterface.InsertHardware"/>, which calls <see cref="ResolveHost"/>
    /// before the host is inserted: when an identifier is known, the DiscoveredHostName parameter is replaced by the
    /// existing record's name, so every later statement of the import uses that record.
    /// </summary>
    public static class HardwareIdentity
    {
        public const string AcasHostIdType = "AcasHostId";
        public const string AliasType = "Alias";

        /// <summary>Rewrites @DiscoveredHostName to the existing record's name when the ACAS host ID or an alias is known.</summary>
        public static void ResolveHost(SQLiteCommand importCommand)
        {
            string name = Text(importCommand, "DiscoveredHostName");
            string hostId = Text(importCommand, "AcasHostId");
            string canonical = null;
            bool byHostId = false;
            if (hostId.Length > 0)
            {
                canonical = Scalar(importCommand,
                    "SELECT H.DiscoveredHostName FROM HardwareIdentifiers HI JOIN Hardware H ON H.Hardware_ID = HI.Hardware_ID " +
                    "WHERE HI.IdentifierType = 'AcasHostId' AND HI.IdentifierValue = @Value LIMIT 1", hostId);
                byHostId = canonical != null;
            }
            if (canonical == null && name.Length > 0 &&
                Scalar(importCommand, "SELECT DiscoveredHostName FROM Hardware WHERE DiscoveredHostName = @Value LIMIT 1", name) == null)
            {
                canonical = Scalar(importCommand,
                    "SELECT H.DiscoveredHostName FROM HardwareIdentifiers HI JOIN Hardware H ON H.Hardware_ID = HI.Hardware_ID " +
                    "WHERE HI.IdentifierType = 'Alias' AND HI.IdentifierValue = @Value COLLATE NOCASE LIMIT 1", name);
            }
            if (canonical == null || canonical == name)
            { return; }
            importCommand.Parameters["DiscoveredHostName"].Value = canonical;
            // A device ACAS knows by its host ID that now reports another name (renamed): remember the new name too,
            // so checklists that use it land on the same record.
            if (byHostId && name.Length > 0)
            { Save(importCommand, canonical, AliasType, name); }
        }

        /// <summary>After the host is inserted: ties the ACAS host ID (if any) to the host's record.</summary>
        public static void RecordAcasHostId(SQLiteCommand importCommand)
        {
            string hostId = Text(importCommand, "AcasHostId");
            string name = Text(importCommand, "DiscoveredHostName");
            if (hostId.Length > 0 && name.Length > 0)
            { Save(importCommand, name, AcasHostIdType, hostId); }
        }

        private static void Save(SQLiteCommand importCommand, string discoveredHostName, string type, string value)
        {
            using (SQLiteCommand command = importCommand.Connection.CreateCommand())
            {
                command.Transaction = importCommand.Transaction;
                command.CommandText = "INSERT INTO HardwareIdentifiers (Hardware_ID, IdentifierType, IdentifierValue) " +
                                      "SELECT Hardware_ID, @Type, @Value FROM Hardware WHERE DiscoveredHostName = @Name LIMIT 1";
                command.Parameters.AddWithValue("@Type", type);
                command.Parameters.AddWithValue("@Value", value);
                command.Parameters.AddWithValue("@Name", discoveredHostName);
                command.ExecuteNonQuery();
            }
        }

        private static string Scalar(SQLiteCommand importCommand, string sql, string value)
        {
            using (SQLiteCommand command = importCommand.Connection.CreateCommand())
            {
                command.Transaction = importCommand.Transaction;
                command.CommandText = sql;
                command.Parameters.AddWithValue("@Value", value);
                object result = command.ExecuteScalar();
                return result == null || result is DBNull ? null : Convert.ToString(result, CultureInfo.InvariantCulture);
            }
        }

        private static string Text(SQLiteCommand command, string parameter)
        {
            if (!command.Parameters.Contains(parameter)) return string.Empty;
            object value = command.Parameters[parameter].Value;
            return value == null || value is DBNull ? string.Empty : Convert.ToString(value, CultureInfo.InvariantCulture).Trim();
        }

        /// <summary>Aliases and ACAS host IDs per hardware record, for the Hardware list. Empty when the database cannot be read.</summary>
        public static Dictionary<long, Identifiers> LoadAll()
        {
            Dictionary<long, Identifiers> result = new Dictionary<long, Identifiers>();
            try
            {
                string database = Properties.Settings.Default.Database;
                if (string.IsNullOrWhiteSpace(database) || database == "Undefined" || !File.Exists(database))
                { return result; }
                using (SQLiteConnection connection = new SQLiteConnection(DatabaseBuilder.ConnectionStringFor(database) + "Read Only=True;"))
                {
                    connection.Open();
                    using (SQLiteCommand command = connection.CreateCommand())
                    {
                        command.CommandText = "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'HardwareIdentifiers'";
                        if (command.ExecuteScalar() == null) return result;
                        command.CommandText = "SELECT Hardware_ID, IdentifierType, IdentifierValue FROM HardwareIdentifiers ORDER BY IdentifierValue";
                        using (SQLiteDataReader reader = command.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                long id = Convert.ToInt64(reader.GetValue(0), CultureInfo.InvariantCulture);
                                Identifiers identifiers;
                                if (!result.TryGetValue(id, out identifiers))
                                {
                                    identifiers = new Identifiers();
                                    result[id] = identifiers;
                                }
                                string type = Convert.ToString(reader.GetValue(1), CultureInfo.InvariantCulture);
                                string value = Convert.ToString(reader.GetValue(2), CultureInfo.InvariantCulture);
                                if (type == AcasHostIdType) identifiers.AcasHostIds.Add(value);
                                else if (type == AliasType) identifiers.Aliases.Add(value);
                            }
                        }
                    }
                }
            }
            catch (Exception exception)
            { LogWriter.LogErrorWithDebug("Unable to read the hardware aliases and ACAS host IDs.", exception); }
            return result;
        }

        public sealed class Identifiers
        {
            public List<string> AcasHostIds { get; } = new List<string>();
            public List<string> Aliases { get; } = new List<string>();
        }
    }
}
