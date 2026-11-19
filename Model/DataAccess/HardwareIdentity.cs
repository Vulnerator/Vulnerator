using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.Globalization;
using System.IO;
using Vulnerator.Helper;

namespace Vulnerator.Model.DataAccess
{
    /// <summary>
    /// Keeps one hardware record per device across ACAS and STIG imports.
    /// <list type="bullet">
    /// <item><b>Registry number</b> (DeviceRegistry): every device gets a permanent Vulnerator number, shown as
    /// VUL-000123. Numbers are never reused. When devices are merged, the kept device keeps its number and the merged
    /// devices' numbers are retired and point to it.</item>
    /// <item><b>Aliases</b> (HardwareIdentifiers, type Alias): other names of the device, saved by a merge (for example
    /// W01.Contoso typed in a checklist for the ACAS host W01.Contoso.com).</item>
    /// </list>
    /// Every import goes through <see cref="DatabaseInterface.InsertHardware"/>, which calls <see cref="ResolveHost"/>
    /// first: when the incoming host is a known device, the DiscoveredHostName parameter is replaced by that record's
    /// name, so every later statement of the import uses it. A host is known by its host name, an alias, or the FQDN /
    /// NetBIOS name of a record (only when exactly one record matches). IP and MAC addresses are not used: they change
    /// and get reused.
    /// </summary>
    public static class HardwareIdentity
    {
        public const string AliasType = "Alias";

        /// <summary>Rewrites @DiscoveredHostName to the existing record's name when the host is a known device.</summary>
        public static void ResolveHost(SQLiteCommand importCommand)
        {
            string name = Text(importCommand, "DiscoveredHostName");
            if (name.Length == 0)
            { return; }
            // 1. A record with exactly this name.
            if (Scalar(importCommand, "SELECT DiscoveredHostName FROM Hardware WHERE DiscoveredHostName = @Value LIMIT 1", name) != null)
            { return; }
            // 2. A saved alias.
            string canonical = Scalar(importCommand,
                "SELECT H.DiscoveredHostName FROM HardwareIdentifiers HI JOIN Hardware H ON H.Hardware_ID = HI.Hardware_ID " +
                "WHERE HI.IdentifierType = 'Alias' AND HI.IdentifierValue = @Value COLLATE NOCASE LIMIT 1", name);
            // 3. One record whose FQDN or NetBIOS name is this name, or whose FQDN is this host's FQDN.
            if (canonical == null)
            {
                string fqdn = Text(importCommand, "FQDN");
                canonical = Unique(importCommand,
                    "SELECT DiscoveredHostName FROM Hardware WHERE FQDN = @Value COLLATE NOCASE OR NetBIOS = @Value COLLATE NOCASE " +
                    "OR (@Fqdn <> '' AND FQDN = @Fqdn COLLATE NOCASE) LIMIT 2", name, fqdn);
            }
            if (canonical != null && canonical != name)
            { importCommand.Parameters["DiscoveredHostName"].Value = canonical; }
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

        /// <summary>The single matching name, or null when none or more than one record matches.</summary>
        private static string Unique(SQLiteCommand importCommand, string sql, string value, string fqdn)
        {
            using (SQLiteCommand command = importCommand.Connection.CreateCommand())
            {
                command.Transaction = importCommand.Transaction;
                command.CommandText = sql;
                command.Parameters.AddWithValue("@Value", value);
                command.Parameters.AddWithValue("@Fqdn", fqdn ?? string.Empty);
                List<string> names = new List<string>();
                using (SQLiteDataReader reader = command.ExecuteReader())
                {
                    while (reader.Read())
                    { if (!reader.IsDBNull(0)) names.Add(Convert.ToString(reader.GetValue(0), CultureInfo.InvariantCulture)); }
                }
                return names.Count == 1 ? names[0] : null;
            }
        }

        private static string Text(SQLiteCommand command, string parameter)
        {
            if (!command.Parameters.Contains(parameter)) return string.Empty;
            object value = command.Parameters[parameter].Value;
            return value == null || value is DBNull ? string.Empty : Convert.ToString(value, CultureInfo.InvariantCulture).Trim();
        }

        /// <summary>Registry numbers and aliases per hardware record, for the Hardware list. Empty when the database cannot be read.</summary>
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
                        command.CommandText = "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name IN ('HardwareIdentifiers', 'DeviceRegistry')";
                        if (Convert.ToInt64(command.ExecuteScalar(), CultureInfo.InvariantCulture) < 2) return result;
                        command.CommandText = "SELECT Hardware_ID, IdentifierValue FROM HardwareIdentifiers WHERE IdentifierType = 'Alias' ORDER BY IdentifierValue";
                        using (SQLiteDataReader reader = command.ExecuteReader())
                        {
                            while (reader.Read())
                            { For(result, reader.GetValue(0)).Aliases.Add(Convert.ToString(reader.GetValue(1), CultureInfo.InvariantCulture)); }
                        }
                        command.CommandText = "SELECT Hardware_ID, RegistryNumber, Retired FROM DeviceRegistry ORDER BY RegistryNumber";
                        using (SQLiteDataReader reader = command.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                Identifiers identifiers = For(result, reader.GetValue(0));
                                long number = Convert.ToInt64(reader.GetValue(1), CultureInfo.InvariantCulture);
                                bool retired = !reader.IsDBNull(2) && Convert.ToInt64(reader.GetValue(2), CultureInfo.InvariantCulture) != 0;
                                if (retired) identifiers.RetiredNumbers.Add(DeviceRegistry.Format(number));
                                else if (!identifiers.RegistryNumber.HasValue) identifiers.RegistryNumber = number;
                            }
                        }
                    }
                }
            }
            catch (Exception exception)
            { LogWriter.LogErrorWithDebug("Unable to read the device registry numbers and aliases.", exception); }
            return result;
        }

        private static Identifiers For(Dictionary<long, Identifiers> result, object hardwareId)
        {
            long id = Convert.ToInt64(hardwareId, CultureInfo.InvariantCulture);
            Identifiers identifiers;
            if (!result.TryGetValue(id, out identifiers))
            {
                identifiers = new Identifiers();
                result[id] = identifiers;
            }
            return identifiers;
        }

        public sealed class Identifiers
        {
            public long? RegistryNumber { get; internal set; }
            /// <summary>Numbers of devices merged into this one (VUL-...).</summary>
            public List<string> RetiredNumbers { get; } = new List<string>();
            public List<string> Aliases { get; } = new List<string>();
        }
    }

    /// <summary>
    /// The permanent device registry: VUL-000123 per device. AUTOINCREMENT, so a number is never given out twice, even
    /// after a device is deleted. A trigger numbers every new hardware record, whichever import or edit adds it.
    /// </summary>
    public static class DeviceRegistry
    {
        public const string Prefix = "VUL-";

        private static readonly string[] Setup =
        {
            "CREATE TABLE IF NOT EXISTS DeviceRegistry (RegistryNumber INTEGER PRIMARY KEY AUTOINCREMENT, Hardware_ID INTEGER NOT NULL, " +
            "Retired INTEGER NOT NULL DEFAULT 0, AssignedOn DATETIME)",
            "CREATE INDEX IF NOT EXISTS DeviceRegistry_Hardware_Index ON DeviceRegistry (Hardware_ID)",
            "CREATE TRIGGER IF NOT EXISTS DeviceRegistry_NewHardware AFTER INSERT ON Hardware BEGIN " +
            "INSERT INTO DeviceRegistry (Hardware_ID, Retired, AssignedOn) VALUES (NEW.Hardware_ID, 0, strftime('%Y-%m-%d %H:%M:%S', 'now', 'localtime')); END",
            // Records from before the registry, in the order they were added.
            "INSERT INTO DeviceRegistry (Hardware_ID, Retired, AssignedOn) SELECT H.Hardware_ID, 0, strftime('%Y-%m-%d %H:%M:%S', 'now', 'localtime') FROM Hardware H " +
            "WHERE NOT EXISTS (SELECT 1 FROM DeviceRegistry R WHERE R.Hardware_ID = H.Hardware_ID AND R.Retired = 0) ORDER BY H.Hardware_ID",
            // 7.5.0-beta.3 stored ACAS host IDs from the TAG host property; matching no longer uses them.
            "DELETE FROM HardwareIdentifiers WHERE IdentifierType = 'AcasHostId'"
        };

        /// <summary>Creates the registry and numbers any record without a number (run at every start).</summary>
        public static void Ensure(SQLiteCommand command)
        {
            command.Parameters.Clear();
            foreach (string sql in Setup)
            {
                command.CommandText = sql;
                command.ExecuteNonQuery();
            }
        }

        /// <summary>123 -> "VUL-000123".</summary>
        public static string Format(long number) => Prefix + number.ToString("D6", CultureInfo.InvariantCulture);

        /// <summary>"VUL-000123", "vul-123" or "123" -> 123; null when it is not a registry number.</summary>
        public static long? Parse(string text)
        {
            string value = (text ?? string.Empty).Trim();
            if (value.StartsWith(Prefix, StringComparison.OrdinalIgnoreCase)) value = value.Substring(Prefix.Length);
            long number;
            return long.TryParse(value, NumberStyles.None, CultureInfo.InvariantCulture, out number) && number > 0 ? number : (long?)null;
        }
    }
}
