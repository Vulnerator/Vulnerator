using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.Globalization;
using System.IO;
using Vulnerator.Helper;

namespace Vulnerator.Model.DataAccess
{
    /// <summary>
    /// When each host was last seen in an ACAS / Nessus result and in a STIG checklist or SCAP (XCCDF) result: the
    /// newest LastObserved of its findings by finding type. Used by Configuration Management &gt; Hardware.
    /// </summary>
    public static class HardwareScanDates
    {
        public sealed class Dates
        {
            public DateTime? LastAcas { get; internal set; }
            public DateTime? LastChecklist { get; internal set; }
        }

        private const string Query =
            "SELECT UF.Hardware_ID, FT.FindingType, MAX(UF.LastObserved) FROM UniqueFindings UF " +
            "JOIN FindingTypes FT ON UF.FindingType_ID = FT.FindingType_ID " +
            "WHERE UF.Hardware_ID IS NOT NULL GROUP BY UF.Hardware_ID, FT.FindingType";

        /// <summary>Dates by Hardware_ID. Empty (never throws) when the database cannot be read.</summary>
        public static Dictionary<long, Dates> Load()
        {
            Dictionary<long, Dates> result = new Dictionary<long, Dates>();
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
                        command.CommandText = Query;
                        using (SQLiteDataReader reader = command.ExecuteReader())
                        {
                            while (reader.Read())
                            {
                                if (reader.IsDBNull(0)) continue;
                                long id = Convert.ToInt64(reader.GetValue(0), CultureInfo.InvariantCulture);
                                string type = reader.IsDBNull(1) ? string.Empty : Convert.ToString(reader.GetValue(1), CultureInfo.InvariantCulture);
                                DateTime? date = ToDate(reader.IsDBNull(2) ? null : reader.GetValue(2));
                                if (!date.HasValue) continue;
                                Dates dates;
                                if (!result.TryGetValue(id, out dates))
                                {
                                    dates = new Dates();
                                    result[id] = dates;
                                }
                                if (type.Equals("ACAS", StringComparison.OrdinalIgnoreCase))
                                { dates.LastAcas = Newer(dates.LastAcas, date.Value); }
                                else if (type.Equals("CKL", StringComparison.OrdinalIgnoreCase) || type.Equals("XCCDF", StringComparison.OrdinalIgnoreCase))
                                { dates.LastChecklist = Newer(dates.LastChecklist, date.Value); }
                            }
                        }
                    }
                }
            }
            catch (Exception exception)
            { LogWriter.LogErrorWithDebug("Unable to read the last scan dates for the Hardware list.", exception); }
            return result;
        }

        private static DateTime Newer(DateTime? current, DateTime candidate)
        { return current.HasValue && current.Value > candidate ? current.Value : candidate; }

        /// <summary>
        /// MAX() loses the column's DATETIME type, so the value comes back as stored: ticks (the database's date format),
        /// or text in databases written by other tools.
        /// </summary>
        public static DateTime? ToDate(object value)
        {
            if (value == null || value is DBNull) return null;
            if (value is DateTime) return (DateTime)value;
            if (value is long || value is int)
            {
                long ticks = Convert.ToInt64(value, CultureInfo.InvariantCulture);
                if (ticks > DateTime.MinValue.Ticks && ticks < DateTime.MaxValue.Ticks && ticks > new DateTime(1990, 1, 1).Ticks) return new DateTime(ticks);
                return null;
            }
            DateTime parsed;
            return DateTime.TryParse(Convert.ToString(value, CultureInfo.InvariantCulture), CultureInfo.InvariantCulture, DateTimeStyles.None, out parsed)
                ? parsed : (DateTime?)null;
        }
    }
}
