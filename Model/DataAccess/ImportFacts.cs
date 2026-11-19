using System;
using System.Data.SQLite;
using Vulnerator.Helper;

namespace Vulnerator.Model.DataAccess
{
    /// <summary>
    /// Details kept at import time that the main tables lose (for add-ons, interface version 3): the ACAS risk factor
    /// (Critical and High both become CAT I) and the STIG release a checklist or SCAP result was submitted with (an older
    /// release is moved onto the newer loaded one). Runs in the import's transaction; a failure is logged and never stops
    /// the import.
    /// </summary>
    public static class ImportFacts
    {
        private const string RiskFactorSql =
            "INSERT INTO AcasRiskFactors (UniqueVulnerabilityIdentifier, RiskFactor) VALUES (@Id, @RiskFactor);";

        private const string SubmissionSql = @"
INSERT INTO StigSubmissions (FindingType, SourceName, SourceVersion, SourceRelease, BenchmarkDate, DiscoveredHostName,
                             FindingSourceFileName, ImportedOn)
VALUES (@FindingType, @SourceName, @SourceVersion, @SourceRelease, @BenchmarkDate, @Host, @File, @ImportedOn);";

        /// <summary>Keeps the Nessus risk factor (Critical, High, Medium, Low, None) of a plugin.</summary>
        public static void RecordRiskFactor(SQLiteCommand importCommand, string pluginId, string riskFactor)
        {
            if (string.IsNullOrWhiteSpace(pluginId) || string.IsNullOrWhiteSpace(riskFactor)) return;
            try
            {
                using (SQLiteCommand command = NewCommand(importCommand, RiskFactorSql))
                {
                    command.Parameters.AddWithValue("@Id", pluginId.Trim());
                    command.Parameters.AddWithValue("@RiskFactor", riskFactor.Trim());
                    command.ExecuteNonQuery();
                }
            }
            catch (Exception exception)
            { LogWriter.LogErrorWithDebug($"Unable to keep the risk factor of plugin '{pluginId}'.", exception); }
        }

        /// <summary>Keeps the STIG name, version, release and benchmark date as submitted, for one host and file.</summary>
        public static void RecordStigSubmission(SQLiteCommand importCommand, string findingType, object sourceName, object version,
            object release, object benchmarkDate, object hostName, object fileName)
        {
            string name = Convert.ToString(sourceName);
            if (string.IsNullOrWhiteSpace(name)) return;
            try
            {
                using (SQLiteCommand command = NewCommand(importCommand, SubmissionSql))
                {
                    command.Parameters.AddWithValue("@FindingType", findingType);
                    command.Parameters.AddWithValue("@SourceName", name.Trim());
                    command.Parameters.AddWithValue("@SourceVersion", Value(version));
                    command.Parameters.AddWithValue("@SourceRelease", Value(release));
                    SQLiteParameter date = command.Parameters.AddWithValue("@BenchmarkDate", benchmarkDate is DateTime ? benchmarkDate : DBNull.Value);
                    date.DbType = System.Data.DbType.DateTime;
                    command.Parameters.AddWithValue("@Host", Value(hostName));
                    command.Parameters.AddWithValue("@File", Value(fileName));
                    SQLiteParameter importedOn = command.Parameters.AddWithValue("@ImportedOn", DateTime.Now);
                    importedOn.DbType = System.Data.DbType.DateTime;
                    command.ExecuteNonQuery();
                }
            }
            catch (Exception exception)
            { LogWriter.LogErrorWithDebug($"Unable to keep the submitted release of '{name}'.", exception); }
        }

        /// <summary>The value of a parameter of the import command, or null when it has none.</summary>
        public static object Parameter(SQLiteCommand importCommand, string name)
        {
            return importCommand.Parameters.Contains(name) ? importCommand.Parameters[name].Value : null;
        }

        private static SQLiteCommand NewCommand(SQLiteCommand importCommand, string sql)
        {
            SQLiteCommand command = importCommand.Connection.CreateCommand();
            command.Transaction = importCommand.Transaction;
            command.CommandText = sql;
            return command;
        }

        private static object Value(object value)
        {
            if (value == null || value == DBNull.Value) return DBNull.Value;
            string text = Convert.ToString(value).Trim();
            return text.Length == 0 ? (object)DBNull.Value : text;
        }
    }
}
