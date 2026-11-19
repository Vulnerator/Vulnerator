using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Text.RegularExpressions;
using Vulnerator.Helper;
using Vulnerator.Model.DataAccess;

namespace Vulnerator.Model.BusinessLogic
{
    /// <summary>
    /// Loads STIG benchmarks into the vulnerability library from a DISA STIG library zip (zips within zips), a single
    /// STIG zip, or one benchmark .xml (manual XCCDF or SCAP data stream).
    /// </summary>
    public class StigLibraryImporter
    {
        // Inside a library, SCAP content duplicates the manual benchmark, and OVAL / CPE / OCIL files are not benchmarks.
        private static readonly Regex SkippedInsideZip = new Regex(@"scap|oval|cpe|ocil", RegexOptions.IgnoreCase);

        public int Attempted { get; private set; }
        public int Parsed { get; private set; }
        public int Older { get; private set; }
        public int Failed { get; private set; }
        public int Rules { get; private set; }

        /// <summary>Called with the number of top-level items once the file is opened.</summary>
        public Action<int> TotalItems { get; set; }

        /// <summary>Called with each file name as it is ingested, and once per top-level item done (null).</summary>
        public Action<string> Progress { get; set; }

        /// <summary>Loads one library zip, STIG zip or benchmark .xml.</summary>
        public string Import(string path)
        { return Import(new[] { path }); }

        /// <summary>
        /// Loads one or more library zips, STIG zips or benchmark .xml files (for example the files written by
        /// <see cref="ExtractBenchmarks"/> where the library zip itself cannot be brought onto the machine).
        /// </summary>
        public string Import(params string[] paths)
        {
            Attempted = Parsed = Older = Failed = Rules = 0;
            List<string> files = paths.Where(p => !string.IsNullOrWhiteSpace(p)).ToList();
            int total = 0;
            foreach (string path in files)
            {
                if (path.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
                {
                    using (ZipArchive zipArchive = ZipFile.OpenRead(path))
                    { total += zipArchive.Entries.Count; }
                }
                else
                { total++; }
            }
            TotalItems?.Invoke(total);
            foreach (string path in files)
            {
                if (path.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
                {
                    using (ZipArchive zipArchive = ZipFile.OpenRead(path))
                    {
                        foreach (ZipArchiveEntry entry in zipArchive.Entries)
                        {
                            HandleEntry(entry);
                            Progress?.Invoke(null);
                        }
                    }
                }
                else
                {
                    using (FileStream stream = File.OpenRead(path))
                    { ReadBenchmark(stream, Path.GetFileName(path), true); }
                    Progress?.Invoke(null);
                }
            }
            string summary = $"Loaded {Parsed} STIG(s), {Rules} rule(s)" +
                             (Older > 0 ? $"; {Older} skipped (a newer release is already loaded)" : string.Empty) +
                             (Failed > 0 ? $"; {Failed} failed (see log)" : string.Empty) + ".";
            if (Parsed + Older > 0)
            {
                string source = files.Count == 1 ? Path.GetFileName(files[0]) : $"{files.Count} files";
                RecordImport(source, Parsed, Rules);
            }
            LogWriter.LogStatusUpdate(summary);
            return summary;
        }

        /// <summary>When a STIG library was last loaded into the current database (null: never).</summary>
        public static DateTime? LastLibraryImport()
        {
            // Never create a database file just by asking.
            if (!File.Exists(Properties.Settings.Default.Database))
            { return null; }
            try
            {
                if (DatabaseBuilder.sqliteConnection.State.ToString().Equals("Closed"))
                { DatabaseBuilder.sqliteConnection.Open(); }
                using (SQLiteCommand command = DatabaseBuilder.sqliteConnection.CreateCommand())
                {
                    command.CommandText = "SELECT MAX(ImportedOn) FROM StigLibraryImports;";
                    object value = command.ExecuteScalar();
                    if (value is DateTime)
                    { return (DateTime)value; }
                    if (value is long)
                    { return new DateTime((long)value); }
                    return null;
                }
            }
            catch (Exception exception)
            {
                LogWriter.LogErrorWithDebug("Unable to read the STIG library import history.", exception);
                return null;
            }
            finally
            { DatabaseBuilder.sqliteConnection.Close(); }
        }

        private static void RecordImport(string source, int stigs, int rules)
        {
            try
            {
                if (DatabaseBuilder.sqliteConnection.State.ToString().Equals("Closed"))
                { DatabaseBuilder.sqliteConnection.Open(); }
                using (SQLiteCommand command = DatabaseBuilder.sqliteConnection.CreateCommand())
                {
                    command.CommandText = "INSERT INTO StigLibraryImports (ImportedOn, Source, Stigs, Rules) VALUES (@On, @Source, @Stigs, @Rules);";
                    command.Parameters.Add(new SQLiteParameter("@On", System.Data.DbType.DateTime) { Value = DateTime.Now });
                    command.Parameters.AddWithValue("@Source", source);
                    command.Parameters.AddWithValue("@Stigs", stigs);
                    command.Parameters.AddWithValue("@Rules", rules);
                    command.ExecuteNonQuery();
                }
            }
            catch (Exception exception)
            { LogWriter.LogErrorWithDebug("Unable to record the STIG library import.", exception); }
            finally
            { DatabaseBuilder.sqliteConnection.Close(); }
        }

        /// <summary>
        /// Writes every STIG benchmark .xml in a library zip (zips within zips; SCAP / OVAL / CPE / OCIL skipped) to
        /// <paramref name="folder"/>, so only those files need to be moved to a machine where the zip is not allowed.
        /// Returns the number of files written.
        /// </summary>
        public static int ExtractBenchmarks(string zipPath, string folder)
        {
            Directory.CreateDirectory(folder);
            int written = 0;
            using (ZipArchive zipArchive = ZipFile.OpenRead(zipPath))
            {
                foreach (ZipArchiveEntry entry in zipArchive.Entries)
                { written += ExtractEntry(entry, folder); }
            }
            LogWriter.LogStatusUpdate($"Extracted {written} STIG benchmark file(s) from '{zipPath}' to '{folder}'.");
            return written;
        }

        private static int ExtractEntry(ZipArchiveEntry entry, string folder)
        {
            if (string.IsNullOrEmpty(entry.Name) || SkippedInsideZip.IsMatch(entry.Name))
            { return 0; }
            using (MemoryStream buffer = new MemoryStream())
            {
                using (Stream stream = entry.Open())
                { stream.CopyTo(buffer); }
                buffer.Position = 0;
                if (entry.Name.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
                {
                    int count = 0;
                    using (ZipArchive inner = new ZipArchive(buffer, ZipArchiveMode.Read))
                    {
                        foreach (ZipArchiveEntry innerEntry in inner.Entries)
                        { count += ExtractEntry(innerEntry, folder); }
                    }
                    return count;
                }
                if (!entry.Name.EndsWith(".xml", StringComparison.OrdinalIgnoreCase))
                { return 0; }
                // Only benchmarks: the first part of the file names a Benchmark element.
                byte[] head = new byte[Math.Min(buffer.Length, 16384)];
                buffer.Read(head, 0, head.Length);
                string start = System.Text.Encoding.UTF8.GetString(head);
                if (!Regex.IsMatch(start, @"<(\w+:)?Benchmark[\s>]"))
                { return 0; }
                string target = Path.Combine(folder, entry.Name);
                for (int i = 2; File.Exists(target); i++)
                { target = Path.Combine(folder, Path.GetFileNameWithoutExtension(entry.Name) + "_" + i + ".xml"); }
                File.WriteAllBytes(target, buffer.ToArray());
                return 1;
            }
        }

        private void HandleEntry(ZipArchiveEntry entry)
        {
            try
            {
                if (string.IsNullOrEmpty(entry.Name) || SkippedInsideZip.IsMatch(entry.Name))
                { return; }
                if (entry.Name.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
                {
                    using (MemoryStream buffer = new MemoryStream())
                    {
                        using (Stream stream = entry.Open())
                        { stream.CopyTo(buffer); }
                        buffer.Position = 0;
                        using (ZipArchive inner = new ZipArchive(buffer, ZipArchiveMode.Read))
                        {
                            foreach (ZipArchiveEntry innerEntry in inner.Entries)
                            { HandleEntry(innerEntry); }
                        }
                    }
                }
                else if (entry.Name.EndsWith(".xml", StringComparison.OrdinalIgnoreCase))
                {
                    using (Stream stream = entry.Open())
                    { ReadBenchmark(stream, entry.Name, false); }
                }
            }
            catch (Exception exception)
            {
                Failed++;
                LogWriter.LogErrorWithDebug($"Unable to read '{entry.FullName}' from the STIG library.", exception);
            }
        }

        private void ReadBenchmark(Stream stream, string name, bool selectedDirectly)
        {
            Progress?.Invoke(name);
            RawStigReader reader = new RawStigReader();
            string result = reader.ReadRawStig(stream, name);
            if (result == RawStigReader.Skipped && !selectedDirectly)
            { return; } // some other XML file in the library
            Attempted++;
            switch (result)
            {
                case RawStigReader.Parsed:
                    {
                        Parsed++;
                        Rules += reader.RulesRead;
                        break;
                    }
                case RawStigReader.Older:
                    {
                        Older++;
                        break;
                    }
                default:
                    {
                        Failed++;
                        break;
                    }
            }
        }
    }
}
