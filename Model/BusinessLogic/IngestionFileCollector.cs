using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Linq;
using Vulnerator.Helper;

namespace Vulnerator.Model.BusinessLogic
{
    /// <summary>
    /// Turns what the user picked for ingestion (files, zip files, folders) into the list of scan / checklist files to
    /// process. Folders are searched with their subfolders, zips (and zips inside zips or folders) are extracted to a
    /// working folder under %TEMP%, and only the requested extensions are kept.
    /// With <see cref="SkipPreviousFolders"/>, anything under a folder named "Previous" inside a picked folder or zip is
    /// left out: Evaluate-STIG keeps earlier results there, while the current ones are in the "Checklist" folder.
    /// </summary>
    public class IngestionFileCollector
    {
        public const string PreviousFolderName = "Previous";
        private const int MaximumZipDepth = 5;

        private readonly string[] _extensions;
        private readonly HashSet<string> _seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        /// <param name="extensions">Extensions to keep, with the dot (".cklb").</param>
        public IngestionFileCollector(params string[] extensions)
        { _extensions = extensions.Select(e => e.StartsWith(".") ? e : "." + e).ToArray(); }

        public bool SkipPreviousFolders { get; set; }

        /// <summary>Where zips are extracted; defaults to a new folder under <see cref="WorkingRoot"/>.</summary>
        public string ExtractionFolder { get; set; }

        /// <summary>The files found, in a stable order, with the name to show for each.</summary>
        public List<CollectedFile> Files { get; } = new List<CollectedFile>();

        /// <summary>Files left out because they were under a "Previous" folder.</summary>
        public int SkippedPrevious { get; private set; }

        /// <summary>Zip files that could not be read.</summary>
        public List<string> UnreadableZips { get; } = new List<string>();

        public static string WorkingRoot =>
            Path.Combine(Path.GetTempPath(), "Vulnerator", "Ingestion");

        public void Add(IEnumerable<string> paths)
        {
            foreach (string path in paths.Where(p => !string.IsNullOrWhiteSpace(p)))
            { Add(path); }
        }

        public void Add(string path)
        {
            if (Directory.Exists(path))
            { AddDirectory(path); }
            else if (IsZip(path))
            { AddZip(path, Path.GetFileNameWithoutExtension(path)); }
            else if (System.IO.File.Exists(path) && HasWantedExtension(path))
            { AddFile(path, Path.GetFileNameWithoutExtension(path)); }
        }

        private void AddDirectory(string root)
        {
            string fullRoot = Path.GetFullPath(root).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            IEnumerable<string> files;
            try
            { files = Directory.EnumerateFiles(fullRoot, "*", SearchOption.AllDirectories).OrderBy(f => f, StringComparer.OrdinalIgnoreCase).ToList(); }
            catch (Exception exception)
            {
                LogWriter.LogErrorWithDebug($"Unable to search folder '{root}'.", exception);
                return;
            }
            foreach (string file in files)
            {
                string relative = file.Substring(fullRoot.Length).TrimStart(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                bool wanted = IsZip(file) || HasWantedExtension(file);
                if (!wanted)
                { continue; }
                if (SkipPreviousFolders && IsUnderPreviousFolder(relative))
                {
                    SkippedPrevious++;
                    continue;
                }
                if (IsZip(file))
                { AddZip(file, Path.GetFileNameWithoutExtension(file)); }
                else
                { AddFile(file, Path.GetFileNameWithoutExtension(file)); }
            }
        }

        private void AddZip(string zipPath, string displayPrefix)
        {
            try
            {
                using (ZipArchive zipArchive = ZipFile.OpenRead(zipPath))
                { AddZipEntries(zipArchive, NewExtractionFolder(displayPrefix), displayPrefix, 1); }
            }
            catch (Exception exception)
            {
                UnreadableZips.Add(zipPath);
                LogWriter.LogErrorWithDebug($"Unable to read zip file '{zipPath}'.", exception);
            }
        }

        private void AddZipEntries(ZipArchive zipArchive, string folder, string displayPrefix, int depth)
        {
            foreach (ZipArchiveEntry entry in zipArchive.Entries.OrderBy(e => e.FullName, StringComparer.OrdinalIgnoreCase))
            {
                if (string.IsNullOrEmpty(entry.Name))
                { continue; } // folder entry
                string entryPath = entry.FullName.Replace('\\', '/');
                bool isZip = IsZip(entryPath);
                if (!isZip && !HasWantedExtension(entryPath))
                { continue; }
                if (SkipPreviousFolders && IsUnderPreviousFolder(entryPath))
                {
                    SkippedPrevious++;
                    continue;
                }
                string target = SafeTarget(folder, entryPath);
                if (target == null)
                {
                    LogWriter.LogError($"Zip entry '{entry.FullName}' in '{displayPrefix}' has an unsafe path; skipped.");
                    continue;
                }
                string display = displayPrefix + "\\" + Path.GetFileNameWithoutExtension(entry.Name);
                if (isZip)
                {
                    if (depth >= MaximumZipDepth)
                    { continue; }
                    using (Stream stream = entry.Open())
                    using (MemoryStream buffer = new MemoryStream())
                    {
                        stream.CopyTo(buffer);
                        buffer.Position = 0;
                        try
                        {
                            using (ZipArchive inner = new ZipArchive(buffer, ZipArchiveMode.Read))
                            {
                                string innerFolder = Path.Combine(Path.GetDirectoryName(target), Path.GetFileNameWithoutExtension(target));
                                AddZipEntries(inner, innerFolder, display, depth + 1);
                            }
                        }
                        catch (InvalidDataException)
                        { UnreadableZips.Add(displayPrefix + "\\" + entry.FullName); }
                    }
                    continue;
                }
                Directory.CreateDirectory(Path.GetDirectoryName(target));
                entry.ExtractToFile(target, true);
                AddFile(target, display);
            }
        }

        private void AddFile(string path, string displayName)
        {
            string full = Path.GetFullPath(path);
            if (!_seen.Add(full))
            { return; }
            Files.Add(new CollectedFile(full, displayName));
        }

        private string NewExtractionFolder(string name)
        {
            string root = ExtractionFolder ?? Path.Combine(WorkingRoot, DateTime.Now.ToString("yyyyMMdd-HHmmss") + "-" + Guid.NewGuid().ToString("N").Substring(0, 8));
            string folder = Path.Combine(root, SafeName(name));
            int suffix = 1;
            while (Directory.Exists(folder))
            { folder = Path.Combine(root, SafeName(name) + "_" + ++suffix); }
            Directory.CreateDirectory(folder);
            return folder;
        }

        private static string SafeName(string name)
        {
            foreach (char c in Path.GetInvalidFileNameChars())
            { name = name.Replace(c, '_'); }
            return string.IsNullOrWhiteSpace(name) ? "zip" : name;
        }

        /// <summary>The extraction path for an entry, or null when it would land outside the folder.</summary>
        private static string SafeTarget(string folder, string entryPath)
        {
            string[] parts = entryPath.Split(new[] { '/' }, StringSplitOptions.RemoveEmptyEntries)
                .Select(SafeName).ToArray();
            if (parts.Length == 0 || parts.Any(p => p == "." || p == ".."))
            { return null; }
            string target = Path.GetFullPath(Path.Combine(new[] { folder }.Concat(parts).ToArray()));
            string root = Path.GetFullPath(folder).TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar;
            return target.StartsWith(root, StringComparison.OrdinalIgnoreCase) ? target : null;
        }

        /// <summary>True when a folder in the (relative) path is named "Previous"; the file name itself does not count.</summary>
        public static bool IsUnderPreviousFolder(string relativePath)
        {
            string[] parts = relativePath.Split(new[] { '/', '\\' }, StringSplitOptions.RemoveEmptyEntries);
            return parts.Take(parts.Length - 1).Any(p => string.Equals(p, PreviousFolderName, StringComparison.OrdinalIgnoreCase));
        }

        private bool HasWantedExtension(string path)
        { return _extensions.Any(e => path.EndsWith(e, StringComparison.OrdinalIgnoreCase)); }

        private static bool IsZip(string path)
        { return path.EndsWith(".zip", StringComparison.OrdinalIgnoreCase); }

        /// <summary>Removes extraction folders from earlier sessions (older than a day). Never throws.</summary>
        public static void CleanUpOldExtractions()
        {
            try
            {
                if (!Directory.Exists(WorkingRoot))
                { return; }
                foreach (string folder in Directory.GetDirectories(WorkingRoot))
                {
                    if (Directory.GetCreationTime(folder) < DateTime.Now.AddDays(-1))
                    {
                        try { Directory.Delete(folder, true); }
                        catch (Exception) { }
                    }
                }
            }
            catch (Exception)
            { }
        }

        public class CollectedFile
        {
            public CollectedFile(string path, string displayName)
            {
                Path = path;
                DisplayName = displayName;
            }

            public string Path { get; }
            public string DisplayName { get; }
        }
    }
}
