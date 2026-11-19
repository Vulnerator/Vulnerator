// Copyright (c) 2026 Hector L. Bones. MIT License (see LICENSE in the repository root).
// View 5 (open vs. closed trend): Vulnerator keeps only the current state, so the add-on records a snapshot after
// each import (IAddOnHost.DataChanged) in its data folder.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;
using System.Text;

namespace Vulnerator.Metrics
{
    [DataContract]
    public sealed class TrendSnapshot
    {
        [DataMember(Order = 1)] public DateTime TakenOn { get; set; }

        /// <summary>Open findings per level (index = (int)SeverityLevel).</summary>
        [DataMember(Order = 2)] public int[] OpenByLevel { get; set; } = new int[6];

        [DataMember(Order = 3)] public int Unverified { get; set; }
        [DataMember(Order = 4)] public int NotAFinding { get; set; }

        /// <summary>Open now that were not open or unverified in the previous snapshot.</summary>
        [DataMember(Order = 5)] public int NewlyOpen { get; set; }

        /// <summary>Open or unverified in the previous snapshot and neither now (Unverified is never counted as closed).</summary>
        [DataMember(Order = 6)] public int NewlyClosed { get; set; }

        /// <summary>Keys of open or unverified findings; kept on the newest two snapshots only (to compare with the next one,
        /// also when the newest is replaced later the same day).</summary>
        [DataMember(Order = 7, EmitDefaultValue = false)] public List<string> ActiveKeys { get; set; }

        public int Open => OpenByLevel?.Sum() ?? 0;
    }

    [DataContract]
    internal sealed class TrendFile
    {
        [DataMember(Order = 1)] public int Format { get; set; } = 1;
        [DataMember(Order = 2)] public List<TrendSnapshot> Snapshots { get; set; } = new List<TrendSnapshot>();
    }

    /// <summary>Snapshots in "trend.json" in a folder (the add-on's data folder). One per day; the newest of a day wins.</summary>
    public sealed class TrendStore
    {
        public const string FileName = "trend.json";
        private readonly string folder;
        private readonly int maxSnapshots;

        public TrendStore(string folder, int maxSnapshots = 365)
        {
            if (string.IsNullOrWhiteSpace(folder)) throw new ArgumentNullException(nameof(folder));
            this.folder = folder;
            this.maxSnapshots = Math.Max(2, maxSnapshots);
        }

        public string Path => System.IO.Path.Combine(folder, FileName);

        /// <summary>Snapshots, oldest first. A missing or damaged file gives an empty list (the trend starts again).</summary>
        public IList<TrendSnapshot> Load()
        {
            return Read().Snapshots;
        }

        /// <summary>Records the current state (findings already resolved) and returns the new snapshot.</summary>
        public TrendSnapshot Record(IEnumerable<MetricFinding> findings, DateTime now)
        {
            TrendFile file = Read();
            List<TrendSnapshot> snapshots = file.Snapshots;
            if (snapshots.Count > 0 && snapshots[snapshots.Count - 1].TakenOn.Date == now.Date) snapshots.RemoveAt(snapshots.Count - 1);
            TrendSnapshot previous = snapshots.Count > 0 ? snapshots[snapshots.Count - 1] : null;

            var snapshot = new TrendSnapshot { TakenOn = now };
            var active = new HashSet<string>(StringComparer.Ordinal);
            var open = new HashSet<string>(StringComparer.Ordinal);
            foreach (MetricFinding f in findings)
            {
                switch (f.EffectiveStatus)
                {
                    case EffectiveStatus.Open:
                        snapshot.OpenByLevel[(int)f.Level]++;
                        open.Add(f.Key);
                        active.Add(f.Key);
                        break;
                    case EffectiveStatus.Unverified:
                        snapshot.Unverified++;
                        active.Add(f.Key);
                        break;
                    case EffectiveStatus.NotAFinding:
                        snapshot.NotAFinding++;
                        break;
                }
            }
            if (previous != null && previous.ActiveKeys != null)
            {
                var before = new HashSet<string>(previous.ActiveKeys, StringComparer.Ordinal);
                snapshot.NewlyOpen = open.Count(k => !before.Contains(k));
                snapshot.NewlyClosed = before.Count(k => !active.Contains(k));
            }
            else
            {
                snapshot.NewlyOpen = open.Count;
            }
            snapshot.ActiveKeys = active.OrderBy(k => k, StringComparer.Ordinal).ToList();

            snapshots.Add(snapshot);
            if (snapshots.Count > maxSnapshots) snapshots.RemoveRange(0, snapshots.Count - maxSnapshots);
            for (int i = 0; i < snapshots.Count - 2; i++) snapshots[i].ActiveKeys = null;
            Write(file);
            return snapshot;
        }

        private TrendFile Read()
        {
            try
            {
                if (!File.Exists(Path)) return new TrendFile();
                using (FileStream stream = File.OpenRead(Path))
                {
                    var file = (TrendFile)new DataContractJsonSerializer(typeof(TrendFile)).ReadObject(stream);
                    if (file == null || file.Format != 1 || file.Snapshots == null) return new TrendFile();
                    file.Snapshots = file.Snapshots.Where(s => s != null && s.OpenByLevel != null && s.OpenByLevel.Length == 6)
                        .OrderBy(s => s.TakenOn).ToList();
                    return file;
                }
            }
            catch (Exception ex) when (ex is IOException || ex is SerializationException || ex is UnauthorizedAccessException || ex is InvalidCastException)
            {
                return new TrendFile();
            }
        }

        private void Write(TrendFile file)
        {
            Directory.CreateDirectory(folder);
            string temp = Path + ".tmp";
            using (var stream = new FileStream(temp, FileMode.Create, FileAccess.Write))
            {
                new DataContractJsonSerializer(typeof(TrendFile)).WriteObject(stream, file);
            }
            if (File.Exists(Path)) File.Replace(temp, Path, null);
            else File.Move(temp, Path);
        }
    }
}
