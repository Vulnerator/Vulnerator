// Copyright (c) 2026 Hector L. Bones. MIT License (see LICENSE in the repository root).
// Treats several Vulnerator hardware records as one device, for example "W01.Contoso.com" from an ACAS scan and
// "W01.Contoso" from a STIG checklist: automatically by short host name, and by links the user makes.
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.Serialization;
using System.Runtime.Serialization.Json;

namespace Vulnerator.Metrics
{
    /// <summary>Host names the user said are one device.</summary>
    [DataContract]
    public sealed class DeviceLink
    {
        [DataMember(Order = 1)] public List<string> Hosts { get; set; } = new List<string>();
    }

    /// <summary>How hardware records are matched into devices (kept in "device-links.json" in the add-on's data folder).</summary>
    [DataContract]
    public sealed class DeviceMatchSettings
    {
        [DataMember(Order = 1)] public int Format { get; set; } = 1;

        /// <summary>Hosts with the same short name (the part before the first dot) are one device. On by default.</summary>
        [DataMember(Order = 2)] public bool MatchShortNames { get; set; } = true;

        /// <summary>Links the user made.</summary>
        [DataMember(Order = 3)] public List<DeviceLink> Links { get; set; } = new List<DeviceLink>();

        /// <summary>Hosts the user keeps out of short-name matching (they can still be linked by hand).</summary>
        [DataMember(Order = 4)] public List<string> KeepSeparate { get; set; } = new List<string>();

        /// <summary>No matching at all: every hardware record is its own device.</summary>
        public static DeviceMatchSettings None => new DeviceMatchSettings { MatchShortNames = false };

        internal void Normalize()
        {
            if (Links == null) Links = new List<DeviceLink>();
            if (KeepSeparate == null) KeepSeparate = new List<string>();
            Links = Links.Where(l => l != null && l.Hosts != null)
                .Select(l => new DeviceLink { Hosts = l.Hosts.Where(h => !string.IsNullOrWhiteSpace(h)).Select(h => h.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).ToList() })
                .Where(l => l.Hosts.Count > 1).ToList();
            KeepSeparate = KeepSeparate.Where(h => !string.IsNullOrWhiteSpace(h)).Select(h => h.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        }

        /// <summary>Links two or more hosts as one device (merging with existing links that share a host).</summary>
        public void Link(IEnumerable<string> hosts)
        {
            Normalize();
            var set = new HashSet<string>((hosts ?? new string[0]).Where(h => !string.IsNullOrWhiteSpace(h)).Select(h => h.Trim()), StringComparer.OrdinalIgnoreCase);
            if (set.Count < 2) return;
            foreach (DeviceLink existing in Links.Where(l => l.Hosts.Any(set.Contains)).ToList())
            {
                set.UnionWith(existing.Hosts);
                Links.Remove(existing);
            }
            Links.Add(new DeviceLink { Hosts = set.OrderBy(h => h, StringComparer.OrdinalIgnoreCase).ToList() });
            KeepSeparate.RemoveAll(set.Contains);
        }

        /// <summary>Removes the hosts from every link and from short-name matching (each becomes its own device).</summary>
        public void Separate(IEnumerable<string> hosts)
        {
            Normalize();
            var set = new HashSet<string>((hosts ?? new string[0]).Where(h => !string.IsNullOrWhiteSpace(h)).Select(h => h.Trim()), StringComparer.OrdinalIgnoreCase);
            foreach (DeviceLink link in Links) link.Hosts.RemoveAll(set.Contains);
            Links.RemoveAll(l => l.Hosts.Count < 2);
            foreach (string host in set) if (!KeepSeparate.Contains(host, StringComparer.OrdinalIgnoreCase)) KeepSeparate.Add(host);
        }
    }

    /// <summary>Which hardware records make one device, and why.</summary>
    public sealed class DeviceGroup
    {
        public IList<MetricHardware> Members { get; } = new List<MetricHardware>();
        /// <summary>"", "short name", "linked" or "short name, linked".</summary>
        public string MatchedBy { get; set; } = string.Empty;
    }

    public static class DeviceMatching
    {
        /// <summary>"W01.Contoso.com" -> "w01". IP addresses and blank names are kept whole (lower case).</summary>
        public static string ShortName(string host)
        {
            string name = (host ?? string.Empty).Trim().ToLowerInvariant();
            if (name.Length == 0) return name;
            IPAddress ip;
            if (IPAddress.TryParse(name, out ip)) return name;
            int dot = name.IndexOf('.');
            return dot > 0 ? name.Substring(0, dot) : name;
        }

        /// <summary>Groups hardware records into devices. Records not matched to anything are a device of their own.</summary>
        public static IList<DeviceGroup> Group(IList<MetricHardware> hardware, DeviceMatchSettings settings)
        {
            settings = settings ?? DeviceMatchSettings.None;
            settings.Normalize();
            int n = hardware.Count;
            var parent = Enumerable.Range(0, n).ToArray();
            var reasons = new string[n];
            Func<int, int> find = null;
            find = i => parent[i] == i ? i : (parent[i] = find(parent[i]));
            Action<int, int, string> union = (a, b, why) =>
            {
                int ra = find(a), rb = find(b);
                reasons[a] = Add(reasons[a], why);
                reasons[b] = Add(reasons[b], why);
                if (ra != rb) parent[rb] = ra;
            };

            if (settings.MatchShortNames)
            {
                var separate = new HashSet<string>(settings.KeepSeparate, StringComparer.OrdinalIgnoreCase);
                var first = new Dictionary<string, int>(StringComparer.Ordinal);
                for (int i = 0; i < n; i++)
                {
                    string host = (hardware[i].HostName ?? string.Empty).Trim();
                    if (host.Length == 0 || separate.Contains(host)) continue;
                    string key = ShortName(host);
                    int other;
                    if (first.TryGetValue(key, out other)) union(other, i, "short name");
                    else first[key] = i;
                }
            }
            foreach (DeviceLink link in settings.Links)
            {
                var names = new HashSet<string>(link.Hosts, StringComparer.OrdinalIgnoreCase);
                List<int> members = Enumerable.Range(0, n).Where(i => names.Contains((hardware[i].HostName ?? string.Empty).Trim())).ToList();
                for (int k = 1; k < members.Count; k++) union(members[0], members[k], "linked");
            }

            var groups = new Dictionary<int, DeviceGroup>();
            for (int i = 0; i < n; i++)
            {
                int root = find(i);
                DeviceGroup group;
                if (!groups.TryGetValue(root, out group))
                {
                    group = new DeviceGroup();
                    groups[root] = group;
                }
                group.Members.Add(hardware[i]);
                foreach (string why in (reasons[i] ?? string.Empty).Split(new[] { ", " }, StringSplitOptions.RemoveEmptyEntries))
                    group.MatchedBy = Add(group.MatchedBy, why);
            }
            foreach (DeviceGroup group in groups.Values)
            {
                if (group.Members.Count == 1) group.MatchedBy = string.Empty;
                else group.MatchedBy = string.Join(", ", group.MatchedBy.Split(new[] { ", " }, StringSplitOptions.RemoveEmptyEntries).OrderByDescending(w => w == "short name"));
            }
            return groups.Values.ToList();
        }

        private static string Add(string list, string item)
        {
            if (string.IsNullOrEmpty(list)) return item;
            return list.Split(new[] { ", " }, StringSplitOptions.None).Contains(item) ? list : list + ", " + item;
        }
    }

    /// <summary>The matching settings in "device-links.json" in a folder (the add-on's data folder).</summary>
    public sealed class DeviceMatchStore
    {
        public const string FileName = "device-links.json";
        private readonly string folder;

        public DeviceMatchStore(string folder)
        {
            if (string.IsNullOrWhiteSpace(folder)) throw new ArgumentNullException(nameof(folder));
            this.folder = folder;
        }

        public string Path => System.IO.Path.Combine(folder, FileName);

        /// <summary>The saved settings; a missing or damaged file gives the defaults (short-name matching on, no links).</summary>
        public DeviceMatchSettings Load()
        {
            try
            {
                if (!File.Exists(Path)) return new DeviceMatchSettings();
                using (FileStream stream = File.OpenRead(Path))
                {
                    var settings = (DeviceMatchSettings)new DataContractJsonSerializer(typeof(DeviceMatchSettings)).ReadObject(stream);
                    if (settings == null || settings.Format != 1) return new DeviceMatchSettings();
                    settings.Normalize();
                    return settings;
                }
            }
            catch (Exception ex) when (ex is IOException || ex is SerializationException || ex is UnauthorizedAccessException || ex is InvalidCastException)
            {
                return new DeviceMatchSettings();
            }
        }

        public void Save(DeviceMatchSettings settings)
        {
            if (settings == null) throw new ArgumentNullException(nameof(settings));
            settings.Normalize();
            Directory.CreateDirectory(folder);
            string temp = Path + ".tmp";
            using (var stream = new FileStream(temp, FileMode.Create, FileAccess.Write))
            {
                new DataContractJsonSerializer(typeof(DeviceMatchSettings)).WriteObject(stream, settings);
            }
            if (File.Exists(Path)) File.Replace(temp, Path, null);
            else File.Move(temp, Path);
        }
    }
}
