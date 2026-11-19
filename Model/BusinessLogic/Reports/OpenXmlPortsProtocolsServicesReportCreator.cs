using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.Globalization;
using System.Linq;
using Vulnerator.Helper;
using Vulnerator.Model.DataAccess;

namespace Vulnerator.Model.BusinessLogic.Reports
{
    /// <summary>
    /// "Ports, Protocols &amp; Services": the ports, protocols and services ACAS / Nessus scans observed, as a starting
    /// point for the system's PPSM registration. Sheet 1 has one row per port / protocol / service with its hosts and the
    /// Nessus plugins that showed it; sheet 2 one row per host and port. Only the group filter applies (hosts in the
    /// selected groups).
    /// </summary>
    public class OpenXmlPortsProtocolsServicesReportCreator
    {
        public const string ReportName = "Ports, Protocols & Services";

        public static readonly string[] ServiceHeaders =
        {
            "Port", "Protocol", "Service (as detected)", "Service Name", "Service Acronym", "Host Count", "Hosts",
            "IP Addresses", "Groups", "Detected By (Nessus plugins)"
        };

        public static readonly string[] HostHeaders =
        {
            "Host Name", "IP Address", "Groups", "Port", "Protocol", "Service (as detected)", "Service Name",
            "Detected By (Nessus plugins)"
        };

        private const string Query = @"
SELECT PPS.Port, PPS.Protocol, PPS.DiscoveredServiceName, PPS.DisplayedServiceName, PPS.ServiceAcronym,
       COALESCE(H.DisplayedHostName, H.DiscoveredHostName) AS HostName,
       COALESCE((SELECT GROUP_CONCAT(IpAddress, ', ') FROM (SELECT DISTINCT IA.IP_Address AS IpAddress FROM Hardware_IP_Addresses HIA
                   JOIN IP_Addresses IA ON HIA.IP_Address_ID = IA.IP_Address_ID WHERE HIA.Hardware_ID = H.Hardware_ID ORDER BY 1)), H.ScanIP, '') AS IpAddresses,
       (SELECT GROUP_CONCAT(GroupName, ', ') FROM (SELECT DISTINCT G.GroupName FROM HardwareGroups HG2
            JOIN Groups G ON HG2.Group_ID = G.Group_ID WHERE HG2.Hardware_ID = H.Hardware_ID ORDER BY 1)) AS GroupNames,
       (SELECT GROUP_CONCAT(Plugin, '; ') FROM (SELECT DISTINCT E.PluginId || COALESCE(' ' || NULLIF(E.PluginName, ''), '') AS Plugin
            FROM PortProtocolServiceEvidence E WHERE E.HardwarePortProtocolService_ID = HPPS.HardwarePortProtocolService_ID ORDER BY 1)) AS Plugins
FROM HardwarePortsProtocolsServices HPPS
         JOIN PortsProtocolsServices PPS ON HPPS.PortProtocolService_ID = PPS.PortProtocolService_ID
         JOIN Hardware H ON HPPS.Hardware_ID = H.Hardware_ID
WHERE PPS.Port > 0 /*GROUPS*/
ORDER BY PPS.Port, PPS.Protocol, PPS.DiscoveredServiceName, HostName";

        public class Entry
        {
            public int Port { get; set; }
            public string Protocol { get; set; }
            public string DetectedService { get; set; }
            public string ServiceName { get; set; }
            public string Acronym { get; set; }
            public string Host { get; set; }
            public string IpAddresses { get; set; }
            public string Groups { get; set; }
            public string Plugins { get; set; }
        }

        public string CreatePortsProtocolsServicesReport(string fileName)
        {
            try
            {
                List<Entry> entries = Load();
                Write(fileName, entries, Properties.Settings.Default.EmassClassificationMarking);
                LogWriter.LogStatusUpdate($"Ports, Protocols & Services: {entries.Count} host / port row(s) written to '{fileName}'.");
                return "Excel report creation successful";
            }
            catch (Exception exception)
            {
                LogWriter.LogErrorWithDebug($"Unable to create '{fileName}' (Ports, Protocols & Services).", exception);
                return "Excel report creation failed - see log for details";
            }
        }

        public static List<Entry> Load()
        {
            bool wasOpen = DatabaseBuilder.sqliteConnection.State == System.Data.ConnectionState.Open;
            if (!wasOpen)
            { DatabaseBuilder.sqliteConnection.Open(); }
            try
            {
                string groups;
                using (SQLiteCommand filterCommand = DatabaseBuilder.sqliteConnection.CreateCommand())
                {
                    filterCommand.Parameters.Add(new SQLiteParameter("UserName", DatabaseBuilder.CurrentUser()));
                    groups = new FilterTextCreator().Group(filterCommand, ReportName);
                }
                string groupCondition = string.IsNullOrWhiteSpace(groups)
                    ? string.Empty
                    : "AND EXISTS (SELECT 1 FROM HardwareGroups HG WHERE HG.Hardware_ID = H.Hardware_ID AND " + groups.Trim() + ")";

                List<Entry> entries = new List<Entry>();
                using (SQLiteCommand command = DatabaseBuilder.sqliteConnection.CreateCommand())
                {
                    command.CommandText = Query.Replace("/*GROUPS*/", groupCondition);
                    using (SQLiteDataReader reader = command.ExecuteReader())
                    {
                        while (reader.Read())
                        {
                            entries.Add(new Entry
                            {
                                Port = Convert.ToInt32(reader.GetValue(0), CultureInfo.InvariantCulture),
                                Protocol = Text(reader, 1),
                                DetectedService = Text(reader, 2),
                                ServiceName = Text(reader, 3),
                                Acronym = Text(reader, 4),
                                Host = Text(reader, 5),
                                IpAddresses = Text(reader, 6),
                                Groups = Text(reader, 7),
                                Plugins = Text(reader, 8)
                            });
                        }
                    }
                }
                return entries;
            }
            finally
            {
                if (!wasOpen)
                { DatabaseBuilder.sqliteConnection.Close(); }
            }
        }

        public static void Write(string fileName, List<Entry> entries, string marking)
        {
            using (EmassWorkbookWriter workbook = new EmassWorkbookWriter(fileName, marking))
            {
                EmassSheet services = workbook.AddSheet("Ports Protocols Services", new double[] { 8, 10, 22, 26, 14, 10, 40, 30, 24, 60 });
                for (int c = 0; c < ServiceHeaders.Length; c++)
                { services.Text(1, c + 1, ServiceHeaders[c], EmassWorkbookWriter.StyleColumnHeader); }
                int row = 2;
                foreach (IGrouping<string, Entry> service in entries
                             .GroupBy(e => e.Port.ToString(CultureInfo.InvariantCulture) + "/" + e.Protocol + "/" + e.DetectedService)
                             .OrderBy(g => g.First().Port).ThenBy(g => g.First().Protocol).ThenBy(g => g.First().DetectedService))
                {
                    Entry first = service.First();
                    List<Entry> hosts = service.OrderBy(e => e.Host, StringComparer.OrdinalIgnoreCase).ToList();
                    int c = 1;
                    services.Text(row, c++, first.Port.ToString(CultureInfo.InvariantCulture));
                    services.Text(row, c++, first.Protocol.ToUpperInvariant());
                    services.Text(row, c++, first.DetectedService);
                    services.Text(row, c++, first.ServiceName);
                    services.Text(row, c++, first.Acronym);
                    services.Text(row, c++, hosts.Select(h => h.Host).Distinct(StringComparer.OrdinalIgnoreCase).Count().ToString(CultureInfo.InvariantCulture));
                    services.Text(row, c++, string.Join(", ", hosts.Select(h => h.Host).Distinct(StringComparer.OrdinalIgnoreCase)));
                    services.Text(row, c++, JoinDistinct(hosts.Select(h => h.IpAddresses)));
                    services.Text(row, c++, JoinDistinct(hosts.Select(h => h.Groups)));
                    services.Text(row, c, JoinDistinct(hosts.Select(h => h.Plugins), "; "));
                    row++;
                }
                services.FrozenRows = 1;
                services.AutoFilter = "A1:" + EmassSheet.ColumnName(ServiceHeaders.Length) + Math.Max(1, row - 1).ToString(CultureInfo.InvariantCulture);
                services.Save();

                EmassSheet byHost = workbook.AddSheet("By Host", new double[] { 28, 26, 24, 8, 10, 22, 26, 60 });
                for (int c = 0; c < HostHeaders.Length; c++)
                { byHost.Text(1, c + 1, HostHeaders[c], EmassWorkbookWriter.StyleColumnHeader); }
                row = 2;
                foreach (Entry entry in entries.OrderBy(e => e.Host, StringComparer.OrdinalIgnoreCase).ThenBy(e => e.Port).ThenBy(e => e.Protocol))
                {
                    int c = 1;
                    byHost.Text(row, c++, entry.Host);
                    byHost.Text(row, c++, entry.IpAddresses);
                    byHost.Text(row, c++, entry.Groups);
                    byHost.Text(row, c++, entry.Port.ToString(CultureInfo.InvariantCulture));
                    byHost.Text(row, c++, entry.Protocol.ToUpperInvariant());
                    byHost.Text(row, c++, entry.DetectedService);
                    byHost.Text(row, c++, entry.ServiceName);
                    byHost.Text(row, c, entry.Plugins);
                    row++;
                }
                byHost.FrozenRows = 1;
                byHost.AutoFilter = "A1:" + EmassSheet.ColumnName(HostHeaders.Length) + Math.Max(1, row - 1).ToString(CultureInfo.InvariantCulture);
                byHost.Save();
            }
        }

        private static string JoinDistinct(IEnumerable<string> values, string separator = ", ")
        {
            string[] split = separator == "; " ? new[] { "; " } : new[] { ", " };
            return string.Join(separator, values
                .Where(v => !string.IsNullOrWhiteSpace(v))
                .SelectMany(v => v.Split(split, StringSplitOptions.RemoveEmptyEntries))
                .Select(v => v.Trim())
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(v => v, StringComparer.OrdinalIgnoreCase));
        }

        private static string Text(SQLiteDataReader reader, int ordinal)
        {
            return reader.IsDBNull(ordinal) ? string.Empty : Convert.ToString(reader.GetValue(ordinal), CultureInfo.InvariantCulture);
        }
    }
}
