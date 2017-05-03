using System;

namespace Vulnerator.Model.Object
{
    public class WorkingSystem
    {
        public DateTime StartTime { get; set; }

        public DateTime EndTime { get; set; }

        public string IpAddress = string.Empty;

        public string HostName = string.Empty;

        public string FQDN = string.Empty;

        public string Role = string.Empty;

        public string TechArea = string.Empty;

        public string NetBiosName = string.Empty;

        public string OperatingSystem = string.Empty;

        public string CredentialedScan = string.Empty;

        public string AssetType = string.Empty;

        public string Site = string.Empty;

        public string Instance = string.Empty;

        public WorkingSystem()
        { }
    }
}
