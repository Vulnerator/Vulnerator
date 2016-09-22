using System;

namespace Vulnerator.Model
{
    public class WorkingSystem
    {
        public DateTime StartTime { get; set; }

        public DateTime EndTime { get; set; }

        public string IpAddress = string.Empty;

        public string HostName = string.Empty;

        public string NetBiosName = string.Empty;

        public string OperatingSystem = string.Empty;

        public string CredentialedScan = string.Empty;

        public WorkingSystem()
        { }

        public void SetStartTime(DateTime startTime)
        { StartTime = startTime; }

        public void SetEndTime(DateTime endTime)
        { EndTime = endTime; }

        public void SetIpAddress(string ipAddress)
        { IpAddress = ipAddress; }

        public void SetHostName(string hostName)
        { HostName = hostName; }

        public void SetNetBiosName(string netBiosName)
        { NetBiosName = netBiosName; }

        public void SetCredentialedScan(string credentialedValue)
        { CredentialedScan = credentialedValue; }

        public void SetOperatingSystem(string operatingSystem)
        { OperatingSystem = operatingSystem; }
    }
}
