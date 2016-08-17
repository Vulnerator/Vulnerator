using System;

namespace Vulnerator.Model
{
    public class WorkingSystem
    {
        public DateTime StartTime { get; set; }

        public DateTime EndTime { get; set; }

        public string IpAddress = string.Empty;

        public string HostName = string.Empty;

        public string OperatingSystem = string.Empty;

        public string CredentialedScan = string.Empty;

        public WorkingSystem()
        { }

        public void SetStartTime(DateTime startTime)
        { this.StartTime = startTime; }

        public void SetEndTime(DateTime endTime)
        { this.EndTime = endTime; }

        public void SetIpAddress(string ipAddress)
        { this.IpAddress = ipAddress; }

        public void SetHostName(string hostName)
        { this.HostName = hostName; }

        public void SetCredentialedScan(string credentialedValue)
        { this.CredentialedScan = credentialedValue; }

        public void SetOperatingSystem(string operatingSystem)
        { this.OperatingSystem = operatingSystem; }
    }
}
