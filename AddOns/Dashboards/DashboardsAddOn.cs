// Copyright (c) 2026 Hector L. Bones. MIT License (see LICENSE in the repository root).
using System;
using System.Reflection;
using System.Threading.Tasks;
using Vulnerator.AddOns;
using Vulnerator.Metrics;

[assembly: VulneratorAddOn(typeof(Vulnerator.Dashboards.DashboardsAddOn), ApiVersion = 3, MinimumCoreVersion = "7.4.0")]

namespace Vulnerator.Dashboards
{
    /// <summary>
    /// Dashboards: offline dashboards inside Vulnerator. Part of Vulnerator 2.0 (MIT); it ships in the release zip.
    /// </summary>
    public sealed class DashboardsAddOn : IAddOn
    {
        public const string AddOnId = "dashboards";
        private readonly object trendLock = new object();
        private IAddOnHost host;
        private TrendStore trend;
        private DeviceMatchStore matching;

        public string Id => AddOnId;
        public string Name => "Dashboards";
        /// <summary>"1.0.0" (the build's "+commit" suffix is left out of what Settings shows).</summary>
        public string Version => (typeof(DashboardsAddOn).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion ?? "1.0.0").Split('+')[0];
        public string Description => "Offline dashboards: severity, top hosts, compliance by control family, POA&M aging, trend, coverage gaps (with device matching), STIG currency and active IAVMs.";

        public void Initialize(IAddOnHost host)
        {
            this.host = host ?? throw new ArgumentNullException(nameof(host));
            trend = new TrendStore(host.DataFolder);
            matching = new DeviceMatchStore(host.DataFolder);
            host.DataChanged += (sender, e) => Task.Run(() => RecordTrend());
            host.AddPage("Dashboards", "ChartBar", () => new DashboardView(new HostDashboardSource(this)));
        }

        /// <summary>Reads everything the views need and records today's trend snapshot.</summary>
        internal DashboardModel Load()
        {
            IFindingsData data = host.Data;
            var input = new DashboardInput
            {
                Findings = ContractAdapter.Findings(data),
                Hardware = ContractAdapter.Hardware(data),
                Submissions = ContractAdapter.Submissions(data),
                PoamItems = ContractAdapter.PoamItems(data),
                LibraryImported = data.GetLastStigLibraryImport(),
                Matching = matching.Load(),
                Now = DateTime.Now
            };
            lock (trendLock)
            {
                try
                {
                    trend.Record(input.Findings, input.Now);
                }
                catch (Exception ex)
                {
                    host.Log.Warning("The trend snapshot could not be saved: " + ex.Message);
                }
                input.Trend = trend.Load();
            }
            return DashboardModel.Build(input, host.ClassificationMarking);
        }

        private void RecordTrend()
        {
            try
            {
                var findings = ContractAdapter.Findings(host.Data);
                lock (trendLock) trend.Record(findings, DateTime.Now);
            }
            catch (Exception ex)
            {
                host.Log.Warning("The trend snapshot could not be saved: " + ex.Message);
            }
        }

        private sealed class HostDashboardSource : IDashboardSource, IDeviceMatchEditor
        {
            private readonly DashboardsAddOn addOn;

            public HostDashboardSource(DashboardsAddOn addOn)
            {
                this.addOn = addOn;
            }

            public DashboardModel Load() => addOn.Load();

            public void SaveMatching(DeviceMatchSettings settings) => addOn.matching.Save(settings);
        }
    }
}
