using System.Diagnostics;
using System.Linq;
using System.Reflection;

namespace Vulnerator.Helper
{
    /// <summary>The version shown to people: the release the build was published as (for example "7.3.0" or "7.3.0-beta.1").</summary>
    public static class AppVersion
    {
        public const string ProductName = "Vulnerator 2.0";

        /// <summary>The release version stamped by the build (AssemblyInformationalVersion), else the file version.</summary>
        public static string Display
        {
            get
            {
                Assembly assembly = typeof(AppVersion).Assembly;
                string informational = assembly.GetCustomAttributes(typeof(AssemblyInformationalVersionAttribute), false)
                    .OfType<AssemblyInformationalVersionAttribute>().Select(a => a.InformationalVersion).FirstOrDefault();
                if (!string.IsNullOrWhiteSpace(informational))
                { return informational.Trim(); }
                return FileVersionInfo.GetVersionInfo(assembly.Location).FileVersion;
            }
        }

        /// <summary>"Vulnerator 2.0 (version 7.3.0)".</summary>
        public static string FullName => ProductName + " (version " + Display + ")";
    }
}
