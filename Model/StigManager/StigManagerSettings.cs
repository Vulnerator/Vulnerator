using System;
using System.Security.Cryptography;
using System.Text;

namespace Vulnerator.Model.StigManager
{
    /// <summary>
    /// The STIG Manager connection settings (Settings &gt; STIG Manager and the pull window). A service-account
    /// secret is kept only when the user asks, encrypted with Windows DPAPI for the current Windows account.
    /// </summary>
    public static class StigManagerSettings
    {
        private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("Vulnerator.StigManager.v1");

        public static bool Enabled => Vulnerator.Properties.Settings.Default.StigManagerEnabled;

        /// <summary>The remembered client secret, or empty when none is stored or it cannot be decrypted here.</summary>
        public static string LoadSecret()
        {
            string stored = Vulnerator.Properties.Settings.Default.StigManagerClientSecret;
            if (string.IsNullOrEmpty(stored))
            { return string.Empty; }
            try
            { return Encoding.UTF8.GetString(ProtectedData.Unprotect(Convert.FromBase64String(stored), Entropy, DataProtectionScope.CurrentUser)); }
            catch (Exception)
            { return string.Empty; }
        }

        /// <summary>Remembers the secret (encrypted for this Windows account), or forgets it when empty.</summary>
        public static void SaveSecret(string secret)
        {
            Vulnerator.Properties.Settings.Default.StigManagerClientSecret = string.IsNullOrEmpty(secret)
                ? string.Empty
                : Convert.ToBase64String(ProtectedData.Protect(Encoding.UTF8.GetBytes(secret), Entropy, DataProtectionScope.CurrentUser));
        }
    }
}
