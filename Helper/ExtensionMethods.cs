using log4net;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Data.SQLite;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Xml;
using Vulnerator.Model.Object;
using File = System.IO.File;

namespace Vulnerator.Helper
{
    public static class ExtensionMethods
    {
        private static readonly Dictionary<string, string> rawStatusDictionary = new Dictionary<string, string>
        {
            { "notafinding", "Completed" },
            { "not a finding", "Completed" },
            { "not_a_finding", "Completed" },
            { "not_reviewed", "Not Reviewed" },
            { "notreviewed", "Not Reviewed" },
            { "not reviewed", "Not Reviewed" },
            { "not applicable", "Not Applicable" },
            { "open", "Ongoing" },
            { "not_applicable", "Not Applicable" },
            { "pass", "Completed" },
            { "fail", "Ongoing" },
            { "error", "Error" },
            { "unknown", "Not Reviewed" },
            { "notapplicable", "Not Applicable" },
            { "notchecked", "Not Reviewed" },
            { "notselected", "Not Reviewed" },
            { "informational", "Completed" },
            { "fixed", "Completed" },
            { "\nfail\n", "Ongoing" },
            { "\npass\n", "Completed" },
            { "\nunknown\n", "Not Reviewed" },
            { "\nmanual review\n", "Not Reviewed" },
            { "manual review", "Not Reviewed" },
            { "not an issue", "Completed" },
            { "reliability issue", "Ongoing" },
            { "bad practice", "Ongoing" },
            { "suspicious", "Ongoing" },
            { "exploitable", "Ongoing" }
        };

        private static readonly Dictionary<string, string> vulneratorStatusDictionary = new Dictionary<string, string>
        {
            { "completed", "NotAFinding" },
            { "not reviewed", "Not_Reviewed" },
            { "ongoing", "Open" },
            { "not applicable", "Not_Applicable" },
            { "error", "Not_Reviewed" },
            { "informational", "Not_Reviewed" }
        };

        private static readonly Dictionary<string, string> severityDictionary = new Dictionary<string, string>
        {
            { "critical", "I" },
            { "high", "I" },
            { "medium", "II" },
            { "moderate", "II" },
            { "low", "III" },
            { "cat i", "I" }, { "cat_i", "I" }, { "cati", "I" }, { "i", "I" },
            { "cat ii", "II" }, { "cat_ii", "II" }, { "catii", "II" }, { "ii", "II" },
            { "cat iii", "III" }, { "cat_iii", "III" }, { "catiii", "III" }, { "iii", "III" },
            { "informational", "IV" },
            { "unknown", "?" },
            { "\nhigh\n", "I" },
            { "\nmedium\n", "II" },
            { "\nlow\n", "III" },
            { "\ninformational\n", "IV" }
        };

        private static readonly Dictionary<string, string> rawRiskDictionary = new Dictionary<string, string>
        {
            { "I", "high" },
            { "II", "medium" },
            { "III", "low" },
            { "IV", "informational" },
            { "?", "unknown" }
        };

        public static bool IsFileInUse(this string file)
        {
            TextReader textReader = null;

            try
            { textReader = File.OpenText(file); }
            catch (FileNotFoundException fileNotFoundException)
            { return false; }
            catch (IOException ioException)
            { return true; }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to determine if '{Path.GetFileName(file)}' is in use.");
                throw exception;
            }
            finally
            { textReader?.Close(); }
            return false;
        }

        public static string FirstCharacterToUpper(this string _string)
        {
            try
            {
                if (_string == null)
                { return null; }
                if (_string.Length > 1)
                { return char.ToUpper(_string[0]) + _string.Substring(1); }
                return _string.ToUpper();
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to convert first character in {_string} to upper case.");
                throw exception;
            }
        }

        public static bool IsTooLargeForExcelCell(this int _int)
        {
            try
            { return _int > 32767; }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to determine if '{_int}' exceeds the bounds of a Microsoft Excel cell.");
                throw exception;
            }
        }

        public static string RemoveAlphaCharacters(this string _string)
        {
            try
            { return new string(_string.Where(x => !char.IsLetter(x) && !char.IsWhiteSpace(x)).ToArray()); }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to remove alpha characters from '{_string}'.");
                throw exception;
            }
        }

        public static object ObtainCurrentNodeValue(this XmlReader xmlReader, bool sanitizeBrackets)
        {
            try
            {
                string value = string.Empty;
                if (xmlReader.IsEmptyElement)
                { return value; }
                XmlReader subTreeXmlReader = xmlReader.ReadSubtree();
                while (subTreeXmlReader.Read())
                { value = string.Concat(value, xmlReader.Value); }

                value = value.SanitizeNewLines();

                if (!sanitizeBrackets)
                { return value; }
                value = value.Replace("&gt", ">");
                value = value.Replace("&lt", "<");
                if (!string.IsNullOrWhiteSpace(value))
                { return value; }
                return  DBNull.Value;
            }
            catch (Exception exception)
            {
                LogWriter.LogError("Unable to obtain the value of the current node.");
                throw exception;
            }
        }

        public static string SanitizeNewLines(this string _string)
        {
            try
            {
                string value = _string;
                if (value.StartsWith("\n"))
                { value = value.Remove(0, 1); }

                // Remove mid-line indented newline characters
                Regex regex = new Regex(Properties.Resources.RegexIndentedMidlineNewLine);
                value = regex.Replace(value, Environment.NewLine + "    ");
                // Remove non-indented mid-line newline characters
                regex = new Regex(Properties.Resources.RegexMidlineNewLine);
                value = regex.Replace(value, " ");
                // Remove trailing newline characters
                regex = new Regex(Properties.Resources.RegexTrailingNewLine);
                value = regex.Replace(value, string.Empty);
                // Remove excessive newline and tab characters; replace with bullet ("•")
                regex = new Regex(Properties.Resources.RegexExcessiveNewLineAndTab);
                value = regex.Replace(value, "  • ");
                if (value.EndsWith(@"\r\n"))
                { value = value.Remove(value.Length - 2, 2); }
                value = value.Trim();
                value = value.Replace("\r\n", Environment.NewLine);
                value = value.Replace("\n", Environment.NewLine);

                return value;
            }
            catch (Exception)
            {
                LogWriter.LogError($"Unable to sanitize the new lines in '{_string}'.");
                throw;
            }
        }

        public static string ToRawRisk(this string _string)
        {
            try
            { return severityDictionary.TryGetValue((_string ?? string.Empty).Trim().ToLowerInvariant(), out string rawRisk) ? rawRisk : "?"; }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to convert severity '{_string}' to a raw risk value.");
                throw exception;
            }
        }

        public static string ToSeverity(this string _string)
        {
            try
            { return rawRiskDictionary.TryGetValue(_string.ToLower(), out string severity) ? severity : "unknown"; }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to convert raw risk '{_string}' to a severity value.");
                throw exception;
            }
        }

        public static string ToImpact(this string _string)
        {
            try
            { return rawRiskDictionary.TryGetValue(_string.ToLower(), out string impact) ? impact : "unknown"; }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to convert raw risk '{_string}' to an impact value.");
                throw exception;
            }
        }

        public static string ToCklStatus(this string _string)
        {
            try
            { return vulneratorStatusDictionary.TryGetValue(_string.ToLower(), out string cklStatus) ? cklStatus : "Not_Reviewed"; }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to convert Vulnerator-provided status '{_string}' to an acceptable DISA STIG checklist status.");
                throw exception;
            }
        }

        public static string ToVulneratorStatus(this string _string)
        {
            try
            {
                string key = (_string ?? string.Empty).Trim().ToLowerInvariant();
                if (key.Length == 0)
                { return "Not Reviewed"; }
                if (rawStatusDictionary.TryGetValue(key, out string sanitizedStatus))
                { return sanitizedStatus; }
                // Unrecognized statuses are treated as not reviewed rather than stored verbatim (CKL-CKLB-Processor rule).
                LogWriter.LogStatusUpdate($"Unrecognized status '{_string}'; treated as Not Reviewed.");
                return "Not Reviewed";
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to convert raw status '{_string}' to a Vulnerator-acceptable status.");
                throw exception;
            }
        }

        public static string ToFortifyThreshold(this string _string)
        {
            try
            { return double.Parse(_string) >= 2.5 ? "High" : "Low"; }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to convert raw status '{_string}' to a Fortify threshold.");
                throw exception;
            }
        }

        public static string ToSanitizedSource(this string _string)
        {
            try
            {
                bool isSrg = _string.Contains("SRG") || _string.Contains("Security Requirement") ? true : false;
                string value = _string;
                Regex regex = new Regex(@"(?<!Application )((?:S|s)ecurity)");
                MatchCollection matches = regex.Matches(value);
                foreach (Match match in matches)
                { value = value.Remove(match.Index, match.Length); }
                string[] replaceArray = {
                    "STIG", "SECURITY", "Technical", "TECHNICAL", "Implementation", "IMPLEMENTATION",
                    "Guide", "GUIDE", "(", ")", "Requirements", "REQUIREMENTS", "SRG", "  "
                };
                value = replaceArray.Aggregate(value, (current, item) => current.Replace(item, item.Equals("  ") ? " " : ""));
                value = value.Trim();
                if (!isSrg)
                {
                    value = $"{value} Security Technical Implementation Guide";
                    return value;
                }
                value = $"{value} Security Requirements Guide";
                return value;
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to sanitize vulnerability source string '{_string}'.");
                throw exception;
            }
        }

        public static ObservableCollection<T> ToObservableCollection<T>(this IEnumerable<T> source)
        {
            try
            {
                if (source == null)
                { throw new ArgumentNullException(nameof(source)); }
                return new ObservableCollection<T>(source);
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to convert '{source}' to an ObservableCollection.");
                throw exception;
            }
        }

        private static readonly HashSet<string> AssetPlaceholders = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        { "n/a", "na", "none", "tbd", "unknown", "-", "x", "null", "localhost", "localhost.localdomain", "host name", "ip", "mac",
          "0.0.0.0", "127.0.0.1", "::1", "255.255.255.255" };

        /// <summary>
        /// True when a checklist asset value is blank or a filler (N/A, TBD, localhost, 127.0.0.1, STIG Viewer's
        /// "HOST NAME" / "IP" / "MAC" defaults, ...) and so does not identify a host. Same list as the
        /// CKL-CKLB-Processor asset check (AD-922).
        /// </summary>
        public static bool IsAssetPlaceholder(object value)
        {
            if (value == null || value == DBNull.Value)
            { return true; }
            string text = value.ToString().Trim();
            return text.Length == 0 || AssetPlaceholders.Contains(text);
        }

        private static readonly Regex StigBenchmarkDateRegex =
            new Regex(@"\b\d{1,2}\s+[A-Za-z]{3,9}\s+\d{4}\b", RegexOptions.Compiled);

        /// <summary>
        /// Extracts the benchmark date from STIG release text such as
        /// "Release: 4 Benchmark Date: 24 Jul 2025". Returns a DateTime, or DBNull.Value when the
        /// text carries no recognizable date, so callers never throw on missing or odd release info.
        /// Parsing is culture-invariant.
        /// </summary>
        public static object ToStigBenchmarkDate(this string releaseInfo)
        {
            if (string.IsNullOrWhiteSpace(releaseInfo))
            { return DBNull.Value; }
            Match match = StigBenchmarkDateRegex.Match(releaseInfo);
            if (!match.Success)
            { return DBNull.Value; }
            string candidate = Regex.Replace(match.Value, @"\s+", " ");
            string[] formats = { "d MMM yyyy", "dd MMM yyyy", "d MMMM yyyy", "dd MMMM yyyy" };
            DateTime parsed;
            if (DateTime.TryParseExact(candidate, formats, System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.None, out parsed))
            { return parsed; }
            return DBNull.Value;
        }

        /// <summary>
        /// True when an XCCDF ident "system" URI denotes a DISA CCI. DISA moved from
        /// http://iase.disa.mil/cci to http://cyber.mil/cci; both are accepted. Null-safe.
        /// </summary>
        public static bool IsCciIdentSystem(string system)
        {
            if (string.IsNullOrWhiteSpace(system))
            { return false; }
            string normalized = system.Trim().TrimEnd('/');
            return normalized.Equals("http://iase.disa.mil/cci", StringComparison.OrdinalIgnoreCase) ||
                   normalized.Equals("http://cyber.mil/cci", StringComparison.OrdinalIgnoreCase) ||
                   normalized.Equals("https://cyber.mil/cci", StringComparison.OrdinalIgnoreCase);
        }

        public static string InsertStartingBullet(this string _string)
        {
            try
            {
                return _string.Insert(0, @"• ");
            }
            catch (Exception exception)
            {
                LogWriter.LogError($"Unable to insert starting bullet on '{_string}'.");
                throw exception;
            }
        }

        public static bool HasColumn(this SQLiteDataReader sqliteDataReader, string columnName)
        {
            for (int i=0; i < sqliteDataReader.FieldCount; i++)
            {
                if (sqliteDataReader.GetName(i).Equals(columnName, StringComparison.InvariantCultureIgnoreCase))
                    return true;
            }
            return false;
        }
    }
}
