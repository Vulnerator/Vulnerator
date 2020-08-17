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
            { "not_reviewed", "Not Reviewed" },
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
            { "low", "III" },
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
            { return severityDictionary.TryGetValue(_string.ToLower(), out string rawRisk) ? rawRisk : "?"; }
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
            { return rawStatusDictionary.TryGetValue(_string.ToLower(), out string sanitizedStatus) ? sanitizedStatus : _string; }
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
