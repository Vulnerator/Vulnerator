using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Web.Configuration;
using System.Xml;

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
            { "informational", "Informational" },
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
            finally
            { textReader?.Close(); }
            return false;
        }

        public static string FirstCharacterToUpper(this string _string)
        {
            if (_string == null)
            { return null; }
            if (_string.Length > 1)
            { return char.ToUpper(_string[0]) + _string.Substring(1); }
            return _string.ToUpper();
        }

        public static bool IsTooLargeForExcelCell(this int _int)
        { return _int > 32767; }

        public static string RemoveAlphaCharacters(this string _input)
        { return new string(_input.Where(x => !char.IsLetter(x) && !char.IsWhiteSpace(x)).ToArray()); }

        public static string ObtainCurrentNodeValue(this XmlReader xmlReader, bool sanitizeBrackets)
        {
            string value = string.Empty;
            if (xmlReader.IsEmptyElement)
            { return value; }
            XmlReader subTreeXmlReader = xmlReader.ReadSubtree();
            while (subTreeXmlReader.Read())
            { value = string.Concat(value, xmlReader.Value); }

            if (value.StartsWith("\n"))
            { value = value.Remove(0, 1); }
            value = value.Replace("\n", Environment.NewLine);
            if (!sanitizeBrackets)
            { return value; }
            value = value.Replace("&gt", ">");
            value = value.Replace("&lt", "<");
            return value;
        }

        public static string ToRawRisk(this string severity)
        { return severityDictionary.TryGetValue(severity, out string rawRisk) ? rawRisk : "?"; }

        public static string ToSeverity(this string rawRisk)
        { return rawRiskDictionary.TryGetValue(rawRisk, out string severity) ? severity : "unknown"; }

        public static string ToImpact(this string rawRisk)
        { return rawRiskDictionary.TryGetValue(rawRisk, out string impact) ? impact : "unknown"; }

        public static string ToCklStatus(this string vulneratorStatus)
        { return vulneratorStatusDictionary.TryGetValue(vulneratorStatus.ToLower(), out string  cklStatus) ? cklStatus : "Not_Reviewed"; }

        public static string ToVulneratorStatus(this string rawStatus)
        { return rawStatusDictionary.TryGetValue(rawStatus.ToLower(), out string sanitizedStatus) ? sanitizedStatus : rawStatus; }

        public static string ToSanitizedSource(this string _string)
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

        public static ObservableCollection<T> ToObservableCollection<T>(this IEnumerable<T> source)
        {
            if (source == null)
            { throw new ArgumentNullException(nameof(source)); }
            return new ObservableCollection<T>(source);
        }

        public static string SanitizeExcessiveNewLineAndTab(this string _string)
        {
            Regex regex = new Regex(Properties.Resources.RegexExcessiveNewLineAndTab);
            return regex.Replace(_string,  Environment.NewLine + @"• ");
        }

        public static string InsertStartingBullet(this string _string)
        { return _string.Insert(0, @"• "); }
    }
}
