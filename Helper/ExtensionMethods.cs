using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
using System.Linq;
using System.Xml;

namespace Vulnerator.Helper
{
    public static class ExtensionMethods
    {
        private static Dictionary<string, string> rawStatusDictionary = new Dictionary<string, string>
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

        private static Dictionary<string, string> vulneratorStatusDictionary = new Dictionary<string, string>
        {
            { "completed", "NotAFinding" },
            { "not reviewed", "Not_Reviewed" },
            { "ongoing", "Open" },
            { "not applicable", "Not_Applicable" },
            { "error", "Not_Reviewed" },
            { "informational", "Not_Reviewed" }
        };

        private static Dictionary<string, string> severityDictionary = new Dictionary<string, string>
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
            { "\ninformational\n", "IV" },
        };

        private static Dictionary<string, string> rawRiskDictionary = new Dictionary<string, string>
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
            {
                if (textReader != null)
                { textReader.Close(); }
            }
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
        {
            if (_int > 32767)
            { return true; }
            else
            { return false; }
        }

        public static string RemoveAlphaCharacters(this string _input)
        { return new string(_input.Where(x => !char.IsLetter(x) && !char.IsWhiteSpace(x)).ToArray()); }

        public static string ObtainCurrentNodeValue(this XmlReader xmlReader, bool sanitizeBrackets)
        {
            string value = string.Empty;
            XmlReader subTreeXmlReader = xmlReader.ReadSubtree();
            while (subTreeXmlReader.Read())
            { value = string.Concat(value, xmlReader.Value); }
            value = value.Replace("\n", Environment.NewLine);
            if (sanitizeBrackets)
            {
                value = value.Replace("&gt", ">");
                value = value.Replace("&lt", "<");
            }
            return value;
        }

        public static string ToRawRisk(this string severity)
        {
            string rawRisk = string.Empty;
            if (severityDictionary.TryGetValue(severity, out rawRisk))
            { return rawRisk; }
            return "?";
        }

        public static string ToSeverity(this string rawRisk)
        {
            string severity = string.Empty;
            if (rawRiskDictionary.TryGetValue(rawRisk, out severity))
            { return severity; }
            return "unknown";
        }

        public static string ToImpact(this string rawRisk)
        {
            string impact = string.Empty;
            if (rawRiskDictionary.TryGetValue(rawRisk, out impact))
            { return impact; }
            return "unknown";
        }

        public static string ToCklStatus(this string vulneratorStatus)
        {
            string cklStatus = string.Empty;
            if (vulneratorStatusDictionary.TryGetValue(vulneratorStatus.ToLower(), out cklStatus))
            { return cklStatus; }
            return "Not_Reviewed";
        }

        public static string ToVulneratorStatus(this string rawStatus)
        {
            string sanitizedStatus = string.Empty;
            if (rawStatusDictionary.TryGetValue(rawStatus.ToLower(), out sanitizedStatus))
            { return sanitizedStatus; }
            return rawStatus;
        }

        public static string ToSanitizedSource(this string _string)
        {
            bool isSRG = _string.Contains("SRG") || _string.Contains("Security Requirement") ? true : false;
            string value = _string;
            string[] replaceArray = new string[]
            {
                    "STIG", "Security", "SECURITY", "Technical", "TECHNICAL", "Implementation", "IMPLEMENTATION",
                    "Guide", "GUIDE", "(", ")", "Requirements", "REQUIREMENTS", "SRG", "  "
            };
            foreach (string item in replaceArray)
            {
                if (item.Equals("  "))
                { value = value.Replace(item, " "); }
                else
                { value = value.Replace(item, ""); }
            }
            value = value.Trim();
            if (!isSRG)
            {
                value = string.Format("{0} Security Technical Implementation Guide", value);
                return value;
            }
            value = string.Format("{0} Security Requirements Guide", value);
            return value;
        }

        public static ObservableCollection<T> ToObservableCollection<T>(this IEnumerable<T> source)
        {
            if (source == null)
            { throw new ArgumentNullException("source"); }
            return new ObservableCollection<T>(source);
        }
    }
}
