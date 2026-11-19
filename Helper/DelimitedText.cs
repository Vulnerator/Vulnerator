using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Vulnerator.Helper
{
    /// <summary>Reads CSV / TSV text (RFC 4180 quoting; quoted fields may span lines) and finds columns by header name.</summary>
    public static class DelimitedText
    {
        /// <summary>The file's text; the encoding comes from a byte order mark (UTF-8 otherwise).</summary>
        public static string ReadAllText(string path)
        {
            using (StreamReader reader = new StreamReader(path, Encoding.UTF8, true))
            { return reader.ReadToEnd(); }
        }

        /// <summary>The text parsed with comma, tab and semicolon, in that order (callers keep the parse whose header they find).</summary>
        public static IEnumerable<List<string[]>> ParseCandidates(string text)
        { return new[] { ',', '\t', ';' }.Select(d => Parse(text, d)); }

        public static List<string[]> Parse(string text, char delimiter)
        {
            List<string[]> rows = new List<string[]>();
            List<string> fields = new List<string>();
            StringBuilder field = new StringBuilder();
            bool quoted = false;
            for (int i = 0; i < text.Length; i++)
            {
                char c = text[i];
                if (quoted)
                {
                    if (c == '"' && i + 1 < text.Length && text[i + 1] == '"')
                    {
                        field.Append('"');
                        i++;
                    }
                    else if (c == '"')
                    { quoted = false; }
                    else
                    { field.Append(c); }
                }
                else if (c == '"' && field.Length == 0)
                { quoted = true; }
                else if (c == delimiter)
                {
                    fields.Add(field.ToString());
                    field.Clear();
                }
                else if (c == '\r' || c == '\n')
                {
                    if (c == '\r' && i + 1 < text.Length && text[i + 1] == '\n')
                    { i++; }
                    fields.Add(field.ToString());
                    field.Clear();
                    rows.Add(fields.ToArray());
                    fields.Clear();
                }
                else
                { field.Append(c); }
            }
            if (field.Length > 0 || fields.Count > 0)
            {
                fields.Add(field.ToString());
                rows.Add(fields.ToArray());
            }
            return rows;
        }

        /// <summary>Header text compared without case, spaces or punctuation ("CVSS V2 Base Score" = "cvssv2basescore").</summary>
        public static string Normalize(string text)
        { return new string((text ?? string.Empty).Where(char.IsLetterOrDigit).Select(char.ToLowerInvariant).ToArray()); }

        /// <summary>Index of the first cell matching one of the names (in the names' order of preference), or -1.</summary>
        public static int Find(string[] row, params string[] names)
        {
            foreach (string name in names)
            {
                string wanted = Normalize(name);
                int index = Array.FindIndex(row, c => Normalize(c) == wanted);
                if (index >= 0)
                { return index; }
            }
            return -1;
        }

        public static string Cell(string[] row, int index)
        { return index >= 0 && index < row.Length ? row[index] ?? string.Empty : string.Empty; }
    }
}
