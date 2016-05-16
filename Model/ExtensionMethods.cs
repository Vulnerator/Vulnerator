using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace Vulnerator.Model
{
    public static class ExtensionMethods
    {
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
    }
}
