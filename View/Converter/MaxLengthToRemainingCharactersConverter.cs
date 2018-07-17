using System;
using System.Globalization;
using System.Windows.Data;

namespace Vulnerator.View.Converter
{
    class MaxLengthToRemainingCharactersConverter : IMultiValueConverter
    {
        public object Convert(object[] values, Type targetType, object parameter, CultureInfo culture)
        {
            if (values != null && values.Length > 1)
            {
                int maxLength = int.Parse(values[0].ToString());
                int currentLength = values[1].ToString().Length;
                int remaining = maxLength - currentLength;
                return string.Format("Remaining: {0}", remaining);
            }
            return null;
        }

        public object[] ConvertBack(object value, Type[] targetTypes, object parameter, CultureInfo culture)
        { throw new NotImplementedException(); }
    }
}
