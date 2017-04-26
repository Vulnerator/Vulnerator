using System;
using System.Windows.Data;

namespace Vulnerator.View.Converter
{
    class ImportButtonTextAppendingConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            string finalValue = "Import " + value;
            return finalValue;
        }

        public object ConvertBack(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}
