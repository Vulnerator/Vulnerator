using System;
using System.Globalization;
using System.Windows.Data;

namespace Vulnerator.View.Converter
{
    class BooleanToCheckboxConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value == null || value.ToString() == string.Empty)
            { return "None"; }

            if (System.Convert.ToBoolean(value))
            { return "Check"; }

            return "None";
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}
