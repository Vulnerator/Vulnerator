using System;
using System.Globalization;
using System.Windows.Data;

namespace Vulnerator.View.Converter
{
    class BooleanToIconConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value.ToString() != string.Empty)
            {
                if (System.Convert.ToBoolean(value))
                { return "CheckboxMarkedCircleOutline"; }
                else
                { return "Exclamation"; }
            }
            return null;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}
