using System;
using System.Globalization;
using System.Windows.Data;

namespace Vulnerator.ViewModel.Converter
{
    class StringToBoolConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if ((string)value != string.Empty)
            {
                bool isChecked = System.Convert.ToBoolean(value);
                return isChecked;
            }
            return null;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value != null)
            {
                string isChecked = System.Convert.ToString(value);
                return isChecked;
            }
            return string.Empty;
        }
    }
}
