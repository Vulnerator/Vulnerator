using System;
using System.Windows.Data;

namespace Vulnerator.ViewModel.Converter
{
    class ObtainFirstSplitStringValueConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            if (value != null && !string.IsNullOrWhiteSpace(value.ToString()))
            {
                string finalValue = value.ToString().Split(':')[0].TrimEnd();
                return finalValue;
            }
            else
            {
                return "";
            }
        }

        public object ConvertBack(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}
