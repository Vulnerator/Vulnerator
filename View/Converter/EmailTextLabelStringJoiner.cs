using System;
using System.Windows.Data;

namespace Vulnerator.ViewModel.Converter
{
    class EmailTextLabelStringJoiner : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            string finalValue = ">" + value + " Days Text";
            return finalValue;
        }

        public object ConvertBack(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}
