using System;
using System.Windows.Data;

namespace Vulnerator.ViewModel.Converter
{
    class StringJoiningConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            string finalValue = ">" + value + " Days";
            return finalValue;
        }

        public object ConvertBack(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}
