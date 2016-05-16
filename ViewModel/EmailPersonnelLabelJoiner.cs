using System;
using System.Windows.Data;

namespace Vulnerator.ViewModel
{
    class EmailPersonnelLabelJoiner : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            string finalValue = ">" + value + " Days Personnel";
            return finalValue;
        }

        public object ConvertBack(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}
