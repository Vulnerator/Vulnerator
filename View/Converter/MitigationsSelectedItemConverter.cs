using System;
using System.Globalization;
using System.Windows.Data;
using Vulnerator.Model.Entity;

namespace Vulnerator.View.Converter
{
    class MitigationsSelectedItemConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            return value;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value is MitigationsOrCondition)
                return value;
            return null;
        }
    }
}
