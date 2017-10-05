using System;
using System.Diagnostics;
using System.Globalization;
using System.Windows.Data;

namespace Vulnerator.View.Converter
{
    class DebugDataBindingConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            Debugger.Break();
            return value;
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            Debugger.Break();
            return value;
        }
    }
}
