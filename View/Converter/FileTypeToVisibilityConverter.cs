using System;
using System.Globalization;
using System.Windows.Data;

namespace Vulnerator.View.Converter
{
    class FileTypeToVisibilityConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            if (value.ToString().Contains("Checklist"))
            { return "VisibleWhenSelected"; }
            else
            { return "Collapsed"; }
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}
