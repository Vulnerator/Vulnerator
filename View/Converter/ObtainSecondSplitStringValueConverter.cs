using System;
using System.Windows.Data;

namespace Vulnerator.ViewModel.Converter
{
    class ObtainSecondSplitStringValueConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            if (value != null && !string.IsNullOrWhiteSpace(value.ToString()))
            {
                if (value.ToString().Contains("MAC"))
                {
                    string finalValue = value.ToString().Split(new string[] { ": MAC " }, StringSplitOptions.None)[1].TrimStart();
                    return finalValue;
                }
                else
                {
                    string finalValue = value.ToString().Split(new string[] { ": " }, StringSplitOptions.None)[1].TrimStart();
                    return finalValue;
                }
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
