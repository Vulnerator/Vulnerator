using System;
using System.Windows.Data;

namespace Vulnerator.ViewModel
{
    public class CustomMultiValueConverter : IMultiValueConverter
    {
        public object Convert(object[] values, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            Model.CommandParameters parameters = MainWindowViewModel.commandParameters;
            if (values != null)
            {
                parameters.controlName = values[0].ToString();
                parameters.controlValue = values[1].ToString();
            }
                
            return parameters;
        }
        public object[] ConvertBack (object value, Type[] targetTypes, object parameter, System.Globalization.CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}
