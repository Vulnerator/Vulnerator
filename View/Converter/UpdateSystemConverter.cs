using System;
using System.Windows.Data;

namespace Vulnerator.ViewModel.Converter
{
    public class UpdateSystemConverter : IMultiValueConverter
    {
        public object Convert(object[] values, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            Model.UpdateSystemParameters parameters = MainWindowViewModel.updateSystemParameters;
            if (values != null)
            {
                parameters.UpdatedSystemGroup = values[0].ToString();
                parameters.UpdatedSystemName = values[1].ToString();
                parameters.UpdatedSystemIP = values[2].ToString();
            }

            return parameters;
        }
        public object[] ConvertBack(object value, Type[] targetTypes, object parameter, System.Globalization.CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}
