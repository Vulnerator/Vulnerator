using System;
using System.Windows.Data;

namespace Vulnerator.ViewModel
{
    public class UpdateSystemGroupConverter : IMultiValueConverter
    {
        public object Convert(object[] values, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            Model.UpdateSystemGroupParameters parameters = MainWindowViewModel.updateSystemGroupParameters;
            if (values != null)
            {
                parameters.UpdatedSystemGroupName = values[0].ToString();
                parameters.UpdatedSystemGroupMacLevel = values[1].ToString();
            }

            return parameters;
        }
        public object[] ConvertBack(object value, Type[] targetTypes, object parameter, System.Globalization.CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}
