using System;
using System.Windows.Data;

namespace Vulnerator.ViewModel.Converter
{
    class StringSeparatorConverter : IMultiValueConverter
    {
        public object Convert(object[] values, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            Model.UpdateMitigationParameters parameters = MainWindowViewModel.updateMitigationParameters;
            parameters.VulnerabilityId = values[0].ToString();
            parameters.CurrentGroupName = values[1].ToString();

            return parameters;
        }
        public object[] ConvertBack(object value, Type[] targetTypes, object parameter, System.Globalization.CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}
