using System;
using System.Windows.Data;

namespace Vulnerator.ViewModel
{
    class ContactInfoSeparatorConverter : IMultiValueConverter
    {
        public object Convert(object[] values, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            Model.UpdateContactParameters parameters = MainWindowViewModel.updateContactParameters;
            parameters.CurrentName= values[0].ToString();
            parameters.CurrentGroup = values[1].ToString();
            parameters.CurrentSystemName = values[2].ToString();
            parameters.NewName = values[3].ToString();
            parameters.NewTitle = values[4].ToString();
            parameters.NewEmail = values[5].ToString();
            parameters.NewGroupName = values[6].ToString();
            parameters.NewSystemIp = values[7].ToString();
            parameters.NewSystemName = values[8].ToString();

            return parameters;
        }
        public object[] ConvertBack(object value, Type[] targetTypes, object parameter, System.Globalization.CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}
