using System;
using System.Windows.Data;

namespace Vulnerator.View.Converter
{
    class UpdateDictionaryConverter : IMultiValueConverter
    {
        public object Convert(object[] values, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            Model.Object.UpdateDictionaryParameter updateDictionaryParameters = new Model.Object.UpdateDictionaryParameter();
            if (values != null)
            {
                updateDictionaryParameters.Key = values[0].ToString();
                updateDictionaryParameters.Value = values[1].ToString();
            }

            return updateDictionaryParameters;
        }
        public object[] ConvertBack(object value, Type[] targetTypes, object parameter, System.Globalization.CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}
