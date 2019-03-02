using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Data;

namespace Vulnerator.View.Converter
{
    class RemainingCharactersConverter : IMultiValueConverter
    {
        public object Convert(object[] values, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            if (values != null)
            {
                int remaining = int.Parse(values[0].ToString()) - int.Parse(values[1].ToString());
                string value = $"Remaining: {remaining}/{values[0].ToString()}";
                return value;
            }
            return string.Empty;
        }

        public object[] ConvertBack(object value, Type[] targetTypes, object parameter, System.Globalization.CultureInfo culture)
        {
            string[] values = null;
            if (value != null)
                return values = value.ToString().Split(' ');
            return values;
        }
    }
}
