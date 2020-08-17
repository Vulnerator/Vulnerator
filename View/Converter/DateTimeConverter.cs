using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Data;

namespace Vulnerator.View.Converter
{
    class DateTimeConverter : IValueConverter
    {
        public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
        {
            try
            {
                if (value != null)
                {
                    
                    DateTime date = DateTime.Parse(value.ToString());
                    return date;
                }
                return new DateTimeOffset(DateTime.Now);
            }
            catch (Exception)
            { return DateTime.Now.ToShortDateString(); }
        }

        public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
        {
            try
            { return DateTime.Parse(value.ToString()); }
            catch (Exception)
            { return DateTime.Now.ToShortDateString(); }
        }
    }
}
