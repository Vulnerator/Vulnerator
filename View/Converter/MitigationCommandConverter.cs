using System;
using System.Windows.Data;

namespace Vulnerator.View.Converter
{
    class MitigationCommandConverter : IMultiValueConverter
    {
        public object Convert(object[] values, Type targetType, object parameter, System.Globalization.CultureInfo culture)
        {
            Model.Object.MitigationCommandParameter mitigationCommandParameters = new Model.Object.MitigationCommandParameter();
            if (values != null)
            {
                if (values[0] != null)
                { mitigationCommandParameters.Index = values[0].ToString(); }
                if (values[1] != null)
                { mitigationCommandParameters.VulnId = values[1].ToString(); }
                if (values[2] != null)
                { mitigationCommandParameters.Text = values[2].ToString(); }
                if (values[3] != null)
                { mitigationCommandParameters.Status = values[3].ToString(); }
                if (values[4] != null)
                { mitigationCommandParameters.Accreditation = values[4].ToString(); }
                if (values[5] != null)
                { mitigationCommandParameters.Project = values[5].ToString(); }
                if (values[6] != null)
                { mitigationCommandParameters.HostName = values[6].ToString(); }
                if (values[7] != null)
                { mitigationCommandParameters.IpAddress = values[7].ToString(); }
                if (values[8] != null)
                { mitigationCommandParameters.DateEntered = values[8].ToString(); }
                if (values[9] != null)
                { mitigationCommandParameters.DateExpires = values[9].ToString(); }
                mitigationCommandParameters.AllInstances = (bool)values[10];
                mitigationCommandParameters.SingleGroup = (bool)values[11];
                mitigationCommandParameters.SingleAsset = (bool)values[12];
            }

            return mitigationCommandParameters;
        }
        public object[] ConvertBack(object value, Type[] targetTypes, object parameter, System.Globalization.CultureInfo culture)
        {
            throw new NotImplementedException();
        }
    }
}
