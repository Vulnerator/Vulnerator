using System;
using System.Windows.Controls;

namespace Vulnerator.View
{
    class BlankFieldValidationRule : ValidationRule
    {
        public override ValidationResult Validate(object value, System.Globalization.CultureInfo cultureInfo)
        {
            string fieldText = value.ToString();
            if (string.IsNullOrWhiteSpace(fieldText))
            {
                return new ValidationResult(false, null);
            }
            return new ValidationResult(true, null);
        }
    }
}
