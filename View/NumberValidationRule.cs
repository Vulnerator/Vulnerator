using System.Text.RegularExpressions;
using System.Windows.Controls;

namespace Vulnerator.View
{
    class NumberValidationRule : ValidationRule
    {
        public override ValidationResult Validate(object value, System.Globalization.CultureInfo cultureInfo)
        {
            string eMassNumber = value.ToString();
            if (!Regex.IsMatch(eMassNumber, @"^[0-9]*$"))
            {
                return new ValidationResult(false, "eMASS POC Number must only contain digits.");
            }
            return new ValidationResult(true, null);
        }
    }
}
