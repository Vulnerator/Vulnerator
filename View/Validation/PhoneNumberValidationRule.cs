using System.Text.RegularExpressions;
using System.Windows.Controls;

namespace Vulnerator.View.Validation
{
    class PhoneNumberValidationRule : ValidationRule
    {
        public override ValidationResult Validate(object value, System.Globalization.CultureInfo cultureInfo)
        {
            string phone = value.ToString();
            if (!Regex.IsMatch(phone, @"^[0-9]*$"))
            {
                return new ValidationResult(false, "eMASS POC Number must only contain digits.");
            }
            return new ValidationResult(true, null);
        }
    }
}
