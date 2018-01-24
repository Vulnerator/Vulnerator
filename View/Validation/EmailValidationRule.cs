using System.Text.RegularExpressions;
using System.Windows.Controls;

namespace Vulnerator.View.Validation
{
    class EmailValidationRule : ValidationRule
    {
        public override ValidationResult Validate(object value, System.Globalization.CultureInfo cultureInfo)
        {
            string email = value.ToString();
            if (email.Length > 0 && !Regex.IsMatch(email, @"^[a-zA-Z][\w\.-]*[a-zA-Z0-9]@[a-zA-Z0-9][\w\.-]*[a-zA-Z0-9]\.[a-zA-Z][a-zA-Z\.]*[a-zA-Z]$"))
            {
                return new ValidationResult(false, "Please enter a valid email address.");
            }
            return new ValidationResult(true, null);
        }
    }
}
