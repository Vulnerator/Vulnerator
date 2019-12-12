using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Windows.Controls;

namespace Vulnerator.View.Validation
{
    class NumericValidationRule : ValidationRule
    {
        public override ValidationResult Validate(object value, System.Globalization.CultureInfo cultureInfo)
        {
            string tier = value.ToString();
            return !Regex.IsMatch(tier, @"\d") 
                ? new ValidationResult(false, "Must be only contain numbers.") : new ValidationResult(true, null);
        }
    }
}
