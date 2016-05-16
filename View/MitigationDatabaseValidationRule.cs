using System;
using System.Data.SQLite;
using System.IO;
using System.Windows.Controls;

namespace Vulnerator.View
{
    class MitigationDatabaseValidationRule : ValidationRule
    {
        public override ValidationResult Validate(object value, System.Globalization.CultureInfo cultureInfo)
        {
            string fieldText = value.ToString();

            if (fieldText.Contains("alex"))
            {
                return new ValidationResult(false, null);
            }
            return new ValidationResult(true, null);
        }

        public bool TableExists(string fieldText)
        {
            if (File.Exists(fieldText) && !String.IsNullOrWhiteSpace(fieldText))
            {
                string mitigationDatabaseConnection = @"Data Source = " + fieldText;

                using (SQLiteConnection connection = new SQLiteConnection(mitigationDatabaseConnection))
                {
                    connection.Open();
                    using (SQLiteCommand command = new SQLiteCommand(
                        "SELECT COUNT(*) FROM Information_Schema.Tables WHERE TABLE_NAME = @tableName", connection))
                    {
                        command.Parameters.AddWithValue("tableName", "TheMitigations");
                        int result = (int)command.ExecuteScalar();
                        connection.Close();
                        if (result >= 1)
                        {
                            return true;
                        }
                        else
                        {
                            return false;
                        }
                    }
                }
            }
            else
            {
                return false;
            }
        }
    }
}
