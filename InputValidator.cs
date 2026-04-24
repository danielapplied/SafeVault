using System.Text.RegularExpressions;

namespace SecurityAndAuth
{
    public static class InputValidator
    {
        // 🔹 Validate Full Name (letters, spaces, hyphens only)
        public static bool IsValidFullName(string fullName)
        {
            if (string.IsNullOrWhiteSpace(fullName))
                return false;

            return Regex.IsMatch(fullName, @"^[a-zA-Z\s\-]{3,100}$");
        }

        // 🔹 Validate Email
        public static bool IsValidEmail(string email)
        {
            if (string.IsNullOrWhiteSpace(email))
                return false;

            return Regex.IsMatch(email, @"^[^@\s]+@[^@\s]+\.[^@\s]+$");
        }

        // 🔹 Validate Password (strong policy)
        public static bool IsValidPassword(string password)
        {
            if (string.IsNullOrWhiteSpace(password))
                return false;

            // Minimum 8 chars, 1 uppercase, 1 lowercase, 1 digit, 1 special char
            return Regex.IsMatch(password,
                @"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$");
        }

        // 🔹 Validate Department
        public static bool IsValidDepartment(string department)
        {
            if (string.IsNullOrWhiteSpace(department))
                return false;

            return department.Length <= 50;
        }

        // 🔹 Detect potential SQL Injection patterns
        public static bool ContainsSqlInjection(string input)
        {
            if (string.IsNullOrWhiteSpace(input))
                return false;

            string pattern = @"(--|\b(SELECT|INSERT|DELETE|DROP|UPDATE|ALTER|EXEC)\b)";
            return Regex.IsMatch(input, pattern, RegexOptions.IgnoreCase);
        }

        // 🔹 Detect potential XSS patterns
        public static bool ContainsXss(string input)
        {
            if (string.IsNullOrWhiteSpace(input))
                return false;

            string pattern = @"<script.*?>.*?</script>";
            return Regex.IsMatch(input, pattern, RegexOptions.IgnoreCase);
        }
    }
}
