using NUnit.Framework;
using SecurityAndAuth;

[TestFixture]
public class TestInputValidation
{
    // 🔴 SQL Injection Test
    [Test]
    public void TestForSQLInjection()
    {
        string maliciousInput = "'; DROP TABLE Users; --";

        bool result = InputValidator.ContainsSqlInjection(maliciousInput);

        Assert.IsTrue(result, "SQL Injection should be detected");
    }

    // 🔴 XSS Test
    [Test]
    public void TestForXSS()
    {
        string maliciousInput = "<script>alert('hack')</script>";

        bool result = InputValidator.ContainsXss(maliciousInput);

        Assert.IsTrue(result, "XSS should be detected");
    }

    // ✅ Safe input should pass
    [Test]
    public void TestForValidInput()
    {
        string safeInput = "John Doe";

        bool sqlResult = InputValidator.ContainsSqlInjection(safeInput);
        bool xssResult = InputValidator.ContainsXss(safeInput);

        Assert.IsFalse(sqlResult);
        Assert.IsFalse(xssResult);
    }

    // 🔒 XSS Encoding protection test
    [Test]
    public void TestForXSS_EncodingProtection()
    {
        string input = "<script>alert('hack')</script>";

        string encoded = InputSanitizer.EncodeForHtml(input);

        Assert.IsFalse(encoded.Contains("<script>"));
        Assert.IsTrue(encoded.Contains("&lt;script&gt;"));
    }

    // 🔴 Edge Case: Empty input
    [Test]
    public void TestEmptyInput()
    {
        string input = "";

        Assert.IsFalse(InputValidator.ContainsSqlInjection(input));
        Assert.IsFalse(InputValidator.ContainsXss(input));
    }

    // 🔴 Edge Case: Null input
    [Test]
    public void TestNullInput()
    {
        string input = null;

        Assert.IsFalse(InputValidator.ContainsSqlInjection(input));
        Assert.IsFalse(InputValidator.ContainsXss(input));
    }
}
