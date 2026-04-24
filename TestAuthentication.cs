using NUnit.Framework;

[TestFixture]
public class TestAuthentication
{
    private AuthService _authService;

    [SetUp]
    public void Setup()
    {
        var repo = new FakeUserRepository(); // Mocked repo
        _authService = new AuthService(repo);

        _authService.Register("admin", "admin@test.com", "Secure123!", "ADMIN");
    }

    [Test]
    public void TestValidLogin()
    {
        var result = _authService.Login("admin", "Secure123!");
        Assert.IsTrue(result);
    }

    [Test]
    public void TestInvalidPassword()
    {
        var result = _authService.Login("admin", "wrongpassword");
        Assert.IsFalse(result);
    }

    [Test]
    public void TestInvalidUser()
    {
        var result = _authService.Login("unknown", "password");
        Assert.IsFalse(result);
    }
}
