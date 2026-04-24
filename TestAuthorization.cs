using NUnit.Framework;
using System;

[TestFixture]
public class TestAuthorization
{
    [Test]
    public void AdminAccess_ShouldPass()
    {
        var result = AuthorizationService.HasAccess("ADMIN", "ADMIN");
        Assert.IsTrue(result);
    }

    [Test]
    public void UserAccess_AdminRoute_ShouldFail()
    {
        Assert.Throws<UnauthorizedAccessException>(() =>
            AuthorizationService.Authorize("USER", "ADMIN"));
    }

    [Test]
    public void CaseInsensitiveRoles_ShouldPass()
    {
        var result = AuthorizationService.HasAccess("admin", "ADMIN");
        Assert.IsTrue(result);
    }
}
