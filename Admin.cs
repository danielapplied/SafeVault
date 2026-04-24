public class AdminController
{
    public string AccessAdminDashboard(UserEntity user)
    {
        AuthorizationService.Authorize(user.Role, "ADMIN");

        return "Welcome to Admin Dashboard";
    }
}
