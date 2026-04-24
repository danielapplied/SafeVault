using MySql.Data.MySqlClient;

public class UserEntity
{
    public string Username { get; set; }
    public string Email { get; set; }
    public string PasswordHash { get; set; }
    public string Role { get; set; }
}

public partial class UserRepository
{
    public void InsertUserWithPassword(string username, string email, string passwordHash, string role)
    {
        using var connection = new MySqlConnection(_connectionString);
        connection.Open();

        string query = @"INSERT INTO Users (Username, Email, PasswordHash, Role) 
                         VALUES (@username, @email, @password, @role)";

        using var command = new MySqlCommand(query, connection);
        command.Parameters.AddWithValue("@username", username);
        command.Parameters.AddWithValue("@email", email);
        command.Parameters.AddWithValue("@password", passwordHash);
        command.Parameters.AddWithValue("@role", role);

        command.ExecuteNonQuery();
    }

    public UserEntity GetUserWithPassword(string username)
    {
        using var connection = new MySqlConnection(_connectionString);
        connection.Open();

        string query = "SELECT Username, Email, PasswordHash, Role FROM Users WHERE Username = @username";

        using var command = new MySqlCommand(query, connection);
        command.Parameters.AddWithValue("@username", username);

        using var reader = command.ExecuteReader();

        if (reader.Read())
        {
            return new UserEntity
            {
                Username = reader.GetString("Username"),
                Email = reader.GetString("Email"),
                PasswordHash = reader.GetString("PasswordHash"),
                Role = reader.GetString("Role")
            };
        }

        return null;
    }
}
