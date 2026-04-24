using NUnit.Framework;
using System.Net;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;

namespace SecurityAndAuth
{
    [TestFixture]
    public class InjectionTest
    {
        private HttpClient _client;

        [SetUp]
        public void Setup()
        {
            // Assuming your API is running locally
            _client = new HttpClient
            {
                BaseAddress = new System.Uri("http://localhost:5000")
            };
        }

        // 🔴 SQL Injection Test
        [Test]
        public async Task Should_Block_SQL_Injection_Attempt()
        {
            var maliciousPayload = new
            {
                fullName = "Robert'); DROP TABLE Users;--",
                email = "test@test.com",
                passwordHash = "Password123!",
                department = "IT"
            };

            var content = new StringContent(
                System.Text.Json.JsonSerializer.Serialize(maliciousPayload),
                Encoding.UTF8,
                "application/json"
            );

            var response = await _client.PostAsync("/api/auth/register", content);

            // Expect rejection due to validation
            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        }

        // 🔴 XSS Injection Test
        [Test]
        public async Task Should_Block_XSS_Attempt()
        {
            var xssPayload = new
            {
                fullName = "<script>alert('hack')</script>",
                email = "xss@test.com",
                passwordHash = "Password123!",
                department = "IT"
            };

            var content = new StringContent(
                System.Text.Json.JsonSerializer.Serialize(xssPayload),
                Encoding.UTF8,
                "application/json"
            );

            var response = await _client.PostAsync("/api/auth/register", content);

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        }

        // 🔴 Invalid Email Test
        [Test]
        public async Task Should_Reject_Invalid_Email()
        {
            var payload = new
            {
                fullName = "Test User",
                email = "invalid-email",
                passwordHash = "Password123!",
                department = "IT"
            };

            var content = new StringContent(
                System.Text.Json.JsonSerializer.Serialize(payload),
                Encoding.UTF8,
                "application/json"
            );

            var response = await _client.PostAsync("/api/auth/register", content);

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
        }

        // 🔴 Unauthorized Access Test
        [Test]
        public async Task Should_Block_Unauthorized_User_Access()
        {
            var response = await _client.GetAsync("/api/users");

            Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
        }
    }
}
