using System;
using NUnit.Framework;
using SafeVault;

namespace SafeVault.Tests
{
    [TestFixture]
    public class SafeVaultSecurityTests
    {
        [Test]
        public void TestForSQLInjection_RejectsMaliciousUsername()
        {
            string sqlInjectionPayload = "admin' OR '1'='1'; DROP TABLE Users;--";
            bool isValid = InputSanitizer.IsValidUsername(sqlInjectionPayload);

            Assert.That(isValid, Is.False, "SQL injection payload should be rejected by input validation.");
        }

        [Test]
        public void TestForXSS_EncodesScriptTags()
        {
            string xssPayload = "<script>alert('XSS');</script>";
            string sanitized = InputSanitizer.SanitizeForOutput(xssPayload);

            Assert.That(sanitized, Does.Not.Contain("<script>"));
            Assert.That(sanitized, Is.EqualTo("&lt;script&gt;alert(&#39;XSS&#39;);&lt;/script&gt;"));
        }

        [Test]
        public void TestAuthentication_PasswordHashingAndVerification()
        {
            string rawPassword = "StrongPassword!2026";
            string hash = PasswordHasher.HashPassword(rawPassword);

            Assert.That(PasswordHasher.VerifyPassword(rawPassword, hash), Is.True);
            Assert.That(PasswordHasher.VerifyPassword("WrongPassword", hash), Is.False);
        }

        [Test]
        public void TestRBAC_DeniesNonAdminUser()
        {
            var standardUser = new User
            {
                UserID = 1,
                Username = "regular_user",
                Email = "user@example.com",
                Role = "User"
            };

            var controller = new AdminDashboardController();

            Assert.Throws<UnauthorizedAccessException>(() =>
            {
                controller.AccessAdminDashboard(standardUser);
            });
        }

        [Test]
        public void TestRBAC_AllowsAdminUser()
        {
            var adminUser = new User
            {
                UserID = 2,
                Username = "admin_user",
                Email = "admin@example.com",
                Role = "Admin"
            };

            var controller = new AdminDashboardController();
            string response = controller.AccessAdminDashboard(adminUser);

            Assert.That(response, Is.EqualTo("Welcome to the Admin Dashboard, admin_user."));
        }
    }
}
