using System;
using System.Collections.Generic;
using System.Data;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Data.SqlClient;

namespace SafeVault
{
    public class User
    {
        public int UserID { get; set; }
        public string Username { get; set; } = string.Empty;
        public string Email { get; set; } = string.Empty;
        public string PasswordHash { get; set; } = string.Empty;
        public string Role { get; set; } = "User"; // Roles: "Admin", "User"
    }

    public static class InputSanitizer
    {
        // Strict allowlist for usernames: alphanumeric and underscores, 3-20 chars
        private static readonly Regex UsernameRegex = new Regex(@"^[a-zA-Z0-9_]{3,20}$", RegexOptions.Compiled);
        private static readonly Regex EmailRegex = new Regex(@"^[^@\s]+@[^@\s]+\.[^@\s]+$", RegexOptions.Compiled);

        public static bool IsValidUsername(string username)
        {
            return !string.IsNullOrWhiteSpace(username) && UsernameRegex.IsMatch(username);
        }

        public static bool IsValidEmail(string email)
        {
            return !string.IsNullOrWhiteSpace(email) && EmailRegex.IsMatch(email);
        }

        // Encodes HTML entities to prevent Cross-Site Scripting (XSS)
        public static string SanitizeForOutput(string input)
        {
            if (string.IsNullOrEmpty(input))
                return string.Empty;

            return WebUtility.HtmlEncode(input.Trim());
        }
    }

    public class PasswordHasher
    {
        private const int SaltSize = 16;
        private const int KeySize = 32;
        private const int Iterations = 100000;

        public static string HashPassword(string password)
        {
            if (string.IsNullOrWhiteSpace(password) || password.Length < 8)
                throw new ArgumentException("Password must be at least 8 characters long.");

            byte[] salt = RandomNumberGenerator.GetBytes(SaltSize);
            byte[] hash = Rfc2898DeriveBytes.Pbkdf2(
                Encoding.UTF8.GetBytes(password),
                salt,
                Iterations,
                HashAlgorithmName.SHA256,
                KeySize
            );

            return $"{Convert.ToBase64String(salt)}.{Convert.ToBase64String(hash)}";
        }

        public static bool VerifyPassword(string password, string storedHash)
        {
            var parts = storedHash.Split('.');
            if (parts.Length != 2) return false;

            byte[] salt = Convert.FromBase64String(parts[0]);
            byte[] expectedHash = Convert.FromBase64String(parts[1]);

            byte[] actualHash = Rfc2898DeriveBytes.Pbkdf2(
                Encoding.UTF8.GetBytes(password),
                salt,
                Iterations,
                HashAlgorithmName.SHA256,
                KeySize
            );

            return CryptographicOperations.FixedTimeEquals(actualHash, expectedHash);
        }
    }

    public class UserRepository
    {
        private readonly string _connectionString;

        public UserRepository(string connectionString)
        {
            _connectionString = connectionString;
        }

        // Uses parameterized queries to eliminate SQL Injection vulnerabilities
        public void RegisterUser(string username, string email, string password, string role = "User")
        {
            if (!InputSanitizer.IsValidUsername(username))
                throw new ArgumentException("Invalid username format.");

            if (!InputSanitizer.IsValidEmail(email))
                throw new ArgumentException("Invalid email format.");

            string passwordHash = PasswordHasher.HashPassword(password);

            const string query = @"
                INSERT INTO Users (Username, Email, PasswordHash, Role)
                VALUES (@Username, @Email, @PasswordHash, @Role);";

            using var connection = new SqlConnection(_connectionString);
            using var command = new SqlCommand(query, connection);

            command.Parameters.Add("@Username", SqlDbType.VarChar, 50).Value = username;
            command.Parameters.Add("@Email", SqlDbType.VarChar, 100).Value = email;
            command.Parameters.Add("@PasswordHash", SqlDbType.VarChar, 255).Value = passwordHash;
            command.Parameters.Add("@Role", SqlDbType.VarChar, 20).Value = role;

            connection.Open();
            command.ExecuteNonQuery();
        }

        public User? AuthenticateUser(string username, string password)
        {
            if (!InputSanitizer.IsValidUsername(username))
                return null;

            const string query = @"
                SELECT UserID, Username, Email, PasswordHash, Role
                FROM Users
                WHERE Username = @Username;";

            using var connection = new SqlConnection(_connectionString);
            using var command = new SqlCommand(query, connection);
            command.Parameters.Add("@Username", SqlDbType.VarChar, 50).Value = username;

            connection.Open();
            using var reader = command.ExecuteReader();

            if (!reader.Read())
                return null;

            string storedHash = reader["PasswordHash"].ToString() ?? string.Empty;
            if (!PasswordHasher.VerifyPassword(password, storedHash))
                return null;

            return new User
            {
                UserID = Convert.ToInt32(reader["UserID"]),
                Username = reader["Username"].ToString() ?? string.Empty,
                Email = reader["Email"].ToString() ?? string.Empty,
                Role = reader["Role"].ToString() ?? "User"
            };
        }
    }

    public class AdminDashboardController
    {
        // Role-Based Access Control (RBAC) enforcement
        public string AccessAdminDashboard(User? currentUser)
        {
            if (currentUser == null)
                throw new UnauthorizedAccessException("Authentication required.");

            if (!string.Equals(currentUser.Role, "Admin", StringComparison.OrdinalIgnoreCase))
                throw new UnauthorizedAccessException("Access denied: Admin role required.");

            string safeName = InputSanitizer.SanitizeForOutput(currentUser.Username);
            return $"Welcome to the Admin Dashboard, {safeName}.";
        }
    }
}
