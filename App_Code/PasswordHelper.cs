using BCrypt.Net;

/// <summary>
/// Password hashing/verification using bcrypt (work factor 12).
///
/// REQUIRES NuGet package: BCrypt.Net-Next
///   Install via Package Manager Console:
///     Install-Package BCrypt.Net-Next
///   or via NuGet Package Manager UI in Visual Studio (search "BCrypt.Net-Next").
///
/// Usage:
///   string hash = PasswordHelper.Hash(plainPassword);      // store this in DB
///   bool ok = PasswordHelper.Verify(plainPassword, hash);   // on login
/// </summary>
public static class PasswordHelper
{
    // Work factor 12 — same as GramSarthi. Higher = slower to hash (more
    // resistant to brute-force) but slower login too. 12 is the current
    // recommended balance for production use.
    private const int WorkFactor = 12;

    /// <summary>
    /// Hashes a plain-text password. The returned string includes the salt
    /// and work factor, so it's all you need to store — no separate salt column.
    /// </summary>
    public static string Hash(string plainPassword)
    {
        return BCrypt.Net.BCrypt.HashPassword(plainPassword, WorkFactor);
    }

    /// <summary>
    /// Verifies a plain-text password against a stored bcrypt hash.
    /// Returns false (not an exception) on any malformed-hash edge case.
    /// </summary>
    public static bool Verify(string plainPassword, string storedHash)
    {
        if (string.IsNullOrEmpty(plainPassword) || string.IsNullOrEmpty(storedHash))
            return false;

        try
        {
            return BCrypt.Net.BCrypt.Verify(plainPassword, storedHash);
        }
        catch
        {
            // Malformed/legacy hash in DB — treat as verification failure, not a crash.
            return false;
        }
    }
}
