using System;
using System.Collections.Generic;
using System.Configuration;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using Newtonsoft.Json;

/// <summary>
/// Lightweight JWT helper (HS256) — no NuGet JWT dependency.
/// Fully compatible with C# 5 / .NET 4.x (ASP.NET WebForms / ASMX).
///
/// Web.config keys required:
///   <add key="JwtSecret"        value="your-secret-min-32-chars" />
///   <add key="JwtExpiryMinutes" value="480" />
/// </summary>
public static class JwtHelper
{
    // =========================================================================
    // CONFIG  —  loaded once in static constructor
    // =========================================================================

    private static readonly string Secret;
    private static readonly int ExpiryMinutes;

    // Add this helper at top of JwtHelper.cs
    private static DateTime NowIst()
    {
        TimeZoneInfo ist = TimeZoneInfo.FindSystemTimeZoneById("India Standard Time");
        return TimeZoneInfo.ConvertTimeFromUtc(DateTime.UtcNow, ist);
    }

    static JwtHelper()
    {
        // ── JwtSecret ────────────────────────────────────────────────────────
        // Cannot use ?? throw  (throw-expression is C# 7+).
        // Use explicit null check instead.
        string secret = ConfigurationManager.AppSettings["JwtSecret"];
        if (string.IsNullOrEmpty(secret))
            throw new InvalidOperationException("JwtSecret not configured in Web.config.");
        Secret = secret;

        // ── JwtExpiryMinutes ─────────────────────────────────────────────────
        // Cannot write  out int m  inline  (inline out-var is C# 6+).
        // Pre-declare the variable first.
        int m;
        ExpiryMinutes = int.TryParse(
            ConfigurationManager.AppSettings["JwtExpiryMinutes"], out m) ? m : 480;
    }

    // ── Cookie / Header name constants ────────────────────────────────────────
    // NOTE: renamed from panchayat_auth/panchayat_csrf (GramSarthi holdover) to
    // hrms_auth/hrms_csrf so this project's cookies never collide with GramSarthi's
    // if both ever end up sharing a domain/subdomain.
    public const string CookieName = "hrms_auth";
    public const string CsrfHeader = "X-CSRF-Token";
    public const string CsrfCookie = "hrms_csrf";


    // =========================================================================
    // INNER CLASSES
    // =========================================================================

    /// <summary>
    /// Claims stored inside the signed JWT.
    /// </summary>
    public class JwtPayload
    {
        public int staff_id { get; set; }
        public string username { get; set; }
        public string role { get; set; }
        public string full_name { get; set; }
        public long iat { get; set; }   // issued-at  (Unix seconds)
        public long exp { get; set; }   // expiry     (Unix seconds)
        public string jti { get; set; }   // unique token ID (jti claim)
    }

    /// <summary>
    /// Return value of Generate().
    /// Replaces the C# 7 value-tuple  (string token, DateTime expiresAt)
    /// with a plain class — fully C# 5 compatible.
    /// </summary>
    public class JwtResult
    {
        public string Token { get; set; }
        public DateTime ExpiresAt { get; set; }
    }

    /// <summary>
    /// Per-IP rate-limit tracking entry.
    /// Replaces the C# 7 value-tuple  (int count, DateTime window)
    /// used as a Dictionary value — fully C# 5 compatible.
    /// </summary>
    private class LoginAttemptEntry
    {
        public int Count { get; set; }
        public DateTime WindowEnd { get; set; }
    }


    // =========================================================================
    // TOKEN GENERATION
    // =========================================================================

    /// <summary>
    /// Generates a signed HS256 JWT for the given staff member.
    /// Returns a JwtResult with Token string and ExpiresAt datetime.
    /// </summary>
    public static JwtResult Generate(
        int staffId, string username, string role, string fullName)
    {
        DateTime now = NowIst();
        DateTime expiresAt = now.AddMinutes(ExpiryMinutes);

        JwtPayload payload = new JwtPayload
        {
            staff_id = staffId,
            username = username,
            role = role,
            full_name = fullName,
            iat = ToUnix(now),
            exp = ToUnix(expiresAt),
            jti = Guid.NewGuid().ToString("N")
        };

        string header = Base64UrlEncode(Encoding.UTF8.GetBytes(
                              JsonConvert.SerializeObject(new { alg = "HS256", typ = "JWT" })));
        string body = Base64UrlEncode(Encoding.UTF8.GetBytes(
                              JsonConvert.SerializeObject(payload)));
        string sigInput = header + "." + body;
        string sig = Sign(sigInput);

        return new JwtResult
        {
            Token = sigInput + "." + sig,
            ExpiresAt = expiresAt
        };
    }


    // =========================================================================
    // TOKEN VALIDATION
    // =========================================================================

    /// <summary>
    /// Validates a JWT string (signature + expiry).
    /// Returns the decoded JwtPayload on success, or null on any failure.
    /// </summary>
    public static JwtPayload Validate(string token)
    {
        try
        {
            // Null-conditional  ?.  is C# 6+ — use explicit null check.
            if (string.IsNullOrEmpty(token))
                return null;

            string[] parts = token.Split('.');
            if (parts.Length != 3)
                return null;

            string expectedSig = Sign(parts[0] + "." + parts[1]);
            if (!SlowEquals(expectedSig, parts[2]))
                return null;

            string json = Encoding.UTF8.GetString(Base64UrlDecode(parts[1]));
            JwtPayload payload = JsonConvert.DeserializeObject<JwtPayload>(json);

            if (payload == null || payload.exp < ToUnix(NowIst()))
                return null;

            return payload;
        }
        catch
        {
            return null;
        }
    }


    // =========================================================================
    // COOKIE HELPERS
    // =========================================================================

    /// <summary>
    /// Writes two cookies on successful login:
    ///   1. HttpOnly + Secure JWT cookie  (unreadable by JS — protects token)
    ///   2. Non-HttpOnly CSRF cookie      (JS reads this and sends as header)
    ///
    /// NOTE on SameSite: Strict works here as long as frontend and backend are
    /// served from subdomains of the SAME registrable domain (e.g. hrms.yoursite.com
    /// and api.yoursite.com) — browsers treat that as "same-site", so the cookie
    /// still gets sent on cross-subdomain fetch calls. If the frontend ever moves to
    /// a genuinely different domain (e.g. a *.vercel.app URL), switch this to
    /// SameSiteMode.None (which requires Secure=true, already set below).
    /// </summary>
    public static void WriteAuthCookies(
     HttpResponse response,
     string token,
     DateTime expiresAt,
     string csrfToken)
    {
        // ── Auth cookie ───────────────────────────────────────────────────────
        HttpCookie authCookie = new HttpCookie(CookieName);
        authCookie.Value = Uri.EscapeDataString(token);
        authCookie.HttpOnly = true;
        authCookie.Secure = true;
        authCookie.Expires = expiresAt;
        authCookie.Path = "/";
        authCookie.SameSite = SameSiteMode.Strict;
        response.Cookies.Add(authCookie);

        // ── CSRF cookie ───────────────────────────────────────────────────────
        HttpCookie csrfCookie = new HttpCookie(CsrfCookie, csrfToken);
        csrfCookie.HttpOnly = false;
        csrfCookie.Secure = true;
        csrfCookie.Expires = expiresAt;
        csrfCookie.Path = "/";
        csrfCookie.SameSite = SameSiteMode.Strict;
        response.Cookies.Add(csrfCookie);
    }

    /// <summary>
    /// Expires both cookies immediately (logout).
    /// </summary>
    public static void ClearAuthCookies(HttpResponse response)
    {
        HttpCookie authCookie = new HttpCookie(CookieName);
        authCookie.Expires = NowIst().AddDays(-1);
        authCookie.HttpOnly = true;
        authCookie.Secure = true;
        authCookie.Path = "/";
        response.Cookies.Add(authCookie);

        HttpCookie csrfCookie = new HttpCookie(CsrfCookie);
        csrfCookie.Expires = NowIst().AddDays(-1);
        csrfCookie.Path = "/";
        response.Cookies.Add(csrfCookie);
    }

    /// <summary>
    /// Reads the raw JWT string from the auth cookie.
    /// Returns null if the cookie is absent.
    /// </summary>
    public static string ReadTokenFromCookie(HttpRequest request)
    {
        HttpCookie cookie = request.Cookies[CookieName];
        if (cookie == null)
            return null;
        return Uri.UnescapeDataString(cookie.Value);
    }


    // =========================================================================
    // CSRF
    // =========================================================================

    /// <summary>
    /// Generates a cryptographically random 32-byte CSRF token (Base64Url).
    /// </summary>
    public static string GenerateCsrfToken()
    {
        byte[] bytes = new byte[32];
        using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider())
        {
            rng.GetBytes(bytes);
        }
        return Convert.ToBase64String(bytes)
                      .Replace("+", "-")
                      .Replace("/", "_")
                      .TrimEnd('=');
    }

    /// <summary>
    /// Validates CSRF: CSRF cookie value must match the X-CSRF-Token request header.
    /// Constant-time comparison prevents timing attacks.
    /// </summary>
    public static bool ValidateCsrf(HttpRequest request)
    {
        // Null-conditional  ?.  is C# 6+ — use explicit null check.
        HttpCookie cookie = request.Cookies[CsrfCookie];
        string cookieVal = (cookie != null) ? cookie.Value : null;
        string headerVal = request.Headers[CsrfHeader];

        if (string.IsNullOrEmpty(cookieVal) || string.IsNullOrEmpty(headerVal))
            return false;

        return SlowEquals(cookieVal, headerVal);
    }


    // =========================================================================
    // RATE LIMITER  (in-memory, per IP)
    // =========================================================================

    private static readonly Dictionary<string, LoginAttemptEntry> _loginAttempts
        = new Dictionary<string, LoginAttemptEntry>();

    private static readonly object _lock = new object();

    private const int MaxAttempts = 5;
    private const int WindowMinutes = 10;

    /// <summary>
    /// Returns true if this IP may attempt login.
    /// Automatically increments the counter on every call.
    /// Call this BEFORE verifying credentials.
    /// </summary>
    public static bool IsLoginAllowed(string ip)
    {
        lock (_lock)
        {
            // out var  is C# 7+ — declare type explicitly.
            LoginAttemptEntry entry;

            if (_loginAttempts.TryGetValue(ip, out entry))
            {
                // Window expired — reset counter
                if (DateTime.UtcNow > entry.WindowEnd)
                {
                    entry.Count = 1;
                    entry.WindowEnd = DateTime.UtcNow.AddMinutes(WindowMinutes);
                    return true;
                }

                // Already at limit
                if (entry.Count >= MaxAttempts)
                    return false;

                // Increment
                entry.Count = entry.Count + 1;
            }
            else
            {
                // First attempt from this IP
                _loginAttempts[ip] = new LoginAttemptEntry
                {
                    Count = 1,
                    WindowEnd = DateTime.UtcNow.AddMinutes(WindowMinutes)
                };
            }

            return true;
        }
    }

    /// <summary>
    /// Clears the attempt counter for an IP after a successful login.
    /// </summary>
    public static void ResetLoginAttempts(string ip)
    {
        lock (_lock)
        {
            _loginAttempts.Remove(ip);
        }
    }


    // =========================================================================
    // PRIVATE INTERNALS
    // =========================================================================

    private static string Sign(string input)
    {
        using (HMACSHA256 hmac = new HMACSHA256(Encoding.UTF8.GetBytes(Secret)))
        {
            byte[] hash = hmac.ComputeHash(Encoding.UTF8.GetBytes(input));
            return Base64UrlEncode(hash);
        }
    }

    // Expression-bodied members  =>  are C# 6+ — use full method bodies.

    private static string Base64UrlEncode(byte[] input)
    {
        return Convert.ToBase64String(input)
                      .Replace("+", "-")
                      .Replace("/", "_")
                      .TrimEnd('=');
    }

    private static byte[] Base64UrlDecode(string input)
    {
        string s = input.Replace("-", "+").Replace("_", "/");
        switch (s.Length % 4)
        {
            case 2: s += "=="; break;
            case 3: s += "="; break;
        }
        return Convert.FromBase64String(s);
    }

    private static long ToUnix(DateTime dt)
    {
        return (long)(dt.ToUniversalTime()
                      - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc))
                      .TotalSeconds;
    }

    /// <summary>
    /// Constant-time string comparison — prevents timing-based attacks.
    /// </summary>
    private static bool SlowEquals(string a, string b)
    {
        if (a == null || b == null)
            return false;
        int diff = a.Length ^ b.Length;
        for (int i = 0; i < a.Length && i < b.Length; i++)
            diff |= a[i] ^ b[i];
        return diff == 0;
    }
}
