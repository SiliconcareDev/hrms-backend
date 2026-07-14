using System;
using System.Linq;
using System.Web;

/// <summary>
/// Centralized auth check for ASMX WebMethods. Wraps JwtHelper's cookie/CSRF/
/// token validation into a single call so every protected WebMethod doesn't
/// need to repeat the same 4-5 lines.
///
/// Usage inside a WebMethod:
///
///   [WebMethod]
///   public string GetEmployeeList()
///   {
///       AuthResult auth = AuthGuard.Require(Context, "Admin", "Manager");
///       if (!auth.Success)
///           return auth.ErrorJson;
///
///       // auth.StaffId, auth.Role, auth.Username, auth.FullName are now available
///       ...
///   }
///
/// No allowed-roles params = any authenticated user is fine:
///   AuthResult auth = AuthGuard.Require(Context);
/// </summary>
public static class AuthGuard
{
    public class AuthResult
    {
        public bool Success { get; set; }
        public int StaffId { get; set; }
        public string Username { get; set; }
        public string Role { get; set; }
        public string FullName { get; set; }
        public string ErrorJson { get; set; }
    }

    /// <summary>
    /// Validates the JWT cookie + CSRF header/cookie pair, and (optionally)
    /// restricts access to a specific set of roles.
    /// </summary>
    public static AuthResult Require(HttpContext context, params string[] allowedRoles)
    {
        HttpRequest request = context.Request;

        // ── 1. CSRF check first (cheap, rejects forged cross-site requests early) ──
        if (!JwtHelper.ValidateCsrf(request))
        {
            return new AuthResult
            {
                Success = false,
                ErrorJson = helper.ErrorResponse("CSRF_INVALID", "Invalid or missing CSRF token.")
            };
        }

        // ── 2. Read + validate JWT from HttpOnly cookie ─────────────────────────
        string token = JwtHelper.ReadTokenFromCookie(request);
        if (string.IsNullOrEmpty(token))
        {
            return new AuthResult
            {
                Success = false,
                ErrorJson = helper.ErrorResponse("NOT_AUTHENTICATED", "Session not found. Please log in again.")
            };
        }

        JwtHelper.JwtPayload payload = JwtHelper.Validate(token);
        if (payload == null)
        {
            return new AuthResult
            {
                Success = false,
                ErrorJson = helper.ErrorResponse("SESSION_EXPIRED", "Session expired. Please log in again.")
            };
        }

        // ── 3. Role check (only if the caller specified allowed roles) ─────────
        if (allowedRoles != null && allowedRoles.Length > 0)
        {
            bool roleOk = allowedRoles.Any(r =>
                string.Equals(r, payload.role, StringComparison.OrdinalIgnoreCase));

            if (!roleOk)
            {
                return new AuthResult
                {
                    Success = false,
                    ErrorJson = helper.ErrorResponse("FORBIDDEN", "You do not have permission to perform this action.")
                };
            }
        }

        // ── 4. All checks passed ─────────────────────────────────────────────────
        return new AuthResult
        {
            Success = true,
            StaffId = payload.staff_id,
            Username = payload.username,
            Role = payload.role,
            FullName = payload.full_name
        };
    }
}
