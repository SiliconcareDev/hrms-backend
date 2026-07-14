using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Script.Serialization;
using System.Web.Script.Services;
using System.Web.Services;

/// <summary>
/// Login.asmx — authentication endpoint.
///
/// Flow:
///   1. LoginUser(username, password)
///        -> rate-limit check (JwtHelper.IsLoginAllowed)
///        -> sp_GetEmployee_ForLogin fetches stored hash + role
///        -> PasswordHelper.Verify compares plain password to bcrypt hash
///        -> on success: JwtHelper.Generate + WriteAuthCookies (HttpOnly JWT + CSRF)
///        -> sp_Insert_AuditLog records the login
///   2. Logout() -> clears both cookies
///   3. CheckSession() -> used by the frontend on page load to restore the
///      logged-in user without re-sending credentials
/// </summary>
/// 

[WebService(Namespace = "http://tempuri.org/")]
[WebServiceBinding(ConformsTo = WsiProfiles.BasicProfile1_1)]
// To allow this Web Service to be called from script, using ASP.NET AJAX, uncomment the following line. 
[System.Web.Script.Services.ScriptService]
public class Login : System.Web.Services.WebService
{

    public Login()
    {

        //Uncomment the following line if using designed components 
        //InitializeComponent(); 
    }

    private readonly helper _helper = new helper();

    [WebMethod(EnableSession = true)]
    [ScriptMethod(ResponseFormat = ResponseFormat.Json)]
    public string LoginUser(string username, string password)
    {
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
            return helper.ErrorResponse("INVALID_INPUT", "Username and password are required.");

        string ip = Context.Request.UserHostAddress;

        // ── Rate limiting — checked BEFORE hitting the DB ────────────────────
        if (!JwtHelper.IsLoginAllowed(ip))
            return helper.ErrorResponse("TOO_MANY_ATTEMPTS",
                "Too many login attempts. Please try again in a few minutes.");

        // ── Fetch employee record (hash + role) ──────────────────────────────
        var lookupParams = new Dictionary<string, object> { { "@p_username", username } };
        string rawResult = _helper.ExecuteSingleReader("sp_Get_EmployeeForLogin", lookupParams);

        var serializer = new JavaScriptSerializer();
        Dictionary<string, object> result = serializer.Deserialize<Dictionary<string, object>>(rawResult);

        int lookupSuccess = Convert.ToInt32(result["success"]);
        if (lookupSuccess == 0)
        {
            string errCode = result.ContainsKey("error_code") && result["error_code"] != null
                ? result["error_code"].ToString() : "LOGIN_FAILED";
            string errMsg = result.ContainsKey("message") && result["message"] != null
                ? result["message"].ToString() : "Invalid username or password.";
            return helper.ErrorResponse(errCode, errMsg);
        }

        var data = (Dictionary<string, object>)result["data"];
        string storedHash = data["PasswordHash"] != null ? data["PasswordHash"].ToString() : null;

        // ── Verify password (bcrypt, in C# — never in SQL) ───────────────────
        if (!PasswordHelper.Verify(password, storedHash))
            return helper.ErrorResponse("INVALID_CREDENTIALS", "Invalid username or password.");

        // ── Success: reset rate-limit counter, issue JWT + CSRF cookies ──────
        JwtHelper.ResetLoginAttempts(ip);

        int employeeId = Convert.ToInt32(data["EmployeeId"]);
        string fullName = data["FullName"] != null ? data["FullName"].ToString() : "";
        string role = data["RoleName"] != null ? data["RoleName"].ToString() : "";

        JwtHelper.JwtResult jwtResult = JwtHelper.Generate(employeeId, username, role, fullName);
        string csrfToken = JwtHelper.GenerateCsrfToken();

        JwtHelper.WriteAuthCookies(Context.Response, jwtResult.Token, jwtResult.ExpiresAt, csrfToken);

        // ── Audit log (best-effort — failure here should not block login) ───
        try
        {
            var auditParams = new Dictionary<string, object>
            {
                { "@p_employee_id", employeeId },
                { "@p_action_type", "Login" },
                { "@p_entity_name", "Employee" },
                { "@p_entity_id", employeeId },
                { "@p_details", "User logged in successfully." },
                { "@p_ip_address", ip }
            };
            _helper.ExecuteProcedure("sp_Insert_AuditLog", auditParams);
        }
        catch
        {
            // Audit logging must never break the login response itself.
        }

        return JsonConvert.SerializeObject(new
        {
            success = 1,
            message = "Login successful.",
            data = new
            {
                employeeId = employeeId,
                username = username,
                fullName = fullName,
                role = role
            }
        });
    }

    [WebMethod(EnableSession = true)]
    [ScriptMethod(ResponseFormat = ResponseFormat.Json)]
    public string Logout()
    {
        // Best-effort audit log before clearing cookies (auth is still valid here).
        try
        {
            AuthGuard.AuthResult auth = AuthGuard.Require(Context);
            if (auth.Success)
            {
                var auditParams = new Dictionary<string, object>
                {
                    { "@p_employee_id", auth.StaffId },
                    { "@p_action_type", "Logout" },
                    { "@p_entity_name", "Employee" },
                    { "@p_entity_id", auth.StaffId },
                    { "@p_details", "User logged out." },
                    { "@p_ip_address", Context.Request.UserHostAddress }
                };
                _helper.ExecuteProcedure("sp_Insert_AuditLog", auditParams);
            }
        }
        catch
        {
            // Never block logout on audit-log failure.
        }

        JwtHelper.ClearAuthCookies(Context.Response);
        return helper.SuccessResponse("Logged out successfully.");
    }

    /// <summary>
    /// Called by the frontend on app load / page refresh to check whether the
    /// HttpOnly JWT cookie still represents a valid session, and to restore
    /// the logged-in user's basic info without asking for credentials again.
    /// </summary>
    [WebMethod(EnableSession = true)]
    [ScriptMethod(ResponseFormat = ResponseFormat.Json)]
    public string CheckSession()
    {
        AuthGuard.AuthResult auth = AuthGuard.Require(Context);
        if (!auth.Success)
            return auth.ErrorJson;

        return JsonConvert.SerializeObject(new
        {
            success = 1,
            data = new
            {
                employeeId = auth.StaffId,
                username = auth.Username,
                fullName = auth.FullName,
                role = auth.Role
            }
        });
    }

}
