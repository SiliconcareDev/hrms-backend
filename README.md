# HRMS Backend

Attendance Management System — backend service, built with **C# ASMX Web Services** on **.NET Framework 4.8**, using **MySQL** (stored procedures) for data access.

---

## Tech Stack

- **Language/Framework:** C#, ASP.NET Web Services (ASMX), .NET Framework 4.8
- **Database:** MySQL (accessed exclusively via stored procedures)
- **Auth:** JWT (HS256, custom implementation — no external JWT library) in an HttpOnly cookie + CSRF double-submit token
- **Password hashing:** bcrypt (via `BCrypt.Net-Next`, work factor 12)
- **Hosting target:** IIS on Windows (cloud VM or Windows-based shared hosting)

---

## Project Structure

```
hrms-backend/
├── api/                        # ASMX web services (one file per module)
│   └── Login.asmx / .asmx.cs   # Auth: LoginUser, Logout, CheckSession
├── App_Code/                   # Shared C# helper classes
│   ├── helper.cs               # Generic SP-execution wrappers (ExecuteReader, ExecuteProcedure, etc.)
│   ├── DB.cs                   # MySQL connection factory
│   ├── JwtHelper.cs            # JWT generate/validate, cookie read/write, CSRF, rate limiting
│   ├── AuthGuard.cs            # Centralized per-request auth + role check for WebMethods
│   └── PasswordHelper.cs       # bcrypt hash/verify
├── App_Data/                   # Runtime data (error_log.txt) — not committed
├── Global.asax / .asax.cs      # Dynamic CORS (origin allow-list) + preflight handling
├── Web.config                  # App settings, JWT config, machineKey, security headers
└── db.sql                      # Full MySQL schema + stored procedures + seed data
```

---

## Architecture Notes

- **Every DB call goes through a stored procedure** — no inline SQL in C#. Naming convention: `sp_{Verb}_{Entity}` (e.g. `sp_Get_EmployeeForLogin`, `sp_Insert_AuditLog`).
- **Auth flow:** login verifies a bcrypt hash fetched via SP, then issues a JWT (HttpOnly, `Secure`, cookie name `hrms_auth`) plus a separate readable CSRF cookie (`hrms_csrf`). Every protected WebMethod calls `AuthGuard.Require(Context, "Role1", "Role2")` to validate both in one line.
- **CORS is NOT static in Web.config.** Because `Access-Control-Allow-Origin` (specific origin) and `Access-Control-Allow-Credentials: true` (required for the cookie) can't both be wildcard, `Global.asax.cs` reflects back the request's `Origin` header only if it's present in the `AllowedOrigins` app setting — this lets both `localhost` (dev) and the production frontend domain work without code changes.
- **Errors are never leaked raw to the client.** Every catch block logs the full exception to `App_Data/error_log.txt` and returns a generic message in production; set `IsDevEnvironment=true` in Web.config to see full exception text during local debugging.
- **`machineKey` is pinned** in Web.config so JWTs/sessions survive IIS App Pool recycles.

---

## Local Setup

1. Clone the repo and open in Visual Studio.
2. Restore NuGet packages (`MySql.Data`, `Newtonsoft.Json`, `BCrypt.Net-Next`).
3. Add your connection string in `Web.config`:
   ```xml
   <connectionStrings>
     <add name="HRMSConnection"
          connectionString="server=...;database=...;uid=...;pwd=...;"
          providerName="MySql.Data.MySqlClient" />
   </connectionStrings>
   ```
4. Set `JwtSecret` in `Web.config` `<appSettings>` to a real 64-char random string (never commit the real value).
5. Run `db.sql` against your MySQL database (via HeidiSQL / phpMyAdmin) — creates all tables, seed data, and stored procedures.
6. Generate a real bcrypt hash for the default admin user (see `PasswordHelper.Hash`) and update the `Employee` table's `PasswordHash` column — the value shipped in `db.sql` is a placeholder, not a working hash.
7. Run the project (F5) and confirm `Login.asmx` responds.

---

## Environments

| Setting | Dev | Prod |
|---|---|---|
| `IsDevEnvironment` | `true` | `false` |
| `AllowedOrigins` | includes `http://localhost:5173` | production frontend domain only (keep localhost too if needed for testing) |
| Cookie `Secure` flag | can be `false` for plain http local testing | must be `true` |

---

## Status

- [x] Auth (Login, Logout, CheckSession)
- [x] Database schema (25 tables — Employee, Attendance, Leave, Payroll, Permission Matrix, etc.)
- [ ] Employee Management module
- [ ] Shift & Roster module
- [ ] Attendance (check-in/out, GPS, selfie, QR)
- [ ] Leave Management
- [ ] Overtime
- [ ] Payroll
- [ ] Dashboards & Reports
