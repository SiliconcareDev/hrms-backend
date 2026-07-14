using System;
using System.Collections.Generic;
using System.Configuration;

using System.Linq;

//using System.Linq;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;

public partial class Global : System.Web.UI.UserControl
{


    // =========================================================================
    // CORS is handled HERE dynamically (not as static headers in web.config)
    // because Access-Control-Allow-Origin (specific origin) + Allow-Credentials
    // (true, required for the JWT HttpOnly cookie) cannot both be static/
    // wildcard — browsers reject "*" + credentials together. So on every
    // request we check the incoming Origin header against the AllowedOrigins
    // list in Web.config and reflect it back only if it matches.
    // =========================================================================
    protected void Application_BeginRequest(object sender, EventArgs e)
    {
        HttpContext ctx = HttpContext.Current;
        string origin = ctx.Request.Headers["Origin"];

        string allowedOriginsRaw = ConfigurationManager.AppSettings["AllowedOrigins"];
        string[] allowedOrigins = string.IsNullOrEmpty(allowedOriginsRaw)
            ? new string[0]
            : allowedOriginsRaw.Split(new[] { ',' }, StringSplitOptions.RemoveEmptyEntries);

        if (!string.IsNullOrEmpty(origin) &&
            allowedOrigins.Any(o => o.Trim().Equals(origin, StringComparison.OrdinalIgnoreCase)))
        {
            ctx.Response.Headers["Access-Control-Allow-Origin"] = origin;
            ctx.Response.Headers["Access-Control-Allow-Credentials"] = "true";
            ctx.Response.Headers["Access-Control-Allow-Methods"] = "POST, GET, OPTIONS";
            ctx.Response.Headers["Access-Control-Allow-Headers"] = "Content-Type, Accept, X-CSRF-Token";
        }

        // Browsers send a preflight OPTIONS request before the real POST for
        // cross-origin calls with custom headers (like X-CSRF-Token). Answer
        // it immediately with 200 and no body — don't let it reach ASMX.
        if (ctx.Request.HttpMethod == "OPTIONS")
        {
            ctx.Response.StatusCode = 200;
            ctx.Response.End();
        }
    }

    protected void Application_Start(object sender, EventArgs e)
    {
    }

    protected void Session_Start(object sender, EventArgs e)
    {
    }

    protected void Application_Error(object sender, EventArgs e)
    {
    }

    protected void Session_End(object sender, EventArgs e)
    {
    }

    protected void Application_End(object sender, EventArgs e)
    {
    }
}



