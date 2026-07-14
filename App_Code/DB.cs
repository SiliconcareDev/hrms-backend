using MySql.Data.MySqlClient;
using System.Configuration;

/// <summary>
/// Central DB connection factory for HRMS.
/// Add the connection string to Web.config under &lt;connectionStrings&gt; with key "HRMSConnection":
///   &lt;connectionStrings&gt;
///     &lt;add name="HRMSConnection" connectionString="server=...;database=...;uid=...;pwd=...;" providerName="MySql.Data.MySqlClient" /&gt;
///   &lt;/connectionStrings&gt;
/// </summary>
public class DB
{
    public static MySqlConnection GetConnection()
    {
        return new MySqlConnection(
            ConfigurationManager.ConnectionStrings["HRMSConnection"].ConnectionString
        );
    }
}
