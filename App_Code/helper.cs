using MySql.Data.MySqlClient;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data;
using System.IO;
using System.Linq;
using System.Web;
using System.Web.Script.Serialization;
using System.Web.Services;

/// <summary>
/// Summary description for helper
/// </summary>
public class helper
{
    public helper()
    {
        //
        // TODO: Add constructor logic here
        //
    }

    public string token, status, message;


    // =========================================================================
    // INTERNAL UTILITIES
    // =========================================================================

    /// <summary>
    /// Safely reads a column value from a reader.
    /// Returns null if column is DBNull or doesn't exist.
    /// </summary>
    private static object SafeGet(MySqlDataReader dr, string col)
    {
        try
        {
            int ord = dr.GetOrdinal(col);
            return dr.IsDBNull(ord) ? null : dr.GetValue(ord);
        }
        catch { return null; }
    }

    /// <summary>
    /// Reads ALL columns from the current reader row into a Dictionary.
    /// </summary>
    private static Dictionary<string, object> ReadRow(MySqlDataReader dr)
    {
        var row = new Dictionary<string, object>();
        for (int i = 0; i < dr.FieldCount; i++)
            row[dr.GetName(i)] = dr.IsDBNull(i) ? null : dr.GetValue(i);
        return row;
    }

    /// <summary>
    /// Standard error JSON response.
    /// </summary>
    public static string ErrorResponse(string errorCode, string message)
    {
        return JsonConvert.SerializeObject(new
        {
            success = 0,
            error_code = errorCode,
            message = message
        });
    }

    /// <summary>
    /// Standard success JSON response (action — no data).
    /// </summary>
    public static string SuccessResponse(string message)
    {
        return JsonConvert.SerializeObject(new
        {
            success = 1,
            message = message
        });
    }


    // =========================================================================
    // PRODUCTION-SAFE ERROR HANDLING
    //
    // Never send raw ex.Message to the client in production — it can leak SQL
    // error text, internal file paths, or schema details. Instead:
    //   - Always log the FULL exception server-side to App_Data/error_log.txt
    //   - Return ex.Message to the client ONLY when Web.config's
    //     appSettings key "IsDevEnvironment" is "true"; otherwise return a
    //     generic message.
    //
    // Requires the App_Data folder to exist and be writable by the App Pool
    // identity (it already exists in this solution — visible in Solution Explorer).
    // =========================================================================

    private static bool IsDevEnvironment()
    {
        string flag = ConfigurationManager.AppSettings["IsDevEnvironment"];
        return string.Equals(flag, "true", StringComparison.OrdinalIgnoreCase);
    }

    private static void LogError(Exception ex, string context)
    {
        try
        {
            string logPath = HttpContext.Current != null
                ? HttpContext.Current.Server.MapPath("~/App_Data/error_log.txt")
                : null;

            if (string.IsNullOrEmpty(logPath))
                return;

            string entry = string.Format(
                "[{0:yyyy-MM-dd HH:mm:ss}] {1}{2}{3}{2}{2}",
                DateTime.Now, context, Environment.NewLine, ex);

            File.AppendAllText(logPath, entry);
        }
        catch
        {
            // Never let logging failures bubble up and break the actual response.
        }
    }

    /// <summary>
    /// Builds the client-facing error JSON for an unhandled exception:
    /// full detail in dev, generic message in production. Always logs full detail.
    /// </summary>
    private static string HandleException(Exception ex, string context, string fallbackMessage)
    {
        LogError(ex, context);

        string clientMessage = IsDevEnvironment()
            ? ex.Message
            : fallbackMessage;

        return ErrorResponse("SYSTEM_ERROR", clientMessage);
    }


    // =========================================================================
    // 1. LOGIN
    //    SP must have OUT params: @o_token, @o_expires_at, @o_errorout
    //    Returns: { status, message, token, expires_at }
    // =========================================================================
    public string ExecuteLoginProcedure(
        string procName,
        Dictionary<string, object> parameters,
        string successMsg,
        string failMsg)
    {
        try
        {
            using (var con = DB.GetConnection())
            using (var cmd = new MySqlCommand(procName, con)
            {
                CommandType = CommandType.StoredProcedure
            })
            {
                foreach (var p in parameters)
                    cmd.Parameters.AddWithValue(p.Key, p.Value ?? DBNull.Value);

                cmd.Parameters.Add("@o_token", MySqlDbType.VarChar, 255)
                   .Direction = ParameterDirection.Output;

                cmd.Parameters.Add("@o_expires_at", MySqlDbType.DateTime)
                   .Direction = ParameterDirection.Output;

                // NOTE: standardized to @o_errorout (was @errorout) so Login and
                // Logout SPs share the same output-param naming convention.
                cmd.Parameters.Add("@o_errorout", MySqlDbType.Int32)
                   .Direction = ParameterDirection.Output;

                con.Open();
                cmd.ExecuteNonQuery();

                int result = Convert.ToInt32(cmd.Parameters["@o_errorout"].Value);
                bool ok = result == 1;

                string token = ok && cmd.Parameters["@o_token"].Value != DBNull.Value
                    ? cmd.Parameters["@o_token"].Value.ToString()
                    : null;

                string expiry = ok && cmd.Parameters["@o_expires_at"].Value != DBNull.Value
                    ? Convert.ToDateTime(cmd.Parameters["@o_expires_at"].Value)
                        .ToString("yyyy-MM-dd HH:mm:ss")
                    : null;

                return JsonConvert.SerializeObject(new
                {
                    status = ok ? "success" : "error",
                    message = ok ? successMsg : failMsg,
                    token = ok ? token : null,
                    expires_at = ok ? expiry : null
                });
            }
        }
        catch (Exception ex)
        {
            LogError(ex, "ExecuteLoginProcedure: " + procName);
            return JsonConvert.SerializeObject(new
            {
                status = "error",
                message = failMsg,
                error = IsDevEnvironment() ? ex.Message : null
            });
        }
    }


    // =========================================================================
    // 2. LOGOUT
    //    SP has OUT param: @o_errorout
    //    Returns: { success, message }
    // =========================================================================
    public string ExecuteLogoutProcedure(
        string procName,
        Dictionary<string, object> parameters)
    {
        try
        {
            using (var con = DB.GetConnection())
            using (var cmd = new MySqlCommand(procName, con)
            {
                CommandType = CommandType.StoredProcedure
            })
            {
                foreach (var p in parameters)
                    cmd.Parameters.AddWithValue(p.Key, p.Value ?? DBNull.Value);

                cmd.Parameters.Add("@o_errorout", MySqlDbType.Int32)
                 .Direction = ParameterDirection.Output;

                con.Open();
                cmd.ExecuteNonQuery();


                int result = Convert.ToInt32(cmd.Parameters["@o_errorout"].Value);

                return result == 1
                    ? SuccessResponse("Logged out successfully.")
                    : ErrorResponse("LOGOUT_FAILED", "Logout failed.");
            }
        }
        catch (Exception ex)
        {
            return HandleException(ex, "ExecuteLogoutProcedure: " + procName, "Logout failed. Please try again.");
        }
    }


    // =========================================================================
    // 3. EXECUTE PROCEDURE (INSERT / UPDATE / DELETE)
    //    SP returns a single-row resultset: SELECT success, error_code, message
    //    Returns: { success, error_code, message }
    // =========================================================================
    public string ExecuteProcedure(
    string procName,
    Dictionary<string, object> parameters)
    {
        try
        {
            using (var con = DB.GetConnection())
            using (var cmd = new MySqlCommand(procName, con)
            {
                CommandType = CommandType.StoredProcedure
            })
            {
                foreach (var kvp in parameters)
                    cmd.Parameters.AddWithValue(kvp.Key, kvp.Value ?? DBNull.Value);
                con.Open();
                using (var dr = cmd.ExecuteReader())
                {
                    do
                    {
                        if (dr.Read())
                        {
                            var row = new Dictionary<string, object>();
                            for (int i = 0; i < dr.FieldCount; i++)
                            {
                                row[dr.GetName(i)] = dr.IsDBNull(i) ? null : dr.GetValue(i);
                            }
                            return JsonConvert.SerializeObject(row);
                        }
                    }
                    while (dr.NextResult());
                }
            }
        }
        catch (Exception ex)
        {
            return HandleException(ex, "ExecuteProcedure: " + procName, "The operation could not be completed. Please try again.");
        }
        return ErrorResponse("NO_RESPONSE", "No response from server.");
    }


    // =========================================================================
    // 4. EXECUTE READER — returns a LIST of rows
    //    SP: first row must have success=1 (or success=0 + error_code + message).
    //    Returns: { success:1, data:[{...},...] }  OR  { success:0, error_code, message }
    //
    //    Use mapRow overload when you want to control column mapping.
    //    Use the auto overload when you want all columns returned as-is.
    // =========================================================================

    /// <summary>Custom row mapping.</summary>
    public string ExecuteReader(
        string procName,
        Dictionary<string, object> parameters,
        Func<MySqlDataReader, object> mapRow)
    {
        var results = new List<object>();

        try
        {
            using (var con = DB.GetConnection())
            using (var cmd = new MySqlCommand(procName, con)
            {
                CommandType = CommandType.StoredProcedure
            })
            {
                foreach (var kvp in parameters)
                    cmd.Parameters.AddWithValue(kvp.Key, kvp.Value ?? DBNull.Value);

                con.Open();

                using (var dr = cmd.ExecuteReader())
                {
                    // Empty result = valid success (no records found)
                    if (!dr.Read())
                        return JsonConvert.SerializeObject(new { success = 1, data = new object[0] });

                    // Check if SP returned an error row
                    int success = Convert.ToInt32(SafeGet(dr, "success") ?? 1);
                    if (success == 0)
                    {
                        return JsonConvert.SerializeObject(new
                        {
                            success = 0,
                            error_code = SafeGet(dr, "error_code"),
                            message = SafeGet(dr, "message")
                        });
                    }

                    // Map first row (already Read above)
                    var first = mapRow(dr);
                    if (first != null) results.Add(first);

                    // Map remaining rows
                    while (dr.Read())
                    {
                        var row = mapRow(dr);
                        if (row != null) results.Add(row);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            return HandleException(ex, "ExecuteReader: " + procName, "Could not load data. Please try again.");
        }

        return JsonConvert.SerializeObject(new { success = 1, data = results });
    }

    /// <summary>Auto column mapping — all columns returned as-is.</summary>
    public string ExecuteReader(
        string procName,
        Dictionary<string, object> parameters)
    {
        return ExecuteReader(procName, parameters, dr => ReadRow(dr));
    }


    // =========================================================================
    // 5. EXECUTE SINGLE ROW READER
    //    SP returns exactly one data row (e.g. GetStaffById, GetInwardDetail).
    //    Returns: { success:1, data:{...} }  OR  { success:0, error_code, message }
    // =========================================================================
    public string ExecuteSingleReader(
        string procName,
        Dictionary<string, object> parameters)
    {
        try
        {
            using (var con = DB.GetConnection())
            using (var cmd = new MySqlCommand(procName, con)
            {
                CommandType = CommandType.StoredProcedure
            })
            {
                foreach (var kvp in parameters)
                    cmd.Parameters.AddWithValue(kvp.Key, kvp.Value ?? DBNull.Value);

                con.Open();

                using (var dr = cmd.ExecuteReader())
                {
                    if (!dr.Read())
                        return ErrorResponse("NOT_FOUND", "Record not found.");

                    int success = Convert.ToInt32(SafeGet(dr, "success") ?? 1);
                    if (success == 0)
                    {
                        return JsonConvert.SerializeObject(new
                        {
                            success = 0,
                            error_code = SafeGet(dr, "error_code"),
                            message = SafeGet(dr, "message")
                        });
                    }

                    return JsonConvert.SerializeObject(new
                    {
                        success = 1,
                        data = ReadRow(dr)
                    });
                }
            }
        }
        catch (Exception ex)
        {
            return HandleException(ex, "ExecuteSingleReader: " + procName, "Could not load data. Please try again.");
        }
    }


    // =========================================================================
    // OUTPUT PARAM DESCRIPTOR — replaces tuple (C# 5 compatible)
    // =========================================================================
    public class OutputParam
    {
        public string Name { get; set; }
        public MySqlDbType Type { get; set; }
        public int Size { get; set; }

        public OutputParam(string name, MySqlDbType type, int size)
        {
            Name = name;
            Type = type;
            Size = size;
        }
    }


    // =========================================================================
    // 6. EXECUTE PROCEDURE WITH OUTPUT PARAMS
    // =========================================================================
    public string ExecuteProcedureWithOutput(
        string procName,
        Dictionary<string, object> inputParams,
        List<OutputParam> outputParams)
    {
        try
        {
            using (var con = DB.GetConnection())
            using (var cmd = new MySqlCommand(procName, con)
            {
                CommandType = CommandType.StoredProcedure
            })
            {
                foreach (var p in inputParams)
                    cmd.Parameters.AddWithValue(p.Key, p.Value ?? DBNull.Value);
                foreach (var op in outputParams)
                {
                    var param = cmd.Parameters.Add(op.Name, op.Type, op.Size);
                    param.Direction = ParameterDirection.Output;
                }
                con.Open();
                cmd.ExecuteNonQuery();

                // Standardized: SP output-param convention is @o_errorout everywhere
                // (Login/Logout above and any custom SP using this method should follow suit).
                string errorOutParamName = null;
                foreach (var op in outputParams)
                {
                    if (op.Name == "@o_errorout" || op.Name == "@errorout")
                    {
                        errorOutParamName = op.Name;
                        break;
                    }
                }

                int errorout = errorOutParamName != null
                    ? Convert.ToInt32(cmd.Parameters[errorOutParamName].Value)
                    : 1;

                bool ok = errorout == 1;
                var result = new Dictionary<string, object>();
                result["success"] = ok ? 1 : 0;
                result["message"] = ok ? "Operation successful." : "Operation failed.";
                foreach (var op in outputParams)
                {

                    result[op.Name.TrimStart('@')] =
                        cmd.Parameters[op.Name].Value == DBNull.Value
                        ? null
                        : cmd.Parameters[op.Name].Value;
                }
                return JsonConvert.SerializeObject(result);
            }
        }
        catch (Exception ex)
        {
            return HandleException(ex, "ExecuteProcedureWithOutput: " + procName, "The operation could not be completed. Please try again.");
        }
    }

    // =========================================================================
    // 7. EXECUTE MULTI-RESULTSET READER
    // =========================================================================
    public string ExecuteMultiReader(
        string procName,
        Dictionary<string, object> parameters,
        string headerKey,
        string listKey)
    {
        try
        {
            using (var con = DB.GetConnection())
            using (var cmd = new MySqlCommand(procName, con)
            {
                CommandType = CommandType.StoredProcedure
            })
            {
                foreach (var kvp in parameters)
                    cmd.Parameters.AddWithValue(kvp.Key, kvp.Value ?? DBNull.Value);

                con.Open();

                using (var dr = cmd.ExecuteReader())
                {
                    Dictionary<string, object> header = null;

                    if (dr.Read())
                    {
                        int success = Convert.ToInt32(SafeGet(dr, "success") ?? 1);
                        if (success == 0)
                        {
                            return JsonConvert.SerializeObject(new
                            {
                                success = 0,
                                error_code = SafeGet(dr, "error_code"),
                                message = SafeGet(dr, "message")
                            });
                        }
                        header = ReadRow(dr);
                    }

                    var items = new List<Dictionary<string, object>>();
                    if (dr.NextResult())
                    {
                        while (dr.Read())
                            items.Add(ReadRow(dr));
                    }

                    var result = new Dictionary<string, object>();
                    result["success"] = 1;
                    result[headerKey] = header;
                    result[listKey] = items;

                    return JsonConvert.SerializeObject(result);
                }
            }
        }
        catch (Exception ex)
        {
            return HandleException(ex, "ExecuteMultiReader: " + procName, "Could not load data. Please try again.");
        }
    }
}
