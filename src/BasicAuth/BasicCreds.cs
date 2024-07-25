namespace ACuriousMind.BasicAuth;

using System.Text;

public static class BasicCreds
{
    public static string Build(string username, string password = "")
    {
        return Convert.ToBase64String(Encoding.UTF8.GetBytes($"{username}:{password}"));
    }
}
