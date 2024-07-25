namespace ACuriousMind.BasicAuth;

using System.Security.Principal;

public class BasicAuthenticationIdentity : IIdentity
{
    public BasicAuthenticationIdentity(string name)
    {
        Name = name;
    }

    public string? AuthenticationType => "Basic";

    public bool IsAuthenticated => true;

    public string? Name { get; init; }
}
