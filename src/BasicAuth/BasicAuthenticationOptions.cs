namespace ACuriousMind.BasicAuth;

using Microsoft.AspNetCore.Authentication;

public class BasicAuthenticationOptions : AuthenticationSchemeOptions
{
    public BasicAuthenticationOptions()
    {
        Events = new BasicAuthenticationEvents();
        Realm = BasicAuthenticationDefaults.Realm;
        IncludeWwwAuthenticateHeader = BasicAuthenticationDefaults.IncludeWwwAuthenticateHeader;
    }

    public string Realm { get; set; }
    public bool IncludeWwwAuthenticateHeader { get; set; }

    public new BasicAuthenticationEvents Events
    {
        get => (BasicAuthenticationEvents)base.Events!;
        set => base.Events = value;
    }


}
