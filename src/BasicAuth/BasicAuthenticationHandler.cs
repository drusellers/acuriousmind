namespace ACuriousMind.BasicAuth;

using System.Text;
using System.Text.Encodings.Web;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

public class BasicAuthenticationHandler : AuthenticationHandler<BasicAuthenticationOptions>
{
    /// <summary>
    /// ctor
    /// </summary>
    public BasicAuthenticationHandler(IOptionsMonitor<BasicAuthenticationOptions> options, ILoggerFactory logger, UrlEncoder encoder)
        : base(options, logger, encoder)
    {
    }

    /// <summary>
    /// The handler calls methods on the events which give the application control at certain points where processing is occurring.
    /// If it is not provided a default instance is supplied which does nothing when the methods are called.
    /// </summary>
    protected new BasicAuthenticationEvents Events
    {
        get => (BasicAuthenticationEvents)base.Events!;
        set => base.Events = value;
    }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var headers = Context.Request.Headers.Authorization;
        if (!headers.Any())
        {
            Logger.LogInformation("Missing Authorization Header");
            return FailRequest("Missing Authorization Header");
        }

        var header = headers[0];
        if (header == null)
        {
            Logger.LogInformation("Missing Authorization Header");
            return FailRequest("Missing Authorization Header");
        }

        var credentials = header.Split(' ');
        if (credentials.Length != 2)
        {
            Logger.LogInformation("Malformed Authorization Header");
            return FailRequest("Malformed Authorization Header");
        }


        var scheme = credentials[0];
        if (scheme != Scheme.Name)
        {
            Logger.LogInformation("Mismatched Scheme Stopping Process: {Actual} != {Configured}", scheme, Scheme.Name);
            return AuthenticateResult.NoResult();
        }

        var decoded = "";
        try
        {
            decoded = Encoding.UTF8.GetString(Convert.FromBase64String(credentials[1]));
            if (!decoded.Contains(':'))
                return FailRequest("Malformed Authorization Header Content");
        }
        catch (FormatException)
        {
            Logger.LogWarning("Basic Auth Header: {Auth}", header);
            return FailRequest("Malformed Authorization Header Content");
        }


        var parts = decoded.Split(':');

        if (parts.Length != 2)
            return FailRequest("Malformed Authorization Header Content");


        var username = parts[0];
        var password = parts[1];

        var properties = new AuthenticationProperties();
        var context = new BasicAuthenticationCreatingTicketContext(Context, username, password, properties);

        await Events.CreatingTicket(context);


        if (context.Principal == null)
        {
            var failContext = new BasicAuthenticationFailedTicketContext(Context, username, properties);
            await Events.FailedTicket(failContext);
            Logger.LogInformation("No User '{Scheme}/{User}' Found", base.Scheme.Name, username);
            return FailRequest("User not authenticated");
        }

        // on success event
        var ticket = new AuthenticationTicket(context.Principal, properties, BasicAuthenticationDefaults.AuthenticationScheme);
        var successContext = new BasicAuthenticationCreatedTicketContext(Context, ticket, properties);
        await Events.CreatedTicket(successContext);

        return AuthenticateResult.Success(ticket);
    }

    AuthenticateResult FailRequest(string message)
    {
        if(Options.IncludeWwwAuthenticateHeader)
            Context.Response.Headers.Append("WWW-Authenticate",$"Basic realm=\"{Options.Realm}\"");

        return AuthenticateResult.Fail(message);
    }
}
