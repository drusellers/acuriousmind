namespace ACuriousMind.BasicAuth;

using System.Security.Claims;
using System.Security.Principal;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

public class BasicAuthenticationCreatingTicketContext
{
    public BasicAuthenticationCreatingTicketContext(HttpContext httpContext, string username, string password, AuthenticationProperties properties)
    {
        HttpContext = httpContext;
        Username = username;
        Password = password;
        Principal = new ClaimsPrincipal(new ClaimsIdentity(new GenericIdentity(username)));
        Properties = properties;
    }

    public string Username { get; }
    public string Password { get; }

    public HttpContext HttpContext { get; }

    public ClaimsPrincipal? Principal { get; private set; }
    public AuthenticationProperties Properties { get; private set; }

    public void ReplacePrincipal(ClaimsPrincipal principal)
    {
        Principal = principal;
    }

    public void RejectPrincipal()
    {
        Principal = null;
    }
}

public class BasicAuthenticationCreatedTicketContext
{
    public BasicAuthenticationCreatedTicketContext(HttpContext httpContext, AuthenticationTicket ticket, AuthenticationProperties properties)
    {
        HttpContext = httpContext;
        Ticket = ticket;
        Properties = properties;
    }

    public HttpContext HttpContext { get; }

    public AuthenticationTicket Ticket { get; private set; }
    public AuthenticationProperties Properties { get; private set; }
}

public class BasicAuthenticationFailedTicketContext
{
    public BasicAuthenticationFailedTicketContext(HttpContext httpContext, string username, AuthenticationProperties properties)
    {
        HttpContext = httpContext;
        Username = username;
        Principal = new ClaimsPrincipal(new ClaimsIdentity(new GenericIdentity(username)));
        Properties = properties;
    }

    public string Username { get; }

    public HttpContext HttpContext { get; }

    public ClaimsPrincipal? Principal { get; private set; }
    public AuthenticationProperties Properties { get; private set; }

    public void ReplacePrincipal(ClaimsPrincipal principal)
    {
        Principal = principal;
    }

    public void RejectPrincipal()
    {
        Principal = null;
    }
}
