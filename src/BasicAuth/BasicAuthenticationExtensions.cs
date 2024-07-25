namespace ACuriousMind.BasicAuth;

using Microsoft.AspNetCore.Authentication;

public static class BasicAuthenticationExtensions
{
    public static AuthenticationBuilder AddBasic(this AuthenticationBuilder builder, Action<BasicAuthenticationOptions> options)
    {
        return builder.AddBasic(BasicAuthenticationDefaults.AuthenticationScheme, options);
    }

    public static AuthenticationBuilder AddBasic(this AuthenticationBuilder builder, string scheme, Action<BasicAuthenticationOptions> options)
    {
        return builder.AddBasic(scheme, "Basic", options);
    }

    public static AuthenticationBuilder AddBasic(this AuthenticationBuilder builder, string scheme, string displayName, Action<BasicAuthenticationOptions> options)
    {
        return builder.AddScheme<BasicAuthenticationOptions, BasicAuthenticationHandler>(scheme, displayName, options);
    }
}
