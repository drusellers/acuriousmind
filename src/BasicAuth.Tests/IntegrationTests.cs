namespace BasicAuth.Tests;

using System.Net;
using System.Net.Http.Headers;
using System.Net.Mime;
using ACuriousMind.BasicAuth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Net.Http.Headers;

public class BasicIntegrationTests
{
    [Test]
    public async Task Authenticated()
    {
        using var server = CreateServer(options =>
        {

        });

        using var client = server.CreateClient();

        // Arrange
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://example.com");
        request.Headers.Authorization = new AuthenticationHeaderValue("Basic", BasicCreds.Build("a","b"));

        // Act
        using var response = await client.SendAsync(request);

        // Assert
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.OK));
    }

    [Test]
    public async Task Challenge()
    {
        using var server = CreateServer(options =>
        {

        });

        using var client = server.CreateClient();

        // Arrange
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://example.com");
        // - no header

        // Act
        using var response = await client.SendAsync(request);

        // Assert
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
        AssertWwwAuthenticate(response);
    }

    [Test]
    public async Task Challenge_NoHeader()
    {
        using var server = CreateServer(options =>
        {
            options.IncludeWwwAuthenticateHeader = false;
        });

        using var client = server.CreateClient();

        // Arrange
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://example.com");
        // - no header

        // Act
        using var response = await client.SendAsync(request);

        // Assert
        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
        Assert.That(response.Headers.Contains(HeaderNames.WWWAuthenticate), Is.False);
    }

    static TestServer CreateServer(Action<BasicAuthenticationOptions> configureOptions)
    {
        // Not using WebApplicationFactory<> since we don't have a Startup / Program class
        var builder = new WebHostBuilder()
            .ConfigureServices(services =>
            {
                services.AddAuthentication(options =>
                {
                    // Prevents from System.InvalidOperationException: No authenticationScheme was specified, and there was no DefaultAuthenticateScheme found.
                    options.DefaultAuthenticateScheme = BasicAuthenticationDefaults.AuthenticationScheme;

                    // Prevents from System.InvalidOperationException: No authenticationScheme was specified, and there was no DefaultChallengeScheme found.
                    options.DefaultChallengeScheme = BasicAuthenticationDefaults.AuthenticationScheme;
                })
                .AddBasic(configureOptions);
            })
            .Configure(app =>
            {
                app.UseAuthentication();

                // A route for us to use
                app.Use(async (HttpContext context, Func<Task> next) =>
                {
                    var authenticationResult = await context.AuthenticateAsync();
                    if (authenticationResult.Succeeded)
                    {
                        context.Response.StatusCode = StatusCodes.Status200OK;
                        context.Response.ContentType = new ContentType("text/plain").MediaType;

                        await context.Response.WriteAsync("Hello");
                    }
                    else
                    {
                        await context.ChallengeAsync();
                    }
                });
            });


        return new TestServer(builder);
    }


    static void AssertWwwAuthenticate(HttpResponseMessage response)
    {
        Assert.That(response.Headers.Contains("WWW-Authenticate"), Is.True);
        var header = response.Headers.WwwAuthenticate;
        Assert.That(header.Count, Is.EqualTo(1));
        Assert.That(header.ToString(), Is.EqualTo("Basic realm=\"API\""));
    }
}
