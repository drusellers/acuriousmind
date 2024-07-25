namespace BasicAuth.Tests;

using System.Security.Claims;
using System.Security.Principal;
using System.Text.Encodings.Web;
using ACuriousMind.BasicAuth;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;

public class BasicAuthenticationHandlerTests
{
    [Test]
    public async Task HappyPath()
    {
        // Arrange
        var handler = await CreateHandler($"Basic {BasicCreds.Build("test","password")}");

        // Act
        var result = await handler.AuthenticateAsync();

        // Assert
        Assert.That(result.None, Is.False);
        Assert.That(result.Succeeded, Is.True);
        Assert.That(result.Failure, Is.Null);

        Assert.That(result.Ticket, Is.Not.Null);
        Assert.That(result.Principal, Is.Not.Null);
        Assert.That(result.Principal, Is.TypeOf(typeof(ClaimsPrincipal)));
        Assert.That(result.Principal!.Identity, Is.TypeOf(typeof(ClaimsIdentity)));
    }

    [Test]
    public async Task HappyPath_MissingUser()
    {
        // Arrange
        var handler = await CreateHandler($"Basic {BasicCreds.Build("test","password")}", options =>
        {
            options.Events.OnCreatingTicket = context =>
            {
                context.RejectPrincipal();
                return Task.CompletedTask;
            };
        });

        // Act
        var result = await handler.AuthenticateAsync();

        // Assert
        Assert.That(result.None, Is.False);
        Assert.That(result.Succeeded, Is.False);
        Assert.That(result.Failure, Is.Not.Null);
    }

    [Test]
    public async Task IgnoreMismatchScheme()
    {
        // Arrange
        var handler = await CreateHandler($"Bearer {BasicCreds.Build("test","password")}", options =>
        {
            options.Events.OnCreatingTicket = context =>
            {
                context.RejectPrincipal();
                return Task.CompletedTask;
            };
        });

        // Act
        var result = await handler.AuthenticateAsync();

        // Assert
        Assert.That(result.None, Is.True);
        Assert.That(result.Succeeded, Is.False);
        Assert.That(result.Failure, Is.Null);
    }

    [Test]
    public async Task CustomScheme()
    {
        // Arrange
        var handler = await CreateHandler($"WOW {BasicCreds.Build("test","password")}", options =>
        {

        }, "WOW");

        // Act
        var result = await handler.AuthenticateAsync();

        // Assert
        Assert.That(result.None, Is.False);
        Assert.That(result.Succeeded, Is.True);
        Assert.That(result.Failure, Is.Null);
    }

    [Test]
    public async Task HappyPath_FoundUser()
    {
        // Arrange
        var handler = await CreateHandler($"Basic {BasicCreds.Build("test","password")}", options =>
        {
            options.Events.OnCreatingTicket = context =>
            {
                // imagine a DB look up or similar
                context.ReplacePrincipal(new ClaimsPrincipal(new ClaimsIdentity(new GenericIdentity("UNIT TEST"))));
                return Task.CompletedTask;
            };
        });

        // Act
        var result = await handler.AuthenticateAsync();

        // Assert
        Assert.That(result.None, Is.False);
        Assert.That(result.Succeeded, Is.True);
        Assert.That(result.Failure, Is.Null);
    }

    [Test]
    public async Task BadData_NoSpace()
    {
        // Arrange
        var handler = await CreateHandler($"Basic{BasicCreds.Build("test","password")}");

        // Act
        var result = await handler.AuthenticateAsync();

        // Assert
        Assert.That(result.None, Is.False);
        Assert.That(result.Succeeded, Is.False);
        Assert.That(result.Failure, Is.Not.Null);

        Assert.That(result.Ticket, Is.Null);
        Assert.That(result.Principal, Is.Null);
    }

    [Test]
    public async Task NoAuth_NoWWWAuthenticate()
    {
        // Arrange
        var handler = await CreateHandler(null);

        // Act
        var result = await handler.AuthenticateAsync();

        // Assert
        Assert.That(result.None, Is.False);
        Assert.That(result.Succeeded, Is.False);
        Assert.That(result.Failure, Is.Not.Null);

        Assert.That(result.Ticket, Is.Null);
        Assert.That(result.Principal, Is.Null);
    }

    [Test]
    public async Task BadData_BadBase64()
    {
        // Arrange
        var handler = await CreateHandler("Basic BadBase64");

        // Act
        var result = await handler.AuthenticateAsync();

        // Assert
        Assert.That(result.None, Is.False);
        Assert.That(result.Succeeded, Is.False);
        Assert.That(result.Failure, Is.Not.Null);

        Assert.That(result.Ticket, Is.Null);
        Assert.That(result.Principal, Is.Null);
    }

    [Test]
    public async Task MissingHeader()
    {
        // Arrange
        var handler = await CreateHandler(null);

        // Act
        var result = await handler.AuthenticateAsync();

        // Assert
        Assert.That(result.None, Is.False);
        Assert.That(result.Succeeded, Is.False);
        Assert.That(result.Failure, Is.Not.Null);

        Assert.That(result.Ticket, Is.Null);
        Assert.That(result.Principal, Is.Null);
    }

    async Task<BasicAuthenticationHandler> CreateHandler(string? headerValue, Action<BasicAuthenticationOptions>? configure = null, string? schemeOverride = null)
    {
        Action<BasicAuthenticationOptions> c = options => { };
        if (configure != null)
        {
            c = configure;
        }

        var o = new BasicAuthenticationOptions();
        c(o);
        var om = new StubOptionsMonitor(o);

        var loggerFactory = NullLoggerFactory.Instance;
        var encoder = UrlEncoder.Default;
        var handler = new BasicAuthenticationHandler(om, loggerFactory, encoder);

        var scheme = new AuthenticationScheme(
            schemeOverride ?? BasicAuthenticationDefaults.AuthenticationScheme,
            BasicAuthenticationDefaults.AuthenticationScheme,
            typeof(BasicAuthenticationHandler)
            );

        var context = new DefaultHttpContext();

        if (headerValue != null)
        {
            context.Request.Headers.Append(HeaderNames.Authorization, headerValue);
        }

        await handler.InitializeAsync(scheme, context);

        return handler;
    }
}

public class StubOptionsMonitor : IOptionsMonitor<BasicAuthenticationOptions>
{
    BasicAuthenticationOptions _currentValue;

    public StubOptionsMonitor(BasicAuthenticationOptions currentValue)
    {
        _currentValue = currentValue;
    }

    public BasicAuthenticationOptions Get(string? name)
    {
        return _currentValue;
    }

    public IDisposable? OnChange(Action<BasicAuthenticationOptions, string?> listener)
    {
        throw new NotImplementedException();
    }

    public BasicAuthenticationOptions CurrentValue => _currentValue;
}
