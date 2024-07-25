namespace ACuriousMind.BasicAuth;

/// <summary>
/// The Events of the Basic Authentication Handler
/// </summary>
public class BasicAuthenticationEvents
{
    /// <summary>
    /// Gets or sets the function that is invoked when the CreatingTicket method is invoked.
    /// </summary>
    public Func<BasicAuthenticationCreatingTicketContext, Task> OnCreatingTicket { get; set; } = context => Task.CompletedTask;

    /// <summary>
    /// Gets or sets the function that is invoked when the CreatedTicket method is invoked.
    /// </summary>
    public Func<BasicAuthenticationCreatedTicketContext, Task> OnCreatedTicket { get; set; } = context => Task.CompletedTask;

    /// <summary>
    /// Gets or sets the function that is invoked when the FailedTicket method is invoked.
    /// </summary>
    public Func<BasicAuthenticationFailedTicketContext, Task> OnFailedTicket { get; set; } = context => Task.CompletedTask;

    /// <summary>
    /// Invoked after the provider successfully authenticates a user.
    /// </summary>
    /// <param name="context" >Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity" />.</param>
    /// <returns>A <see cref="Task" /> representing the completed operation.</returns>
    public virtual Task CreatingTicket(BasicAuthenticationCreatingTicketContext context)
    {
        return OnCreatingTicket(context);
    }

    public virtual Task CreatedTicket(BasicAuthenticationCreatedTicketContext context)
    {
        return OnCreatedTicket(context);
    }

    public virtual Task FailedTicket(BasicAuthenticationFailedTicketContext context)
    {
        return OnFailedTicket(context);
    }
}
