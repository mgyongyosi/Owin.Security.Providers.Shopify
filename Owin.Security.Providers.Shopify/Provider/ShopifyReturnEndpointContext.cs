using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;

namespace Owin.Security.Providers.Shopify.Provider
{
    /// <summary>
    /// Provides context information to middleware providers.
    /// </summary>
    public class ShopifyReturnEndpointContext : ReturnEndpointContext
    {
        public ShopifyReturnEndpointContext(
                IOwinContext context,
                AuthenticationTicket ticket)
            : base(context, ticket)
        {
        }

    }
}
