using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Web;

namespace Owin.Security.Providers.Shopify.Provider
{
    public class ShopifyAuthenticationProvider : IShopifyAuthenticationProvider
    {
        /// <summary>
        /// Initializes a <see cref="ShopifyAuthenticationProvider"/>
        /// </summary>
        public ShopifyAuthenticationProvider()
        {
            OnAuthenticated = context => Task.FromResult<object>(null);
            OnReturnEndpoint = context => Task.FromResult<object>(null);
        }

        /// <summary>
        /// Gets or sets the function that is invoked when the Authenticated method is invoked.
        /// </summary>
        public Func<ShopifyAuthenticatedContext, Task> OnAuthenticated { get; set; }

        /// <summary>
        /// Gets or sets the function that is invoked when the ReturnEndpoint method is invoked.
        /// </summary>
        public Func<ShopifyReturnEndpointContext, Task> OnReturnEndpoint { get; set; }

        public Task Authenticated(ShopifyAuthenticatedContext context)
        {
            return OnAuthenticated(context);
        }

        public Task ReturnEndpoint(ShopifyReturnEndpointContext context)
        {
            return OnReturnEndpoint(context);
        }
    }
}