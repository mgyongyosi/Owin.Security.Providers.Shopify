using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;
using System.Security.Claims;

namespace Owin.Security.Providers.Shopify.Provider
{
    public class ShopifyAuthenticatedContext : BaseContext
    {
        public ShopifyAuthenticatedContext(IOwinContext context, JObject user, string accessToken)
            : base(context)
        {
            AccessToken = accessToken;
            User = user;

            Id = user["shop"]["id"].ToString();
            Name = user["shop"]["myshopify_domain"].ToString();
            Email = user["shop"]["email"].ToString();
        }

        /// <summary>
        /// Gets the JSON-serialized user
        /// </summary>
        /// <remarks>
        /// Contains properties of the shop
        /// </remarks>
        public JObject User { get; private set; }

        /// <summary>
        /// Gets the Shopify OAuth access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the Shopify shop ID
        /// </summary>
        public string Id { get; private set; }

        /// <summary>
        /// The name of the user
        /// </summary>
        public string Name { get; private set; }

        /// <summary>
        /// The email fo the user
        /// </summary>
        public string Email { get; private set; }

        /// <summary>
        /// Gets the <see cref="ClaimsIdentity"/> representing the user
        /// </summary>
        public ClaimsIdentity Identity { get; set; }

        /// <summary>
        /// Gets or sets a property bag for common authentication properties
        /// </summary>
        public AuthenticationProperties Properties { get; set; }
    }
}
