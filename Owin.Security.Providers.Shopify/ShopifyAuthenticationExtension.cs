using System;
using System.Collections.Generic;

namespace Owin.Security.Providers.Shopify
{
    /// <summary>
    /// Extension methods for using <see cref="ShopifyAuthenticationMiddleware"/>
    /// </summary>
    public static class ShopifyAuthenticationExtension
    {
        public static IAppBuilder UseShopifyAuthentication(this IAppBuilder app,
            ShopifyAuthenticationOptions options)
        {
            if (app == null)
                throw new ArgumentNullException("app");
            if (options == null)
                throw new ArgumentNullException("options");

            app.Use(typeof(ShopifyAuthenticationMiddleware), app, options);

            return app;
        }

        public static IAppBuilder UseShopifyAuthentication(this IAppBuilder app, string clientId, string clientSecret)
        {
            return app.UseShopifyAuthentication(new ShopifyAuthenticationOptions
            {
                ClientId = clientId,
                ClientSecret = clientSecret,
                Scope = new List<string>() { "read_content", "write_content" }
            });
        }

    }
}