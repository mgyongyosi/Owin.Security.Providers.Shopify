using Microsoft.Owin;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Owin.Security.Providers.Shopify.Provider;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace Owin.Security.Providers.Shopify
{
    public class ShopifyAuthenticationHandler : AuthenticationHandler<ShopifyAuthenticationOptions>
    {
        private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";
        private string TokenEndpoint = "https://{shop}/admin/oauth/access_token";
        private string UserInfoEndpoint = "https://{shop}/admin/shop.json";

        private readonly ILogger logger;
        private readonly HttpClient httpClient;

        public ShopifyAuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            this.httpClient = httpClient;
            this.logger = logger;
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            // Workaround: Shopify does not implement oath2 fully (no state parameter returned with the redirect_uri)
            AuthenticationProperties properties = new AuthenticationProperties() { RedirectUri = "/Account/ExternalLoginCallback" };

            try
            {
                string code = null;
                string hmac = null;
                string timestamp = null;
                string shop = null;

                IReadableStringCollection query = Request.Query;
                IList<string> values = query.GetValues("code");
                if (values != null && values.Count == 1)
                {
                    code = values[0];
                }

                values = query.GetValues("hmac");
                if (values != null && values.Count == 1)
                {
                    hmac = values[0];
                }

                values = query.GetValues("timestamp");
                if (values != null && values.Count == 1)
                {
                    timestamp = values[0];
                }

                values = query.GetValues("shop");
                if (values != null && values.Count == 1)
                {
                    shop = values[0];
                }

                // Replace the shopify url in the format string
                TokenEndpoint = TokenEndpoint.Replace("{shop}", shop);
                UserInfoEndpoint = UserInfoEndpoint.Replace("{shop}", shop);

                var signBase = string.Format("code={0}&shop={1}&timestamp={2}", code, shop, timestamp);

                // Verify the response with the method specified at https://docs.shopify.com/api/authentication/oauth#verification
                if (!ValidateShopifySignature(signBase, hmac, Options.ClientSecret))
                {
                    return new AuthenticationTicket(null, properties);
                }

                // Check for error
                if (Request.Query.Get("error") != null)
                    return new AuthenticationTicket(null, properties);

                string requestPrefix = Request.Scheme + "://" + Request.Host;
                string redirectUri = requestPrefix + Request.PathBase + Options.CallbackPath;

                // Build up the body for the token request
                var body = new List<KeyValuePair<string, string>>();
                body.Add(new KeyValuePair<string, string>("code", code));
                body.Add(new KeyValuePair<string, string>("client_id", Options.ClientId));
                body.Add(new KeyValuePair<string, string>("client_secret", Options.ClientSecret));

                // Request the token
                HttpResponseMessage tokenResponse =
                    await httpClient.PostAsync(TokenEndpoint, new FormUrlEncodedContent(body));
                tokenResponse.EnsureSuccessStatusCode();
                string text = await tokenResponse.Content.ReadAsStringAsync();

                // Deserializes the response
                dynamic response = JsonConvert.DeserializeObject<dynamic>(text);
                string accessToken = (string)response.access_token;

                // Get the Shopify shop
                HttpResponseMessage shopInfoResponse = await httpClient.GetAsync(
                    UserInfoEndpoint + "?access_token=" + Uri.EscapeDataString(accessToken), Request.CallCancelled);
                shopInfoResponse.EnsureSuccessStatusCode();
                text = await shopInfoResponse.Content.ReadAsStringAsync();
                JObject user = JObject.Parse(text);

                var context = new ShopifyAuthenticatedContext(Context, user, accessToken);
                context.Identity = new ClaimsIdentity(
                    Options.AuthenticationType,
                    ClaimsIdentity.DefaultNameClaimType,
                    ClaimsIdentity.DefaultRoleClaimType);

                if (!string.IsNullOrEmpty(context.Id))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, context.Id, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.Name))
                {
                    context.Identity.AddClaim(new Claim(ClaimsIdentity.DefaultNameClaimType, context.Name, XmlSchemaString, Options.AuthenticationType));
                }
                context.Properties = properties;

                await Options.Provider.Authenticated(context);

                return new AuthenticationTicket(context.Identity, context.Properties);
            }
            catch (Exception ex)
            {
                logger.WriteError(ex.Message);
            }
            return new AuthenticationTicket(null, properties);
        }

        /// <summary>
        /// Verify if the request is valid.
        /// </summary>
        /// <param name="signatureBase">Generated signature from the query string parameters.</param>
        /// <param name="hmacFromServer">hmac query string parameter.</param>
        /// <param name="clientSecret">Shopify app client secret.</param>
        /// <returns></returns>
        private bool ValidateShopifySignature(string signatureBase, string hmacFromServer, string clientSecret)
        {
            var hash = new HMACSHA256(Encoding.UTF8.GetBytes(clientSecret));
            var generatedSignatureHmac = BitConverter.ToString(hash.ComputeHash(Encoding.UTF8.GetBytes(signatureBase))).Replace("-", string.Empty);

            return string.Equals(generatedSignatureHmac, hmacFromServer, StringComparison.InvariantCultureIgnoreCase);
        }

        protected override Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode != 401)
            {
                return Task.FromResult<object>(null);
            }

            AuthenticationResponseChallenge challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

            if (challenge != null)
            {
                string baseUri =
                    Request.Scheme +
                    Uri.SchemeDelimiter +
                    Request.Host +
                    Request.PathBase;

                string currentUri =
                    baseUri +
                    Request.Path +
                    Request.QueryString;

                string redirectUri =
                    baseUri +
                    Options.CallbackPath;

                AuthenticationProperties properties = challenge.Properties;
                if (string.IsNullOrEmpty(properties.RedirectUri))
                {
                    properties.RedirectUri = currentUri;
                }

                // Comma separated
                string scope = string.Join(",", Options.Scope);

                // Allow scopes to be specified via the authentication properties for this request, when specified they will already be comma separated
                if (properties.Dictionary.ContainsKey("scope"))
                {
                    scope = properties.Dictionary["scope"];
                }

                // Get the shop base url
                var currentShop = properties.Dictionary["shop"];

                string authorizationEndpoint =
                    "https://"+ currentShop +"/admin/oauth/authorize" +
                        "?client_id=" + Uri.EscapeDataString(Options.ClientId) +
                        "&redirect_uri=" + Uri.EscapeDataString(redirectUri) +
                        "&scope=" + Uri.EscapeDataString(scope);

                Response.Redirect(authorizationEndpoint);
            }

            return Task.FromResult<object>(null);
        }

        public override async Task<bool> InvokeAsync()
        {
            return await InvokeReplyPathAsync();
        }

        private async Task<bool> InvokeReplyPathAsync()
        {
            if (Options.CallbackPath.HasValue && Options.CallbackPath == Request.Path)
            {
                AuthenticationTicket ticket = await AuthenticateAsync();
                if (ticket == null)
                {
                    logger.WriteWarning("Invalid return state, unable to redirect.");
                    Response.StatusCode = 500;
                    return true;
                }

                var context = new ShopifyReturnEndpointContext(Context, ticket);
                context.SignInAsAuthenticationType = Options.SignInAsAuthenticationType;
                context.RedirectUri = ticket.Properties.RedirectUri;

                await Options.Provider.ReturnEndpoint(context);

                if (context.SignInAsAuthenticationType != null &&
                    context.Identity != null)
                {
                    ClaimsIdentity grantIdentity = context.Identity;
                    if (!string.Equals(grantIdentity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal))
                    {
                        grantIdentity = new ClaimsIdentity(grantIdentity.Claims, context.SignInAsAuthenticationType, grantIdentity.NameClaimType, grantIdentity.RoleClaimType);
                    }
                    Context.Authentication.SignIn(context.Properties, grantIdentity);
                }

                if (!context.IsRequestCompleted && context.RedirectUri != null)
                {
                    string redirectUri = context.RedirectUri;
                    if (context.Identity == null)
                    {
                        // sign in failed
                        redirectUri = WebUtilities.AddQueryString(redirectUri, "error", "access_denied");
                    }
                    Response.Redirect(redirectUri);
                    context.RequestCompleted();
                }

                return context.IsRequestCompleted;
            }
            return false;
        }
    }
}