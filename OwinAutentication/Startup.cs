using System;
using System.Threading.Tasks;
using Microsoft.Owin;
using Owin;
using System.Web.Http;
using Microsoft.Owin.Cors;
using System.Web.Cors;
using Microsoft.Owin.Security.OAuth;
using System.Collections;
using System.Collections.Generic;
using OwinAutentication.Models;
using System.Linq;
using System.Security.Claims;

namespace OwinAutentication
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            var config = new HttpConfiguration();
            config.MapHttpAttributeRoutes();
            config.Routes.MapHttpRoute(
                name: "DefaultApi",
                routeTemplate: "api/{controller}/{id}",
                defaults: new { id = RouteParameter.Optional }
            );
            //Ativando Cors
            ConfigureCors(app);

            AtivandoAccessTokens(app);

            //Ativando Configuração WebApi
            app.UseWebApi(config);

            
        }

        private void AtivandoAccessTokens(IAppBuilder app)
        {
            var opcoesConfiguracaoToken = new OAuthAuthorizationServerOptions()
            {
                AllowInsecureHttp = true,
                TokenEndpointPath = new PathString("/token"),
                AccessTokenExpireTimeSpan = TimeSpan.FromHours(2),
                Provider = new ProviderDeTokensDeAcesso()
            };
            app.UseOAuthAuthorizationServer(opcoesConfiguracaoToken);
            app.UseOAuthBearerAuthentication(new OAuthBearerAuthenticationOptions());
        }

        public class ProviderDeTokensDeAcesso : OAuthAuthorizationServerProvider
        {
            public override async Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
            {
                context.Validated();
            }

            public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
            {
                var usuario = BaseUsuarios
                    .Usuarios()
                    .FirstOrDefault(x => x.Nome == context.UserName && x.Senha == context.Password);
                if(usuario == null)
                {
                    context.SetError("invalid_grant ", "Usuário não encontrado ou senha incorreta");
                    return;
                }

                var identidadeUsuario = new ClaimsIdentity(context.Options.AuthenticationType);
                context.Validated(identidadeUsuario);
            }
        }

        public static class BaseUsuarios
        {
            public static IEnumerable<Usuario> Usuarios()
            {
                return new List<Usuario>
                {
                    new Usuario { Nome = "Fulano", Senha = "1234" },
                     new Usuario { Nome = "Beltrano", Senha = "5678" },
                     new Usuario { Nome = "Sicrano", Senha = "0912" }
                };
            }
        }

        private void ConfigureCors(IAppBuilder app)
        {
            var politica = new CorsPolicy();
            politica.AllowAnyHeader = true;
            politica.Origins.Add("http://localhost:40874");
            politica.Origins.Add("http://localhost:40874");
            politica.Methods.Add("GET");
            politica.Methods.Add("POST");

            var CorsOptions = new CorsOptions
            {
                PolicyProvider = new CorsPolicyProvider
                {
                    PolicyResolver = context => Task.FromResult(politica)
                }
            };
            app.UseCors(CorsOptions);
        }
    }
}
