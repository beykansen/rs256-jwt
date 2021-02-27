using System;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Tokens;

namespace WebApplication
{
    public class Startup
    {
        public Startup(IConfiguration configuration) => Configuration = configuration;
        public IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllers();
            services.AddAuthentication(x =>
                {
                    x.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
                    x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                    x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                })
                .AddJwtBearer( options =>
                {
                    options.IncludeErrorDetails = true;
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        IssuerSigningKey = RsaSecurityKeyHelper.GetKey("public.cer"),
                        ValidIssuer = "beykan",
                        RequireExpirationTime = true,
                        RequireAudience = true,
                        ValidateIssuer = true,
                        ValidateLifetime = true,
                        ValidateAudience = false,
                        ValidateIssuerSigningKey = true
                    };
                });
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
                app.UseDeveloperExceptionPage();
            app.UseHttpsRedirection();
            app.UseRouting();
            app.UseAuthentication();
            app.UseAuthorization();
            app.UseEndpoints(endpoints => { endpoints.MapControllers(); });
        }
    }

    public static class RsaSecurityKeyHelper
    {
        public static RsaSecurityKey GetKey(string x509CertificateFileName)
        {
            var rsaPublicKeyFileText = ReadAndCleanPemFile(x509CertificateFileName);
            return new RsaSecurityKey(new X509Certificate2(Convert.FromBase64String(rsaPublicKeyFileText)).GetRSAPublicKey());
        }
        private static string ReadAndCleanPemFile(string fileName)
        {
            var privateKeyFileText = File.ReadAllText(fileName);
            privateKeyFileText = privateKeyFileText.Replace("-----BEGIN CERTIFICATE-----", "");
            privateKeyFileText = privateKeyFileText.Replace("-----END CERTIFICATE-----", "");
            return privateKeyFileText.RemoveLineEndings();
        }
        private static string RemoveLineEndings(this string value)
        {
            if(string.IsNullOrEmpty(value))
            {
                return value;
            }
            return value.Replace("\r\n", string.Empty)
                .Replace("\n", string.Empty)
                .Replace("\r", string.Empty);
        }
    }
}