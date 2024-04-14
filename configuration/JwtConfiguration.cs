using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace AuthenticationAuthorisation.Configuration
{
    public class JwtConfiguration
    {
        public string? ValidAudience { get; set; }
        public string? ValidIssuer { get; set; }
        public string? SecurityKey { get; set; }

        public JwtConfiguration(IConfiguration configuration)
        {
            ValidAudience = configuration.GetSection("JWTSetting:ValidAudience").Value;
            ValidIssuer = configuration.GetSection("JWTSetting:ValidIssuer").Value;
            SecurityKey = configuration.GetSection("JWTSetting:securityKey").Value;
        }
        public SymmetricSecurityKey GetSymmetricSecurityKey()
        {
            if (SecurityKey == null)
            {
                throw new InvalidOperationException("SecurityKey is not configured.");
            }
            return new SymmetricSecurityKey(Encoding.UTF8.GetBytes(SecurityKey));
        }

        public TokenValidationParameters GetTokenValidationParameters()
        {
            if (ValidAudience == null || ValidIssuer == null || SecurityKey == null)
            {
                throw new InvalidOperationException("JWT configuration is incomplete.");
            }
            return new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidAudience = ValidAudience,
                ValidIssuer = ValidIssuer,
                IssuerSigningKey = GetSymmetricSecurityKey()
            };
        }

        public void ConfigureJwtBearerOptions(JwtBearerOptions options)
        {
            options.SaveToken = true;
            options.RequireHttpsMetadata = false;
            options.TokenValidationParameters = GetTokenValidationParameters();
        }
    }
}
