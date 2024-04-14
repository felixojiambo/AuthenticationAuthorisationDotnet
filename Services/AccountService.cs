using AuthenticationAuthorisation.Dtos;
using AuthenticationAuthorisation.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using RestSharp;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Runtime.CompilerServices;
using System.Security.Claims;
using System.Text;
using System.Web;

namespace AuthenticationAuthorisation.Services
{
    public class AccountService
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly IConfiguration _configuration;

        public AccountService(UserManager<AppUser> userManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _configuration = configuration;
        }

        public async Task<AppUser> RegisterUserAsync(RegisterDto registerDto)
        {
            var user = new AppUser
            {
                Email = registerDto.Email,
                FullName = registerDto.FullName,
                UserName = registerDto.Email
            };

            var result = await _userManager.CreateAsync(user, registerDto.Password);
            if (!result.Succeeded)
            {
                throw new Exception("User registration failed.");
            }

            if (registerDto.Roles != null)
            {
                foreach (var role in registerDto.Roles)
                {
                    await _userManager.AddToRoleAsync(user, role);
                }
            }
            else
            {
                await _userManager.AddToRoleAsync(user, "User");
            }

            return user;
        }

        public async Task<AuthResponseDto> LoginUserAsync(LoginDto loginDto)
        {
            var user = await _userManager.FindByEmailAsync(loginDto.Email);
            if (user == null)
            {
                throw new Exception("User not found.");
            }

            var isPasswordValid = await _userManager.CheckPasswordAsync(user, loginDto.Password);
            if (!isPasswordValid)
            {
                throw new Exception("Invalid password.");
            }

            var token = await GenerateTokenAsync(user);
            return new AuthResponseDto
            {
                Token = token,
                IsSuccess = true,
                Message = "Login Success."
            };
        }

//         [AllowAnonymous]
//         [HttpPost("/forgot-password")]
//         public async Task<ActionResult> ForgotPassword(ForgotPasswordDto forgotPasswordDto)
//         {
//             var user = await _userManager.FindByEmailAsync(forgotPasswordDto.Email);
//             if (user is null)
//             {
//                 return Ok(new AuthResponseDto
//                 {

//                     IsSuccess = false,
//                     Message = "User does not exit with this email"
//                 });
//             }
//             var token = await _userManager.GeneratePasswordResetTokenAsync(user);
//             var resetLink = $"http://localhost:4200/reset-password?email={user.Email}&token={WebUtility.UrlEncode(token)}",


//         // using RestSharp;

//         // var client = new RestClient("https://send.api.mailtrap.io/api/send");
//         // var request = new RestRequest();
//         // request.AddHeader("Authorization", "Bearer c2ab31073bef448fa08fbec6a9c0cbb1");
//         // request.AddHeader("Content-Type", "application/json");
//         // request.AddParameter("application/json", "{\"from\":{\"email\":\"mailtrap@demomailtrap.com\",\"name\":\"Mailtrap Test\"},\"to\":[{\"email\":\"felixojiamboe@gmail.com\"}],\"template_uuid\":\"3539aea4-8d29-4211-b955-bac1936e41f0\",\"template_variables\":{\"user_email\":\"felixojiamboe@gmail.com\",\"pass_reset_link\":\"linkforreset\"}}", ParameterType.RequestBody);
//         // var response = client.Post(request);
//         // System.Console.WriteLine(response.Content);
//            var client = new RestClient("https://send.api.mailtrap.io/api/send");
//            var request = new RestRequest{
//             Method = Method.Post,
//             RequestFormat.DataFormat.Json
//         };
//             request.AddHeader("Authorization", "Bearer wekfjhvgchxjklskdjfh");
//             request.AddJsonBody(new
//             {
//                 from = new { email = "mailtrap@demomatrap.com" },
//                 to = new[] { new { email = user.Email } },
//                 template_uuid = "3539aea4-8d29-4211-b955-bac1936e41f0",
//                 template_variables = new { user_email = user.Email, pass_reset_link = resetLink }
//             });
// var response=client.Execute(request);
// if(response.IsSuccessful){
//     return Ok (new AuthResponseDto{
//         IsSuccess=true,
//         Message="Email Sent with password reset link"
//     });
// }else{
//     return BadRequest(new  AuthResponseDto{
// IsSuccess=false,
// Message="Failed to send email"
//     })
// }
//         }

       public async Task<bool> SendPasswordResetEmailAsync(string email)
    {
        var user = await _userManager.FindByEmailAsync(email);
        if (user == null)
        {
            return false;
        }

        var token = await _userManager.GeneratePasswordResetTokenAsync(user);
        var resetLink = $"http://localhost:4200/reset-password?email={HttpUtility.UrlEncode(user.Email)}&token={HttpUtility.UrlEncode(token)}";

        var client = new RestClient("https://send.api.mailtrap.io/api/send");
        var request = new RestRequest
        {
            Method = Method.Post,
            RequestFormat = DataFormat.Json
        };
        request.AddHeader("Authorization", "Bearer " + _configuration["Mailtrap:ApiKey"]);
        request.AddJsonBody(new
        {
            from = new { email = "mailtrap@demomailtrap.com" },
            to = new[] { new { email = user.Email } },
            template_uuid = "3539aea4-8d29-4211-b955-bac1936e41f0",
            template_variables = new { user_email = user.Email, pass_reset_link = resetLink }
        });

        var response = client.Execute(request);
        return response.IsSuccessful;
    }

        public async Task<UserDetailDto> GetUserDetailAsync(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                throw new Exception("User not found.");
            }

            var roles = await _userManager.GetRolesAsync(user);
            return new UserDetailDto
            {
                Id = user.Id,
                Email = user.Email,
                FullName = user.FullName,
                Roles = roles.ToArray(),
                PhoneNumber = user.PhoneNumber,
                PhoneNumberConfirmed = user.PhoneNumberConfirmed,
                AccessFailedCount = user.AccessFailedCount
            };
        }

        public async Task<IEnumerable<UserDetailDto>> GetUsersAsync()
        {
            var users = await _userManager.Users.ToListAsync();
            var userDetails = new List<UserDetailDto>();

            foreach (var user in users)
            {
                var roles = await _userManager.GetRolesAsync(user);
                userDetails.Add(new UserDetailDto
                {
                    Id = user.Id,
                    Email = user.Email,
                    FullName = user.FullName,
                    Roles = roles.ToArray(),
                    PhoneNumber = user.PhoneNumber,
                    PhoneNumberConfirmed = user.PhoneNumberConfirmed,
                    AccessFailedCount = user.AccessFailedCount
                });
            }

            return userDetails;
        }

        private async Task<string> GenerateTokenAsync(AppUser user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
#pragma warning disable CS8604 // Possible null reference argument.
            var key = Encoding.ASCII.GetBytes(_configuration.GetSection("JWTSetting").GetSection("securityKey").Value);
#pragma warning restore CS8604 // Possible null reference argument.
            var roles = await _userManager.GetRolesAsync(user);

#pragma warning disable CS8604 // Possible null reference argument.
            var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Email, user.Email ?? ""),
                new Claim(JwtRegisteredClaimNames.Name, user.FullName ?? ""),
                new Claim(JwtRegisteredClaimNames.NameId, user.Id ?? ""),
                new Claim(JwtRegisteredClaimNames.Aud, _configuration.GetSection("JWTSetting").GetSection("validAudience").Value),
                new Claim(JwtRegisteredClaimNames.Iss, _configuration.GetSection("JWTSetting").GetSection("validIssuer").Value)
            };
#pragma warning restore CS8604 // Possible null reference argument.

            foreach (var role in roles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = DateTime.UtcNow.AddDays(1),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
    }
}
