using AuthenticationAuthorisation.Dtos;
using AuthenticationAuthorisation.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace AuthenticationAuthorisation.Controllers
{
    [Authorize]
    [ApiController]
    [Route("api/[controller]")]
    public class AccountController : ControllerBase
    {
        private readonly AccountService _accountService;

        public AccountController(AccountService accountService)
        {
            _accountService = accountService;
        }

        [AllowAnonymous]
        [HttpPost("register")]
        public async Task<ActionResult<string>> Register(RegisterDto registerDto)
        {
            try
            {
                await _accountService.RegisterUserAsync(registerDto);
                return Ok(new AuthResponseDto
                {
                    IsSuccess = true,
                    Message = "Account Created Successfully!"
                });
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }

        [AllowAnonymous]
        [HttpPost("login")]
        public async Task<ActionResult<AuthResponseDto>> Login(LoginDto loginDto)
        {
            try
            {
                var response = await _accountService.LoginUserAsync(loginDto);
                return Ok(response);
            }
            catch (Exception ex)
            {
                return Unauthorized(new AuthResponseDto
                {
                    IsSuccess = false,
                    Message = ex.Message
                });
            }
        }
 [AllowAnonymous]
        [HttpPost("forgot-password")]
        public async Task<ActionResult> ForgotPassword(ForgotPasswordDto forgotPasswordDto)
        {
            var isEmailSent = await _accountService.SendPasswordResetEmailAsync(forgotPasswordDto.Email);

            if (!isEmailSent)
            {
                return BadRequest(new AuthResponseDto
                {
                    IsSuccess = false,
                    Message = "Failed to send email"
                });
            }

            return Ok(new AuthResponseDto
            {
                IsSuccess = true,
                Message = "Email Sent with password reset link"
            });
        }

        [HttpGet("detail")]
        public async Task<ActionResult<UserDetailDto>> GetUserDetail()
        {
            var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            try
            {
#pragma warning disable CS8604 // Possible null reference argument.
                var userDetail = await _accountService.GetUserDetailAsync(currentUserId);
#pragma warning restore CS8604 // Possible null reference argument.
                return Ok(userDetail);
            }
            catch (Exception ex)
            {
                return NotFound(new AuthResponseDto
                {
                    IsSuccess = false,
                    Message = ex.Message
                });
            }
        }

        [HttpGet]
        public async Task<ActionResult<IEnumerable<UserDetailDto>>> GetUsers()
        {
            try
            {
                var users = await _accountService.GetUsersAsync();
                return Ok(users);
            }
            catch (Exception ex)
            {
                return BadRequest(ex.Message);
            }
        }
    }
}
