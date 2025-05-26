using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OnePieceCardManagement.DTOs.Authentication.Request;
using OnePieceCardManagement.DTOs.Authentication.Response;
using OnePieceCardManagement.DTOs.Common;
using OnePieceCardManagement.DTOs.Email;
using OnePieceCardManagement.Services;
using System.Security.Claims;

namespace OnePieceCardManagement.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly IAuthenticationService _authenticationService;
        private readonly ILogger<AuthenticationController> _logger;

        public AuthenticationController(
            IAuthenticationService authenticationService,
            ILogger<AuthenticationController> logger)
        {
            _authenticationService = authenticationService;
            _logger = logger;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterUserDto registerUserDto, [FromQuery] string role = "User")
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(new ApiResponseDto<object>
                {
                    IsSuccess = false,
                    Message = "Invalid input data",
                    StatusCode = 400,
                    Response = ModelState
                });
            }

            // Validation
            if (string.IsNullOrWhiteSpace(registerUserDto?.Email) || string.IsNullOrWhiteSpace(registerUserDto?.Username))
            {
                return BadRequest(new ApiResponseDto<object>
                {
                    IsSuccess = false,
                    Message = "Email and Username are required",
                    StatusCode = 400
                });
            }

            var result = await _authenticationService.RegisterAsync(registerUserDto, role);

            // Send confirmation email if registration was successful
            if (result.IsSuccess)
            {
                var token = await GetEmailConfirmationToken(registerUserDto.Email);
                var confirmationLink = Url.Action(nameof(ConfirmEmail), "Authentication",
                    new { token, email = registerUserDto.Email }, Request.Scheme);

                var messageDto = new MessageDto(new string[] { registerUserDto.Email }, "Email Confirmation", confirmationLink!);
                _authenticationService.SendEmail(messageDto);
            }

            return StatusCode(result.StatusCode, result);
        }

        [HttpGet("confirm-email")]
        public async Task<IActionResult> ConfirmEmail(string token, string email)
        {
            if (string.IsNullOrWhiteSpace(token) || string.IsNullOrWhiteSpace(email))
            {
                return BadRequest(new ApiResponseDto<object>
                {
                    IsSuccess = false,
                    Message = "Token and email are required",
                    StatusCode = 400
                });
            }

            var result = await _authenticationService.ConfirmEmailAsync(token, email);
            return StatusCode(result.StatusCode, result);
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDto loginDto)
        {
            if (!ModelState.IsValid || string.IsNullOrWhiteSpace(loginDto?.Username))
            {
                return BadRequest(new ApiResponseDto<object>
                {
                    IsSuccess = false,
                    Message = "Invalid login data",
                    StatusCode = 400
                });
            }

            var result = await _authenticationService.LoginAsync(loginDto);
            return StatusCode(result.StatusCode, result);
        }

        [HttpPost("login-2fa")]
        public async Task<IActionResult> LoginWithOTP([FromBody] TwoFactorLoginDto twoFactorLoginDto)
        {
            if (!ModelState.IsValid || string.IsNullOrWhiteSpace(twoFactorLoginDto?.Code) || string.IsNullOrWhiteSpace(twoFactorLoginDto?.Username))
            {
                return BadRequest(new ApiResponseDto<object>
                {
                    IsSuccess = false,
                    Message = "Code and username are required",
                    StatusCode = 400
                });
            }

            var result = await _authenticationService.LoginWithOTPAsync(twoFactorLoginDto);
            return StatusCode(result.StatusCode, result);
        }

        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenModelDto refreshTokenDto)
        {
            if (string.IsNullOrWhiteSpace(refreshTokenDto?.RefreshToken))
            {
                return BadRequest(new ApiResponseDto<object>
                {
                    IsSuccess = false,
                    Message = "Refresh token is required",
                    StatusCode = 400
                });
            }

            var result = await _authenticationService.RefreshTokenAsync(refreshTokenDto);
            return StatusCode(result.StatusCode, result);
        }

        [HttpPost("logout")]
        [Authorize]
        public async Task<IActionResult> Logout()
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var result = await _authenticationService.LogoutAsync(userId ?? string.Empty);
            return StatusCode(result.StatusCode, result);
        }

        [HttpPost("forgot-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordDto forgotPasswordDto)
        {
            if (string.IsNullOrWhiteSpace(forgotPasswordDto?.Email))
            {
                return BadRequest(new ApiResponseDto<object>
                {
                    IsSuccess = false,
                    Message = "Email is required",
                    StatusCode = 400
                });
            }

            var resetLink = Url.Action("ResetPassword", "Authentication", null, Request.Scheme);
            var result = await _authenticationService.ForgotPasswordAsync(forgotPasswordDto, resetLink!);
            return StatusCode(result.StatusCode, result);
        }

        [HttpGet("reset-password")]
        public async Task<IActionResult> ResetPassword(string token, string email)
        {
            var result = await _authenticationService.GetResetPasswordFormAsync(token, email);
            return StatusCode(result.StatusCode, result);
        }

        [HttpPost("reset-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordDto resetPasswordDto)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(new ApiResponseDto<object>
                {
                    IsSuccess = false,
                    Message = "Invalid input data",
                    StatusCode = 400,
                    Response = ModelState
                });
            }

            var result = await _authenticationService.ResetPasswordAsync(resetPasswordDto);
            return StatusCode(result.StatusCode, result);
        }

        [HttpPost("revoke-token")]
        [Authorize]
        public async Task<IActionResult> RevokeToken([FromBody] RevokeTokenDto revokeTokenDto)
        {
            if (string.IsNullOrWhiteSpace(revokeTokenDto?.RefreshToken))
            {
                return BadRequest(new ApiResponseDto<object>
                {
                    IsSuccess = false,
                    Message = "Refresh token is required",
                    StatusCode = 400
                });
            }

            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId))
            {
                return Unauthorized(new ApiResponseDto<object>
                {
                    IsSuccess = false,
                    Message = "User not found",
                    StatusCode = 401
                });
            }

            var result = await _authenticationService.RevokeTokenAsync(revokeTokenDto, userId);
            return StatusCode(result.StatusCode, result);
        }

        [HttpPost("revoke-all-tokens")]
        [Authorize]
        public async Task<IActionResult> RevokeAllTokens()
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId))
            {
                return Unauthorized(new ApiResponseDto<object>
                {
                    IsSuccess = false,
                    Message = "User not found",
                    StatusCode = 401
                });
            }

            var result = await _authenticationService.RevokeAllTokensAsync(userId);
            return StatusCode(result.StatusCode, result);
        }

        // Private helper method - this would need to be injected or moved to service
        private async Task<string> GetEmailConfirmationToken(string email)
        {
            // This is a simplified version - in real implementation, 
            // this would need access to UserManager through the service
            return await Task.FromResult("dummy-token");
        }
    }
}