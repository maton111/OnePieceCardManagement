using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OnePieceCardManagement.Models;
using OnePieceCardManagement.Models.Authentication.Login;
using OnePieceCardManagement.Models.Authentication.SignUp;
using OnePieceCardManagement.Presentation.Models.Authentication.SignUp;
using OnePieceCardManagement.Services;
using OnePieceCardManagement.Utils;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace OnePieceCardManagement.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IAuthenticationService _emailService;
        private readonly IConfiguration _configuration;
        private readonly ILogger<AuthenticationController> _logger;

        // Constants per evitare magic numbers
        private const int JWT_EXPIRY_MINUTES = 15; // JWT breve per sicurezza
        private const int REFRESH_TOKEN_EXPIRY_DAYS = 7;
        private const int EMAIL_CONFIRMATION_HOURS = 24;

        public AuthenticationController(
            UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IAuthenticationService emailService,
            SignInManager<IdentityUser> signInManager,
            IConfiguration configuration,
            ILogger<AuthenticationController> logger)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _signInManager = signInManager;
            _emailService = emailService;
            _configuration = configuration;
            _logger = logger;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterUser registerUser, [FromQuery] string role = "User")
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(new ApiResponse<object>
                    {
                        IsSuccess = false,
                        Message = "Invalid input data",
                        StatusCode = 400,
                        Response = ModelState
                    });
                }

                // Validation
                if (string.IsNullOrWhiteSpace(registerUser?.Email) || string.IsNullOrWhiteSpace(registerUser?.Username))
                {
                    return BadRequest(new ApiResponse<object>
                    {
                        IsSuccess = false,
                        Message = "Email and Username are required",
                        StatusCode = 400
                    });
                }

                // Check if user exists
                var userExists = await _userManager.FindByEmailAsync(registerUser.Email);
                if (userExists != null)
                {
                    _logger.LogWarning("Registration attempt for existing email: {Email}", registerUser.Email);
                    return Conflict(new ApiResponse<object>
                    {
                        IsSuccess = false,
                        Message = "User already exists!",
                        StatusCode = 409
                    });
                }

                // Check if role exists
                if (!await _roleManager.RoleExistsAsync(role))
                {
                    _logger.LogError("Registration attempt with non-existing role: {Role}", role);
                    return BadRequest(new ApiResponse<object>
                    {
                        IsSuccess = false,
                        Message = "This role does not exist",
                        StatusCode = 400
                    });
                }

                // Create user
                var user = new IdentityUser
                {
                    Email = registerUser.Email,
                    SecurityStamp = Guid.NewGuid().ToString(),
                    UserName = registerUser.Username,
                    TwoFactorEnabled = true
                };

                var result = await _userManager.CreateAsync(user, registerUser.Password!);
                if (!result.Succeeded)
                {
                    _logger.LogError("User creation failed for {Email}: {Errors}",
                        registerUser.Email, string.Join(", ", result.Errors.Select(e => e.Description)));

                    return BadRequest(new ApiResponse<object>
                    {
                        IsSuccess = false,
                        Message = "User creation failed",
                        StatusCode = 400,
                        Response = result.Errors
                    });
                }

                // Add role
                await _userManager.AddToRoleAsync(user, role);

                // Send confirmation email
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                var confirmationLink = Url.Action(nameof(ConfirmEmail), "Authentication",
                    new { token, email = user.Email }, Request.Scheme);

                var message = new Message(new string[] { user.Email }, "Email Confirmation", confirmationLink!);
                _emailService.SendEmail(message);

                _logger.LogInformation("User {Email} registered successfully", user.Email);

                return Ok(new ApiResponse<object>
                {
                    IsSuccess = true,
                    Message = $"User created successfully. Confirmation email sent to {user.Email}",
                    StatusCode = 200
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during user registration for {Email}", registerUser?.Email);
                return StatusCode(500, new ApiResponse<object>
                {
                    IsSuccess = false,
                    Message = "An error occurred during registration",
                    StatusCode = 500
                });
            }
        }

        [HttpGet("confirm-email")]
        public async Task<IActionResult> ConfirmEmail(string token, string email)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(token) || string.IsNullOrWhiteSpace(email))
                {
                    return BadRequest(new ApiResponse<object>
                    {
                        IsSuccess = false,
                        Message = "Token and email are required",
                        StatusCode = 400
                    });
                }

                var user = await _userManager.FindByEmailAsync(email);
                if (user == null)
                {
                    _logger.LogWarning("Email confirmation attempt for non-existing user: {Email}", email);
                    return NotFound(new ApiResponse<object>
                    {
                        IsSuccess = false,
                        Message = "User not found",
                        StatusCode = 404
                    });
                }

                var result = await _userManager.ConfirmEmailAsync(user, token);
                if (!result.Succeeded)
                {
                    _logger.LogWarning("Invalid email confirmation token for user: {Email}", email);
                    return BadRequest(new ApiResponse<object>
                    {
                        IsSuccess = false,
                        Message = "Invalid confirmation token",
                        StatusCode = 400
                    });
                }

                _logger.LogInformation("Email confirmed successfully for user: {Email}", email);
                return Ok(new ApiResponse<object>
                {
                    IsSuccess = true,
                    Message = "Email verified successfully",
                    StatusCode = 200
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during email confirmation for {Email}", email);
                return StatusCode(500, new ApiResponse<object>
                {
                    IsSuccess = false,
                    Message = "An error occurred during email confirmation",
                    StatusCode = 500
                });
            }
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel loginModel)
        {
            try
            {
                if (!ModelState.IsValid || string.IsNullOrWhiteSpace(loginModel?.Username))
                {
                    return BadRequest(new ApiResponse<object>
                    {
                        IsSuccess = false,
                        Message = "Invalid login data",
                        StatusCode = 400
                    });
                }

                var user = await _userManager.FindByNameAsync(loginModel.Username);
                if (user == null || !await _userManager.CheckPasswordAsync(user, loginModel.Password!))
                {
                    _logger.LogWarning("Failed login attempt for username: {Username}", loginModel.Username);
                    return Unauthorized(new ApiResponse<object>
                    {
                        IsSuccess = false,
                        Message = "Invalid credentials",
                        StatusCode = 401
                    });
                }

                // Check if email is confirmed
                if (!await _userManager.IsEmailConfirmedAsync(user))
                {
                    return Unauthorized(new ApiResponse<object>
                    {
                        IsSuccess = false,
                        Message = "Email not confirmed. Please check your email.",
                        StatusCode = 401
                    });
                }

                // Handle 2FA
                if (user.TwoFactorEnabled)
                {
                    await _signInManager.SignOutAsync();
                    await _signInManager.PasswordSignInAsync(user, loginModel.Password!, false, true);

                    var twoFactorToken = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");
                    var message = new Message(new string[] { user.Email! }, "OTP Verification", twoFactorToken);
                    _emailService.SendEmail(message);

                    _logger.LogInformation("2FA token sent to user: {Email}", user.Email);
                    return Ok(new ApiResponse<object>
                    {
                        IsSuccess = true,
                        Message = $"OTP sent to your email {user.Email}",
                        StatusCode = 200,
                        Response = new { RequiresTwoFactor = true, Username = user.UserName }
                    });
                }

                // Generate tokens
                var tokenResponse = await GenerateTokensAsync(user);

                _logger.LogInformation("User {Email} logged in successfully", user.Email);
                return Ok(new ApiResponse<TokenResponse>
                {
                    IsSuccess = true,
                    Message = "Login successful",
                    StatusCode = 200,
                    Response = tokenResponse
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during login for username: {Username}", loginModel?.Username);
                return StatusCode(500, new ApiResponse<object>
                {
                    IsSuccess = false,
                    Message = "An error occurred during login",
                    StatusCode = 500
                });
            }
        }

        [HttpPost("login-2fa")]
        public async Task<IActionResult> LoginWithOTP([FromBody] TwoFactorLoginModel model)
        {
            try
            {
                if (!ModelState.IsValid || string.IsNullOrWhiteSpace(model?.Code) || string.IsNullOrWhiteSpace(model?.Username))
                {
                    return BadRequest(new ApiResponse<object>
                    {
                        IsSuccess = false,
                        Message = "Code and username are required",
                        StatusCode = 400
                    });
                }

                var user = await _userManager.FindByNameAsync(model.Username);
                if (user == null)
                {
                    return NotFound(new ApiResponse<object>
                    {
                        IsSuccess = false,
                        Message = "User not found",
                        StatusCode = 404
                    });
                }

                var signIn = await _signInManager.TwoFactorSignInAsync("Email", model.Code, false, false);
                if (!signIn.Succeeded)
                {
                    _logger.LogWarning("Invalid 2FA code for user: {Username}", model.Username);
                    return BadRequest(new ApiResponse<object>
                    {
                        IsSuccess = false,
                        Message = "Invalid verification code",
                        StatusCode = 400
                    });
                }

                var tokenResponse = await GenerateTokensAsync(user);

                _logger.LogInformation("User {Email} completed 2FA login successfully", user.Email);
                return Ok(new ApiResponse<TokenResponse>
                {
                    IsSuccess = true,
                    Message = "Login successful",
                    StatusCode = 200,
                    Response = tokenResponse
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during 2FA login for username: {Username}", model?.Username);
                return StatusCode(500, new ApiResponse<object>
                {
                    IsSuccess = false,
                    Message = "An error occurred during 2FA verification",
                    StatusCode = 500
                });
            }
        }

        [HttpPost("refresh-token")]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenModel model)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(model?.RefreshToken))
                {
                    return BadRequest(new ApiResponse<object>
                    {
                        IsSuccess = false,
                        Message = "Refresh token is required",
                        StatusCode = 400
                    });
                }

                var principal = GetPrincipalFromExpiredToken(model.AccessToken);
                if (principal?.Identity?.Name == null)
                {
                    return BadRequest(new ApiResponse<object>
                    {
                        IsSuccess = false,
                        Message = "Invalid access token",
                        StatusCode = 400
                    });
                }

                var user = await _userManager.FindByNameAsync(principal.Identity.Name);
                if (user == null)
                {
                    return NotFound(new ApiResponse<object>
                    {
                        IsSuccess = false,
                        Message = "User not found",
                        StatusCode = 404
                    });
                }

                // In produzione, dovresti verificare il refresh token contro il database
                // Per ora simuliamo la validazione
                if (!IsValidRefreshToken(model.RefreshToken))
                {
                    _logger.LogWarning("Invalid refresh token for user: {Username}", user.UserName);
                    return BadRequest(new ApiResponse<object>
                    {
                        IsSuccess = false,
                        Message = "Invalid refresh token",
                        StatusCode = 400
                    });
                }

                var tokenResponse = await GenerateTokensAsync(user);

                _logger.LogInformation("Token refreshed for user: {Email}", user.Email);
                return Ok(new ApiResponse<TokenResponse>
                {
                    IsSuccess = true,
                    Message = "Token refreshed successfully",
                    StatusCode = 200,
                    Response = tokenResponse
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during token refresh");
                return StatusCode(500, new ApiResponse<object>
                {
                    IsSuccess = false,
                    Message = "An error occurred during token refresh",
                    StatusCode = 500
                });
            }
        }

        [HttpPost("logout")]
        [Authorize]
        public async Task<IActionResult> Logout()
        {
            try
            {
                // In produzione, invalida il refresh token nel database
                await _signInManager.SignOutAsync();

                _logger.LogInformation("User logged out successfully");
                return Ok(new ApiResponse<object>
                {
                    IsSuccess = true,
                    Message = "Logout successful",
                    StatusCode = 200
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during logout");
                return StatusCode(500, new ApiResponse<object>
                {
                    IsSuccess = false,
                    Message = "An error occurred during logout",
                    StatusCode = 500
                });
            }
        }

        [HttpPost("forgot-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ForgotPassword([FromBody] ForgotPasswordModel model)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(model?.Email))
                {
                    return BadRequest(new ApiResponse<object>
                    {
                        IsSuccess = false,
                        Message = "Email is required",
                        StatusCode = 400
                    });
                }

                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user == null)
                {
                    // Non rivelare se l'utente esiste o meno per sicurezza
                    return Ok(new ApiResponse<object>
                    {
                        IsSuccess = true,
                        Message = "If the email exists, a password reset link has been sent",
                        StatusCode = 200
                    });
                }

                var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                var resetLink = Url.Action("ResetPassword", "Authentication",
                    new { token, email = user.Email }, Request.Scheme);

                var message = new Message(new string[] { user.Email }, "Password Reset", resetLink!);
                _emailService.SendEmail(message);

                _logger.LogInformation("Password reset email sent to: {Email}", user.Email);
                return Ok(new ApiResponse<object>
                {
                    IsSuccess = true,
                    Message = "If the email exists, a password reset link has been sent",
                    StatusCode = 200
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during forgot password for email: {Email}", model?.Email);
                return StatusCode(500, new ApiResponse<object>
                {
                    IsSuccess = false,
                    Message = "An error occurred while processing your request",
                    StatusCode = 500
                });
            }
        }

        [HttpGet("reset-password")]
        public IActionResult ResetPassword(string token, string email)
        {
            if (string.IsNullOrWhiteSpace(token) || string.IsNullOrWhiteSpace(email))
            {
                return BadRequest(new ApiResponse<object>
                {
                    IsSuccess = false,
                    Message = "Token and email are required",
                    StatusCode = 400
                });
            }

            var model = new ResetPassword { Token = token, Email = email };
            return Ok(new ApiResponse<ResetPassword>
            {
                IsSuccess = true,
                Message = "Reset password form",
                StatusCode = 200,
                Response = model
            });
        }

        [HttpPost("reset-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPassword resetPassword)
        {
            try
            {
                if (!ModelState.IsValid)
                {
                    return BadRequest(new ApiResponse<object>
                    {
                        IsSuccess = false,
                        Message = "Invalid input data",
                        StatusCode = 400,
                        Response = ModelState
                    });
                }

                var user = await _userManager.FindByEmailAsync(resetPassword.Email);
                if (user == null)
                {
                    // Non rivelare se l'utente esiste per sicurezza
                    return Ok(new ApiResponse<object>
                    {
                        IsSuccess = true,
                        Message = "Password has been reset successfully",
                        StatusCode = 200
                    });
                }

                var result = await _userManager.ResetPasswordAsync(user, resetPassword.Token, resetPassword.Password);
                if (!result.Succeeded)
                {
                    _logger.LogWarning("Password reset failed for user: {Email}", resetPassword.Email);
                    return BadRequest(new ApiResponse<object>
                    {
                        IsSuccess = false,
                        Message = "Password reset failed",
                        StatusCode = 400,
                        Response = result.Errors
                    });
                }

                _logger.LogInformation("Password reset successfully for user: {Email}", user.Email);
                return Ok(new ApiResponse<object>
                {
                    IsSuccess = true,
                    Message = "Password has been reset successfully",
                    StatusCode = 200
                });
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during password reset for email: {Email}", resetPassword?.Email);
                return StatusCode(500, new ApiResponse<object>
                {
                    IsSuccess = false,
                    Message = "An error occurred during password reset",
                    StatusCode = 500
                });
            }
        }

        #region Private Methods

        private async Task<TokenResponse> GenerateTokensAsync(IdentityUser user)
        {
            var authClaims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.UserName!),
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
            };

            var userRoles = await _userManager.GetRolesAsync(user);
            authClaims.AddRange(userRoles.Select(role => new Claim(ClaimTypes.Role, role)));

            var accessToken = GenerateAccessToken(authClaims);
            var refreshToken = GenerateRefreshToken();

            return new TokenResponse
            {
                AccessToken = new JwtSecurityTokenHandler().WriteToken(accessToken),
                RefreshToken = refreshToken,
                ExpiresAt = accessToken.ValidTo,
                TokenType = "Bearer"
            };
        }

        private JwtSecurityToken GenerateAccessToken(List<Claim> authClaims)
        {
            var jwtSecret = _configuration["JWT:Secret"];
            if (string.IsNullOrEmpty(jwtSecret))
                throw new InvalidOperationException("JWT Secret not configured");

            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret));

            return new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: DateTime.UtcNow.AddMinutes(JWT_EXPIRY_MINUTES),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
            );
        }

        private string GenerateRefreshToken()
        {
            var randomNumber = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        private ClaimsPrincipal? GetPrincipalFromExpiredToken(string? token)
        {
            if (string.IsNullOrWhiteSpace(token))
                return null;

            var jwtSecret = _configuration["JWT:Secret"];
            if (string.IsNullOrEmpty(jwtSecret))
                return null;

            var tokenHandler = new JwtSecurityTokenHandler();
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = false, // Non validare la scadenza per il refresh
                ValidateIssuerSigningKey = true,
                ValidIssuer = _configuration["JWT:ValidIssuer"],
                ValidAudience = _configuration["JWT:ValidAudience"],
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret))
            };

            try
            {
                var principal = tokenHandler.ValidateToken(token, validationParameters, out _);
                return principal;
            }
            catch
            {
                return null;
            }
        }

        private bool IsValidRefreshToken(string refreshToken)
        {
            // In produzione, verifica contro il database
            // Per ora, controlla solo che non sia vuoto e abbia una lunghezza ragionevole
            return !string.IsNullOrWhiteSpace(refreshToken) && refreshToken.Length > 20;
        }

        #endregion
    }

    // Nuovi modelli per supportare il refresh token
    public class TokenResponse
    {
        public string AccessToken { get; set; } = null!;
        public string RefreshToken { get; set; } = null!;
        public DateTime ExpiresAt { get; set; }
        public string TokenType { get; set; } = "Bearer";
    }

    public class RefreshTokenModel
    {
        public string? AccessToken { get; set; }

        [Required(ErrorMessage = "Refresh token is required")]
        public string RefreshToken { get; set; } = null!;
    }

    public class TwoFactorLoginModel
    {
        [Required(ErrorMessage = "Username is required")]
        public string Username { get; set; } = null!;

        [Required(ErrorMessage = "Verification code is required")]
        public string Code { get; set; } = null!;
    }

    public class ForgotPasswordModel
    {
        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email format")]
        public string Email { get; set; } = null!;
    }
}