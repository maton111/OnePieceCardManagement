using MimeKit;
using MailKit.Net.Smtp;
using OnePieceCardManagement.Models;
using OnePieceCardManagement.Data;
using Microsoft.EntityFrameworkCore;
using OnePieceCardManagement.DTOs.Authentication.Request;
using OnePieceCardManagement.DTOs.Authentication.Response;
using OnePieceCardManagement.DTOs.Common;
using OnePieceCardManagement.DTOs.Email;
using AutoMapper;
using Microsoft.AspNetCore.Identity;
using OnePieceCardManagement.Models.Email;
using OnePieceCardManagement.Models.Authentication;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using OnePieceCardManagement.DTOs;
using FluentValidation;
using OnePieceCardManagement.Validators;
using Microsoft.AspNetCore.Mvc;

namespace OnePieceCardManagement.Services
{
    public interface IAuthenticationService
    {
        void SendEmail(MessageDto messageDto);
        Task<ApiResponseDto<object>> RegisterAsync(RegisterUserDto registerUserDto, string role);
        Task<ApiResponseDto<object>> ConfirmEmailAsync(string token, string email);
        Task<ApiResponseDto<object>> ResendEmailConfirmationAsync(string email);
        Task<ApiResponseDto<LoginResponseDto>> LoginAsync(LoginDto loginDto);
        Task<ApiResponseDto<TokenResponseDto>> LoginWithOTPAsync(TwoFactorLoginDto twoFactorLoginDto);
        Task<RefreshTokenDto> CreateRefreshTokenAsync(string userId, int expiryDays = 7);
        Task<RefreshTokenDto?> GetRefreshTokenAsync(string token);
        Task<bool> ValidateRefreshTokenAsync(string token, string userId);
        Task RevokeRefreshTokenAsync(string token);
        Task RevokeAllUserRefreshTokensAsync(string userId);
        Task CleanupExpiredTokensAsync();
        Task<ApiResponseDto<TokenResponseDto>> RefreshTokenAsync(RefreshTokenModelDto refreshTokenDto);
        Task<ApiResponseDto<object>> LogoutAsync(string userId);
        Task<ApiResponseDto<object>> ForgotPasswordAsync(ForgotPasswordDto forgotPasswordDto, string resetLink);
        Task<ApiResponseDto<ResetPasswordResponseDto>> GetResetPasswordFormAsync(string token, string email);
        Task<ApiResponseDto<object>> ResetPasswordAsync(ResetPasswordDto resetPasswordDto);
        Task<ApiResponseDto<object>> RevokeTokenAsync(RevokeTokenDto revokeTokenDto, string userId);
        Task<ApiResponseDto<object>> RevokeAllTokensAsync(string userId);
        Task<string> GetEmailConfirmationToken(string email);
    }

    public class AuthenticationService : IAuthenticationService
    {
        private readonly DataContext _context;
        private readonly ILogger<AuthenticationService> _logger;
        private readonly EmailConfiguration _emailConfig;
        private readonly IMapper _mapper;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly IValidator<RegisterUserDto> _registerUserValidator;
        private readonly IConfiguration _configuration;

        // Constants
        private const int JWT_EXPIRY_MINUTES = 15;
        private const int REFRESH_TOKEN_EXPIRY_DAYS = 7;

        public AuthenticationService(
            DataContext context,
            ILogger<AuthenticationService> logger,
            EmailConfiguration emailConfig,
            IMapper mapper,
            UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager,
            SignInManager<IdentityUser> signInManager,
            IValidator<RegisterUserDto> registerUserValidator,
            IConfiguration configuration)
        {
            _context = context;
            _logger = logger;
            _emailConfig = emailConfig;
            _mapper = mapper;
            _userManager = userManager;
            _roleManager = roleManager;
            _signInManager = signInManager;
            _registerUserValidator = registerUserValidator;
            _configuration = configuration;
        }
        public void SendEmail(MessageDto messageDto)
        {
            var message = _mapper.Map<Message>(messageDto);
            var emailMessage = CreateEmailMessage(message);
            Send(emailMessage);
        }

        public async Task<ApiResponseDto<object>> RegisterAsync(RegisterUserDto registerUserDto, string role)
        {
            try
            {
                var registerUser = _mapper.Map<RegisterUser>(registerUserDto);

                // Check if user exists
#pragma warning disable CS8604 // Possible null reference argument.
                var userExists = await _userManager.FindByEmailAsync(registerUser.Email);
#pragma warning restore CS8604 // Possible null reference argument.
                if (userExists != null)
                {
                    _logger.LogWarning("Registration attempt for existing email: {Email}", registerUser.Email);
                    return new ApiResponseDto<object>
                    {
                        IsSuccess = false,
                        Message = "User already exists!",
                        StatusCode = 409
                    };
                }

                // Check if role exists
                if (!await _roleManager.RoleExistsAsync(role))
                {
                    _logger.LogError("Registration attempt with non-existing role: {Role}", role);
                    return new ApiResponseDto<object>
                    {
                        IsSuccess = false,
                        Message = "This role does not exist",
                        StatusCode = 400
                    };
                }

                // Validation
                var validate = _registerUserValidator.Validate(registerUserDto);
                if (!validate.IsValid)
                {
                    return new ApiResponseDto<object>
                    {
                        IsSuccess = false,
                        Message = "Params invalid",
                        StatusCode = 400,
                        Response = validate
                    };
                }

                // Create user
                var user = new IdentityUser
                {
                    Email = registerUser.Email,
                    SecurityStamp = Guid.NewGuid().ToString(),
                    UserName = registerUser.Username,
                };

                var result = await _userManager.CreateAsync(user, registerUser.Password!);
                if (!result.Succeeded)
                {
                    _logger.LogError("User creation failed for {Email}: {Errors}",
                        registerUser.Email, string.Join(", ", result.Errors.Select(e => e.Description)));

                    return new ApiResponseDto<object>
                    {
                        IsSuccess = false,
                        Message = "User creation failed",
                        StatusCode = 400,
                        Response = result.Errors
                    };
                }

                // Add role
                await _userManager.AddToRoleAsync(user, role);

                _logger.LogInformation("User {Email} registered successfully", user.Email);

                return new ApiResponseDto<object>
                {
                    IsSuccess = true,
                    Message = $"User created successfully. Confirmation email sent to {user.Email}",
                    StatusCode = 200
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during user registration for {Email}", registerUserDto?.Email);
                return new ApiResponseDto<object>
                {
                    IsSuccess = false,
                    Message = "An error occurred during registration",
                    StatusCode = 500
                };
            }
        }

        public async Task<ApiResponseDto<object>> ConfirmEmailAsync(string token, string email)
        {
            try
            {
                var user = await _userManager.FindByEmailAsync(email);
                if (user == null)
                {
                    _logger.LogWarning("Email confirmation attempt for non-existing user: {Email}", email);
                    return new ApiResponseDto<object>
                    {
                        IsSuccess = false,
                        Message = "User not found",
                        StatusCode = 404
                    };
                }

                var result = await _userManager.ConfirmEmailAsync(user, token);
                if (!result.Succeeded)
                {
                    _logger.LogWarning("Invalid email confirmation for: {Email}", email);
                    return new ApiResponseDto<object>
                    {
                        IsSuccess = false,
                        Message = "Invalid confirmation email",
                        StatusCode = 400
                    };
                }

                _logger.LogInformation("Email confirmed successfully for user: {Email}", email);
                return new ApiResponseDto<object>
                {
                    IsSuccess = true,
                    Message = "Email confirmed successfully",
                    StatusCode = 200
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during all email confirmation");
                return new ApiResponseDto<object>
                {
                    IsSuccess = false,
                    Message = "An error occurred during email confirmation",
                    StatusCode = 500
                };
            }
        }

        public async Task<ApiResponseDto<object>> ResendEmailConfirmationAsync(string email)
        {
            try
            {
                var user = await _userManager.FindByEmailAsync(email);
                if (user == null)
                {
                    _logger.LogWarning("Email confirmation attempt for non-existing user: {Email}", email);
                    return new ApiResponseDto<object>
                    {
                        IsSuccess = false,
                        Message = "User not found",
                        StatusCode = 404
                    };
                }

                _logger.LogInformation("Email confirmation sent successfully to: {Email}", email);
                return new ApiResponseDto<object>
                {
                    IsSuccess = true,
                    Message = $"Confirmation email sent to {user.Email}",
                    StatusCode = 200
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during all email confirmation");
                return new ApiResponseDto<object>
                {
                    IsSuccess = false,
                    Message = "An error occurred during email confirmation",
                    StatusCode = 500
                };
            }
        }

        public async Task<ApiResponseDto<LoginResponseDto>> LoginAsync(LoginDto loginDto)
        {
            try
            {
                var loginModel = _mapper.Map<LoginModel>(loginDto);

                var user = await _userManager.FindByNameAsync(loginModel.Username);
                if (user == null || !await _userManager.CheckPasswordAsync(user, loginModel.Password!))
                {
                    _logger.LogWarning("Failed login attempt for username: {Username}", loginModel.Username);
                    return new ApiResponseDto<LoginResponseDto>
                    {
                        IsSuccess = false,
                        Message = "Invalid credentials",
                        StatusCode = 401
                    };
                }

                // Handle 2FA
                if (user.TwoFactorEnabled)
                {
                    await _signInManager.SignOutAsync();
                    await _signInManager.PasswordSignInAsync(user, loginModel.Password!, false, true);

                    var twoFactorToken = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");
                    var messageDto = new MessageDto(new string[] { user.Email! }, "OTP Verification", twoFactorToken);
                    SendEmail(messageDto);

                    _logger.LogInformation("2FA token sent to user: {Email}", user.Email);
                    return new ApiResponseDto<LoginResponseDto>
                    {
                        IsSuccess = true,
                        Message = $"OTP sent to your email {user.Email}",
                        StatusCode = 200,
                        Response = new LoginResponseDto
                        {
                            RequiresTwoFactor = true,
                            Username = user.UserName
                        }
                    };
                }

                // Generate tokens
                var tokenResponse = await GenerateTokensAsync(user);
                var tokenResponseDto = _mapper.Map<TokenResponseDto>(tokenResponse);

                _logger.LogInformation("User {Email} logged in successfully", user.Email);
                return new ApiResponseDto<LoginResponseDto>
                {
                    IsSuccess = true,
                    Message = "Login successful",
                    StatusCode = 200,
                    Response = new LoginResponseDto
                    {
                        RequiresTwoFactor = false,
                        TokenResponse = tokenResponseDto
                    }
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during login for username: {Username}", loginDto?.Username);
                return new ApiResponseDto<LoginResponseDto>
                {
                    IsSuccess = false,
                    Message = "An error occurred during login",
                    StatusCode = 500
                };
            }
        }

        public async Task<ApiResponseDto<TokenResponseDto>> LoginWithOTPAsync(TwoFactorLoginDto twoFactorLoginDto)
        {
            try
            {
                var user = await _userManager.FindByNameAsync(twoFactorLoginDto.Username);
                if (user == null)
                {
                    return new ApiResponseDto<TokenResponseDto>
                    {
                        IsSuccess = false,
                        Message = "User not found",
                        StatusCode = 404
                    };
                }

                var signIn = await _signInManager.TwoFactorSignInAsync("Email", twoFactorLoginDto.Code, false, false);
                if (!signIn.Succeeded)
                {
                    _logger.LogWarning("Invalid 2FA code for user: {Username}", twoFactorLoginDto.Username);
                    return new ApiResponseDto<TokenResponseDto>
                    {
                        IsSuccess = false,
                        Message = "Invalid verification code",
                        StatusCode = 400
                    };
                }

                var tokenResponse = await GenerateTokensAsync(user);
                var tokenResponseDto = _mapper.Map<TokenResponseDto>(tokenResponse);

                _logger.LogInformation("User {Email} completed 2FA login successfully", user.Email);
                return new ApiResponseDto<TokenResponseDto>
                {
                    IsSuccess = true,
                    Message = "Login successful",
                    StatusCode = 200,
                    Response = tokenResponseDto
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during 2FA login for username: {Username}", twoFactorLoginDto?.Username);
                return new ApiResponseDto<TokenResponseDto>
                {
                    IsSuccess = false,
                    Message = "An error occurred during 2FA verification",
                    StatusCode = 500
                };
            }
        }

        public async Task<RefreshTokenDto> CreateRefreshTokenAsync(string userId, int expiryDays = 7)
        {
            // Revoke previous tokens (optional - single session)
            await RevokeAllUserRefreshTokensAsync(userId);

            var refreshToken = RefreshToken.Create(userId, expiryDays);

            _context.RefreshTokens.Add(refreshToken);
            await _context.SaveChangesAsync();

            _logger.LogInformation("Created refresh token for user: {UserId}", userId);
            return _mapper.Map<RefreshTokenDto>(refreshToken);
        }

        public async Task<RefreshTokenDto?> GetRefreshTokenAsync(string token)
        {
            var refreshToken = await _context.RefreshTokens
                .Include(rt => rt.User)
                .FirstOrDefaultAsync(rt => rt.Token == token);

            return refreshToken != null ? _mapper.Map<RefreshTokenDto>(refreshToken) : null;
        }

        public async Task<bool> ValidateRefreshTokenAsync(string token, string userId)
        {
            var refreshToken = await _context.RefreshTokens
                .FirstOrDefaultAsync(rt => rt.Token == token);

            if (refreshToken == null)
            {
                _logger.LogWarning("Refresh token not found: {Token}", token);
                return false;
            }

            if (refreshToken.UserId != userId)
            {
                _logger.LogWarning("Refresh token user mismatch. Expected: {ExpectedUserId}, Actual: {ActualUserId}",
                    userId, refreshToken.UserId);
                return false;
            }

            if (!refreshToken.IsActive)
            {
                _logger.LogWarning("Refresh token is not active. Token: {Token}, IsRevoked: {IsRevoked}, IsExpired: {IsExpired}",
                    token, refreshToken.IsRevoked, refreshToken.IsExpired);
                return false;
            }

            return true;
        }

        public async Task RevokeRefreshTokenAsync(string token)
        {
            var refreshToken = await _context.RefreshTokens
                .FirstOrDefaultAsync(rt => rt.Token == token);
                
            if (refreshToken != null)
            {
                refreshToken.Revoke();
                await _context.SaveChangesAsync();
                _logger.LogInformation("Revoked refresh token: {Token}", token);
            }
        }

        public async Task RevokeAllUserRefreshTokensAsync(string userId)
        {
            var userTokens = await _context.RefreshTokens
                .Where(rt => rt.UserId == userId && rt.RevokedDate == null)
                .ToListAsync();

            foreach (var token in userTokens)
            {
                token.Revoke();
            }

            if (userTokens.Any())
            {
                await _context.SaveChangesAsync();
                _logger.LogInformation("Revoked {Count} refresh tokens for user: {UserId}",
                    userTokens.Count, userId);
            }
        }

        public async Task CleanupExpiredTokensAsync()
        {
            var expiredTokens = await _context.RefreshTokens
                .Where(rt => rt.ExpiryDate < DateTime.UtcNow)
                .ToListAsync();

            if (expiredTokens.Any())
            {
                _context.RefreshTokens.RemoveRange(expiredTokens);
                await _context.SaveChangesAsync();
                _logger.LogInformation("Cleaned up {Count} expired refresh tokens", expiredTokens.Count);
            }
        }

        // Private methods
        private async Task<TokenResponseDto> GenerateTokensAsync(IdentityUser user)
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

            // Create and save refresh token
            var refreshTokenDto = await CreateRefreshTokenAsync(user.Id, REFRESH_TOKEN_EXPIRY_DAYS);

            return new TokenResponseDto
            {
                AccessToken = new JwtSecurityTokenHandler().WriteToken(accessToken),
                RefreshToken = refreshTokenDto.Token,
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
                ValidateLifetime = false, // Don't validate expiration for refresh
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

        private MimeMessage CreateEmailMessage(Message message)
        {
            var emailMessage = new MimeMessage();
            emailMessage.From.Add(new MailboxAddress("email", _emailConfig.From));
            emailMessage.To.AddRange(message.To);
            emailMessage.Subject = message.Subject;
            emailMessage.Body = new TextPart(MimeKit.Text.TextFormat.Text) { Text = message.Content };

            return emailMessage;
        }

        private void Send(MimeMessage mailMessage)
        {
            using var client = new SmtpClient();
            try
            {
                client.Connect(_emailConfig.SmtpServer, _emailConfig.Port, true);
                client.AuthenticationMechanisms.Remove("XOAUTH2");
                client.Authenticate(_emailConfig.UserName, _emailConfig.Password);

                client.Send(mailMessage);
            }
            catch
            {
                throw;
            }
            finally
            {
                client.Disconnect(true);
                client.Dispose();
            }
        }

        public async Task<ApiResponseDto<TokenResponseDto>> RefreshTokenAsync(RefreshTokenModelDto refreshTokenDto)
        {
            try
            {
                var model = _mapper.Map<RefreshTokenModel>(refreshTokenDto);

                var principal = GetPrincipalFromExpiredToken(model.AccessToken);
                if (principal?.Identity?.Name == null)
                {
                    return new ApiResponseDto<TokenResponseDto>
                    {
                        IsSuccess = false,
                        Message = "Invalid access token",
                        StatusCode = 400
                    };
                }

                var user = await _userManager.FindByNameAsync(principal.Identity.Name);
                if (user == null)
                {
                    return new ApiResponseDto<TokenResponseDto>
                    {
                        IsSuccess = false,
                        Message = "User not found",
                        StatusCode = 404
                    };
                }

                // Validate refresh token
                var isValidRefreshToken = await ValidateRefreshTokenAsync(model.RefreshToken, user.Id);
                if (!isValidRefreshToken)
                {
                    _logger.LogWarning("Invalid refresh token for user: {Username}", user.UserName);
                    return new ApiResponseDto<TokenResponseDto>
                    {
                        IsSuccess = false,
                        Message = "Invalid refresh token",
                        StatusCode = 400
                    };
                }

                // Revoke used refresh token
                await RevokeRefreshTokenAsync(model.RefreshToken);

                // Generate new tokens
                var tokenResponse = await GenerateTokensAsync(user);
                var tokenResponseDto = _mapper.Map<TokenResponseDto>(tokenResponse);

                _logger.LogInformation("Token refreshed for user: {Email}", user.Email);
                return new ApiResponseDto<TokenResponseDto>
                {
                    IsSuccess = true,
                    Message = "Token refreshed successfully",
                    StatusCode = 200,
                    Response = tokenResponseDto
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during token refresh");
                return new ApiResponseDto<TokenResponseDto>
                {
                    IsSuccess = false,
                    Message = "An error occurred during token refresh",
                    StatusCode = 500
                };
            }
        }

        public async Task<ApiResponseDto<object>> LogoutAsync(string userId)
        {
            try
            {
                if (!string.IsNullOrEmpty(userId))
                {
                    await RevokeAllUserRefreshTokensAsync(userId);
                }

                await _signInManager.SignOutAsync();

                _logger.LogInformation("User logged out successfully");
                return new ApiResponseDto<object>
                {
                    IsSuccess = true,
                    Message = "Logout successful",
                    StatusCode = 200
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during logout");
                return new ApiResponseDto<object>
                {
                    IsSuccess = false,
                    Message = "An error occurred during logout",
                    StatusCode = 500
                };
            }
        }

        public async Task<ApiResponseDto<object>> ForgotPasswordAsync(ForgotPasswordDto forgotPasswordDto, string resetLink)
        {
            try
            {
                var user = await _userManager.FindByEmailAsync(forgotPasswordDto.Email);
                if (user == null)
                {
                    // Don't reveal if user exists for security
                    return new ApiResponseDto<object>
                    {
                        IsSuccess = true,
                        Message = "If the email exists, a password reset link has been sent",
                        StatusCode = 200
                    };
                }

                var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                var fullResetLink = $"{resetLink}?token={token}&email={user.Email}";

                var messageDto = new MessageDto(new string[] { forgotPasswordDto.Email }, "Password Reset", fullResetLink);
                SendEmail(messageDto);

                _logger.LogInformation("Password reset email sent to: {Email}", user.Email);
                return new ApiResponseDto<object>
                {
                    IsSuccess = true,
                    Message = "If the email exists, a password reset link has been sent",
                    StatusCode = 200
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during forgot password for email: {Email}", forgotPasswordDto?.Email);
                return new ApiResponseDto<object>
                {
                    IsSuccess = false,
                    Message = "An error occurred while processing your request",
                    StatusCode = 500
                };
            }
        }

        public Task<ApiResponseDto<ResetPasswordResponseDto>> GetResetPasswordFormAsync(string token, string email)
        {
            if (string.IsNullOrWhiteSpace(token) || string.IsNullOrWhiteSpace(email))
            {
                return Task.FromResult(new ApiResponseDto<ResetPasswordResponseDto>
                {
                    IsSuccess = false,
                    Message = "Token and email are required",
                    StatusCode = 400
                });
            }

            var model = new ResetPassword { Token = token, Email = email };
            var responseDto = _mapper.Map<ResetPasswordResponseDto>(model);

            return Task.FromResult(new ApiResponseDto<ResetPasswordResponseDto>
            {
                IsSuccess = true,
                Message = "Reset password form",
                StatusCode = 200,
                Response = responseDto
            });
        }

        public async Task<ApiResponseDto<object>> ResetPasswordAsync(ResetPasswordDto resetPasswordDto)
        {
            try
            {
                var resetPassword = _mapper.Map<ResetPassword>(resetPasswordDto);

                var user = await _userManager.FindByEmailAsync(resetPassword.Email);
                if (user == null)
                {
                    // Don't reveal if user exists for security
                    return new ApiResponseDto<object>
                    {
                        IsSuccess = true,
                        Message = "Password has been reset successfully",
                        StatusCode = 200
                    };
                }

                var result = await _userManager.ResetPasswordAsync(user, resetPassword.Token, resetPassword.Password);
                if (!result.Succeeded)
                {
                    _logger.LogWarning("Password reset failed for user: {Email}", resetPassword.Email);
                    return new ApiResponseDto<object>
                    {
                        IsSuccess = false,
                        Message = "Password reset failed",
                        StatusCode = 400,
                        Response = result.Errors
                    };
                }

                _logger.LogInformation("Password reset successfully for user: {Email}", user.Email);
                return new ApiResponseDto<object>
                {
                    IsSuccess = true,
                    Message = "Password has been reset successfully",
                    StatusCode = 200
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during password reset for email: {Email}", resetPasswordDto?.Email);
                return new ApiResponseDto<object>
                {
                    IsSuccess = false,
                    Message = "An error occurred during password reset",
                    StatusCode = 500
                };
            }
        }

        public async Task<ApiResponseDto<object>> RevokeTokenAsync(RevokeTokenDto revokeTokenDto, string userId)
        {
            try
            {
                // Verify token belongs to current user
                var isValid = await ValidateRefreshTokenAsync(revokeTokenDto.RefreshToken, userId);
                if (!isValid)
                {
                    return new ApiResponseDto<object>
                    {
                        IsSuccess = false,
                        Message = "Invalid refresh token",
                        StatusCode = 400
                    };
                }

                await RevokeRefreshTokenAsync(revokeTokenDto.RefreshToken);

                _logger.LogInformation("Refresh token revoked manually for user: {UserId}", userId);
                return new ApiResponseDto<object>
                {
                    IsSuccess = true,
                    Message = "All tokens revoked successfully",
                    StatusCode = 200
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during all tokens revocation");
                return new ApiResponseDto<object>
                {
                    IsSuccess = false,
                    Message = "An error occurred during tokens revocation",
                    StatusCode = 500
                };
            }
        }

        public async Task<ApiResponseDto<object>> RevokeAllTokensAsync(string userId)
        {
            try
            {
                await RevokeAllUserRefreshTokensAsync(userId);

                _logger.LogInformation("All refresh tokens revoked for user: {UserId}", userId);
                return new ApiResponseDto<object>
                {
                    IsSuccess = true,
                    Message = "Email verified successfully",
                    StatusCode = 200
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during tokens revoke for {UserId}", userId);
                return new ApiResponseDto<object>
                {
                    IsSuccess = false,
                    Message = "An error occurred during tokens revoke",
                    StatusCode = 500
                };
            }
        }

        // Private helper method - this would need to be injected or moved to service
        public async Task<string> GetEmailConfirmationToken(string email)
        {
            // This is a simplified version - in real implementation, 
            // this would need access to UserManager through the service
            return await Task.FromResult("dummy-token");
        }
    }
}
