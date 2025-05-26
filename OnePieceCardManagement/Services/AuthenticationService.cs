using MimeKit;
using MailKit.Net.Smtp;
using OnePieceCardManagement.Models;
using OnePieceCardManagement.Data;
using Microsoft.EntityFrameworkCore;

namespace OnePieceCardManagement.Services
{
    public interface IAuthenticationService
    {
        void SendEmail(Message message);
        Task<RefreshToken> CreateRefreshTokenAsync(string userId, int expiryDays = 7);
        Task<RefreshToken?> GetRefreshTokenAsync(string token);
        Task<bool> ValidateRefreshTokenAsync(string token, string userId);
        Task RevokeRefreshTokenAsync(string token);
        Task RevokeAllUserRefreshTokensAsync(string userId);
        Task CleanupExpiredTokensAsync();
    }

    public class AuthenticationService : IAuthenticationService
    {
        private readonly DataContext _context;
        private readonly ILogger<AuthenticationService> _logger;
        private readonly EmailConfiguration _emailConfig;
        public AuthenticationService(DataContext context, ILogger<AuthenticationService> logger, EmailConfiguration emailConfig)
        {
            _context = context;
            _logger = logger;
            _emailConfig = emailConfig;
        }

        public async Task<RefreshToken> CreateRefreshTokenAsync(string userId, int expiryDays = 7)
        {
            // Revoca i token precedenti dell'utente (opzionale - single session)
            await RevokeAllUserRefreshTokensAsync(userId);

            var refreshToken = RefreshToken.Create(userId, expiryDays);

            _context.RefreshTokens.Add(refreshToken);
            await _context.SaveChangesAsync();

            _logger.LogInformation("Created refresh token for user: {UserId}", userId);
            return refreshToken;
        }

        public async Task<RefreshToken?> GetRefreshTokenAsync(string token)
        {
            return await _context.RefreshTokens
                .Include(rt => rt.User)
                .FirstOrDefaultAsync(rt => rt.Token == token);
        }

        public async Task<bool> ValidateRefreshTokenAsync(string token, string userId)
        {
            var refreshToken = await GetRefreshTokenAsync(token);

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
            var refreshToken = await GetRefreshTokenAsync(token);
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

        public void SendEmail(Message message)
        {
            var emailMessage = CreateEmailMessage(message);
            Send(emailMessage);
        }

        private MimeMessage CreateEmailMessage(Message message)
        {
            var emailMessage = new MimeMessage();
            emailMessage.From.Add(new MailboxAddress("email",_emailConfig.From));
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
                //log an error message or throw an exception or both.
                throw;
            }
            finally
            {
                client.Disconnect(true);
                client.Dispose();
            }
        }
    }
}
