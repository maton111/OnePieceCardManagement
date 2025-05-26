using OnePieceCardManagement.Services;

namespace OnePieceCardManagement.Services
{
    public class TokenCleanupService : BackgroundService
    {
        private readonly IServiceProvider _serviceProvider;
        private readonly ILogger<TokenCleanupService> _logger;
        private readonly TimeSpan _cleanupInterval = TimeSpan.FromHours(24); // Esegue pulizia ogni 24 ore

        public TokenCleanupService(IServiceProvider serviceProvider, ILogger<TokenCleanupService> logger)
        {
            _serviceProvider = serviceProvider;
            _logger = logger;
        }

        protected override async Task ExecuteAsync(CancellationToken stoppingToken)
        {
            _logger.LogInformation("Token cleanup service started");

            while (!stoppingToken.IsCancellationRequested)
            {
                try
                {
                    using var scope = _serviceProvider.CreateScope();
                    var refreshTokenService = scope.ServiceProvider.GetRequiredService<IAuthenticationService>();

                    await refreshTokenService.CleanupExpiredTokensAsync();

                    _logger.LogInformation("Token cleanup completed successfully");
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Error occurred during token cleanup");
                }

                // Attende il prossimo intervallo di pulizia
                await Task.Delay(_cleanupInterval, stoppingToken);
            }

            _logger.LogInformation("Token cleanup service stopped");
        }

        public override async Task StopAsync(CancellationToken cancellationToken)
        {
            _logger.LogInformation("Token cleanup service is stopping");
            await base.StopAsync(cancellationToken);
        }
    }
}