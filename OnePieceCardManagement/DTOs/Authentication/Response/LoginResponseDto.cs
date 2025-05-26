namespace OnePieceCardManagement.DTOs.Authentication.Response
{
    public class LoginResponseDto
    {
        public bool RequiresTwoFactor { get; set; }
        public string? Username { get; set; }
        public TokenResponseDto? TokenResponse { get; set; }
    }
}