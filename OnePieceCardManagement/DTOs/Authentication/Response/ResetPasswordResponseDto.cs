namespace OnePieceCardManagement.DTOs.Authentication.Response
{
    public class ResetPasswordResponseDto
    {
        public string Token { get; set; } = null!;
        public string Email { get; set; } = null!;
    }
}