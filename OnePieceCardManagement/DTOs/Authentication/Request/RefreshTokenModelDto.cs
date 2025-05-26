using System.ComponentModel.DataAnnotations;

namespace OnePieceCardManagement.DTOs.Authentication.Request
{
    public class RefreshTokenModelDto
    {
        public string? AccessToken { get; set; }

        [Required(ErrorMessage = "Refresh token is required")]
        public string RefreshToken { get; set; } = null!;
    }
}