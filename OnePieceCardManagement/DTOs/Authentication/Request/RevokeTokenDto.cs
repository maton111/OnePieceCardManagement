using System.ComponentModel.DataAnnotations;

namespace OnePieceCardManagement.DTOs.Authentication.Request
{
    public class RevokeTokenDto
    {
        [Required(ErrorMessage = "Refresh token is required")]
        public string RefreshToken { get; set; } = null!;
    }
}
