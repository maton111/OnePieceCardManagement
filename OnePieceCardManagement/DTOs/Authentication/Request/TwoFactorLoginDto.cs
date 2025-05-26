using System.ComponentModel.DataAnnotations;

namespace OnePieceCardManagement.DTOs.Authentication.Request
{
    public class TwoFactorLoginDto
    {
        [Required(ErrorMessage = "Username is required")]
        public string Username { get; set; } = null!;

        [Required(ErrorMessage = "Verification code is required")]
        public string Code { get; set; } = null!;
    }
}