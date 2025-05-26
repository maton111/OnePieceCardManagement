using System.ComponentModel.DataAnnotations;

namespace OnePieceCardManagement.DTOs.Authentication.Request
{
    public class ForgotPasswordDto
    {
        [Required(ErrorMessage = "Email is required")]
        [EmailAddress(ErrorMessage = "Invalid email format")]
        public string Email { get; set; } = null!;
    }
}