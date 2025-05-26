using System.ComponentModel.DataAnnotations;

namespace OnePieceCardManagement.Models.Authentication
{
    public class ResetPassword
    {
        public string Password { get; set; } = null!;
        public string ConfirmPassword { get; set; } = null!;
        public string Email { get; set; } = null!;
        public string Token { get; set; } = null!;
    }
}
