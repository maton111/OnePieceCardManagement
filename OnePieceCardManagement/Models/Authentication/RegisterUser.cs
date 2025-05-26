using System.ComponentModel.DataAnnotations;

namespace OnePieceCardManagement.Models.Authentication
{
    public class RegisterUser
    {
        public string? Username { get; set; }

        public string? Email { get; set; }

        public string? Password { get; set; }
    }
}
