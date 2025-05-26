using System.ComponentModel.DataAnnotations;

namespace OnePieceCardManagement.Models.Authentication
{
    public class RefreshTokenModel
    {
        public string? AccessToken { get; set; }
        public string RefreshToken { get; set; } = null!;
    }
}
