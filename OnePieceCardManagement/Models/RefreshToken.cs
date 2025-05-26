using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;
using Microsoft.AspNetCore.Identity;

namespace OnePieceCardManagement.Models
{
    public class RefreshToken
    {
        [Key]
        public int Id { get; set; }

        [Required]
        public string Token { get; set; } = null!;

        [Required]
        public string UserId { get; set; } = null!;

        [Required]
        public DateTime ExpiryDate { get; set; }

        [Required]
        public DateTime CreatedDate { get; set; }

        public DateTime? RevokedDate { get; set; }

        // Proprietà calcolate - non mappate al database
        [NotMapped]
        public bool IsRevoked => RevokedDate.HasValue;

        [NotMapped]
        public bool IsExpired => DateTime.UtcNow >= ExpiryDate;

        [NotMapped]
        public bool IsActive => !IsRevoked && !IsExpired;

        // Navigation property
        public virtual IdentityUser User { get; set; } = null!;

        // Metodi di utilità
        public void Revoke()
        {
            RevokedDate = DateTime.UtcNow;
        }

        public static RefreshToken Create(string userId, int expiryDays = 7)
        {
            var randomBytes = new byte[64];
            using var rng = System.Security.Cryptography.RandomNumberGenerator.Create();
            rng.GetBytes(randomBytes);

            return new RefreshToken
            {
                Token = Convert.ToBase64String(randomBytes),
                UserId = userId,
                CreatedDate = DateTime.UtcNow,
                ExpiryDate = DateTime.UtcNow.AddDays(expiryDays)
            };
        }
    }
}