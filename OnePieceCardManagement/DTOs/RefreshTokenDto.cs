namespace OnePieceCardManagement.DTOs
{
    public class RefreshTokenDto
    {
        public int Id { get; set; }
        public string Token { get; set; } = null!;
        public string UserId { get; set; } = null!;
        public DateTime ExpiryDate { get; set; }
        public DateTime CreatedDate { get; set; }
        public DateTime? RevokedDate { get; set; }
        public bool IsRevoked { get; set; }
        public bool IsExpired { get; set; }
        public bool IsActive { get; set; }
    }
}