namespace OnePieceCardManagement.DTOs.Tattoos
{
    public class TattooDto
    {
        public int Id { get; set; }
        public string Name { get; set; } = string.Empty;
        public string? ImageUrl { get; set; }
        public string Position { get; set; } = string.Empty;
        public string Style { get; set; } = string.Empty;
        public decimal AveragePrice { get; set; }
        public string? Notes { get; set; }
        public int Rating { get; set; }
        public DateTime CreatedAt { get; set; }
        public DateTime UpdatedAt { get; set; }
    }
}
