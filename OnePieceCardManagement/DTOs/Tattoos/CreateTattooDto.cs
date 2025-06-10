namespace OnePieceCardManagement.DTOs.Tattoos
{
    public class CreateTattooDto
    {
        public string Name { get; set; } = string.Empty;
        public string? ImageUrl { get; set; }
        public string Position { get; set; } = string.Empty;
        public string Style { get; set; } = string.Empty;
        public decimal AveragePrice { get; set; }
        public string? Notes { get; set; }
        public int Rating { get; set; }
    }

    public class UpdateTattooDto : CreateTattooDto
    {
        public int Id { get; set; }
    }
}
