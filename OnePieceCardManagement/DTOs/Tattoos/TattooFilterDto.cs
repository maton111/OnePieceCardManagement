namespace OnePieceCardManagement.DTOs.Tattoos
{
    public class TattooFilterDto
    {
        public string? Style { get; set; }
        public string? Position { get; set; }
        public decimal? MinPrice { get; set; }
        public decimal? MaxPrice { get; set; }
        public int? Rating { get; set; }
        public string? Sort { get; set; }
        public string? Order { get; set; } = "asc";
    }
}
