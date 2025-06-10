namespace OnePieceCardManagement.Configuration
{
    public class MinioConfiguration
    {
        public string Endpoint { get; set; } = string.Empty;
        public string AccessKey { get; set; } = string.Empty;
        public string SecretKey { get; set; } = string.Empty;
        public bool UseSSL { get; set; } = false;
        public string DefaultBucket { get; set; } = "tattoos";
        public string PublicUrl { get; set; } = string.Empty;
    }
}
