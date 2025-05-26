namespace OnePieceCardManagement.DTOs.Email
{
    public class MessageDto
    {
        public List<string> To { get; set; }
        public string Subject { get; set; }
        public string Content { get; set; }

        public MessageDto(IEnumerable<string> to, string subject, string content)
        {
            To = to.ToList();
            Subject = subject;
            Content = content;
        }
    }
}