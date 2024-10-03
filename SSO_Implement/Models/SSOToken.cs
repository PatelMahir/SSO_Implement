namespace SSO_Implement.Models
{
    public class SSOToken
    {
        public int Id { get; set; }
        public string UserId {  get; set; }
        public string Token {  get; set; }
        public DateTime ExpiryDate {  get; set; }
        public bool IsUsed {  get; set; }
        public bool IsExpired => DateTime.UtcNow > ExpiryDate;
    }
}