using SecureApiFoundation.Domain.Common;

namespace SecureApiFoundation.Domain.Entities;

public class UserSession : BaseEntity
{
    public Guid UserId { get; set; }
    public string RefreshTokenHash { get; set; } = string.Empty;
    public string DeviceInfo { get; set; } = string.Empty;
    public string IpAddress { get; set; } = string.Empty;
    public string UserAgent { get; set; } = string.Empty;
    public DateTime ExpiresAt { get; set; }
    public DateTime? RevokedAt { get; set; }
    public bool IsActive { get; set; } = true;
    public bool IsRevoked { get; set; } = false;

    public User User { get; set; } = null!;
}
