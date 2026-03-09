using SecureApiFoundation.Domain.Common;
using SecureApiFoundation.Domain.Enums;

namespace SecureApiFoundation.Domain.Entities;

public class SecurityLog : BaseEntity
{
    public Guid UserId { get; set; }
    public SecurityLogAction Action { get; set; }
    public string IpAddress { get; set; } = string.Empty;
    public string UserAgent { get; set; } = string.Empty;
    public string? Details { get; set; }
    public bool IsSuccess { get; set; }

    public User User { get; set; } = null!;
}
