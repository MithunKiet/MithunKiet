using SecureApiFoundation.Domain.Entities;
using SecureApiFoundation.Domain.Enums;

namespace SecureApiFoundation.Application.Interfaces;

public interface ISecurityLogRepository
{
    Task CreateAsync(SecurityLog log, CancellationToken cancellationToken = default);
    Task<IEnumerable<SecurityLog>> GetByUserIdAsync(Guid userId, int take = 50, CancellationToken cancellationToken = default);
}
