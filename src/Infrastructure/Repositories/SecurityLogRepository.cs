using Microsoft.EntityFrameworkCore;
using SecureApiFoundation.Application.Interfaces;
using SecureApiFoundation.Domain.Entities;
using SecureApiFoundation.Infrastructure.Database;

namespace SecureApiFoundation.Infrastructure.Repositories;

public class SecurityLogRepository : ISecurityLogRepository
{
    private readonly AppDbContext _context;

    public SecurityLogRepository(AppDbContext context) => _context = context;

    public async Task CreateAsync(SecurityLog log, CancellationToken cancellationToken = default)
    {
        _context.SecurityLogs.Add(log);
        await _context.SaveChangesAsync(cancellationToken);
    }

    public async Task<IEnumerable<SecurityLog>> GetByUserIdAsync(Guid userId, int take = 50, CancellationToken cancellationToken = default) =>
        await _context.SecurityLogs
            .Where(l => l.UserId == userId)
            .OrderByDescending(l => l.CreatedAt)
            .Take(take)
            .ToListAsync(cancellationToken);
}
