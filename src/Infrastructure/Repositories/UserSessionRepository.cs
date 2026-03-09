using Microsoft.EntityFrameworkCore;
using SecureApiFoundation.Application.Interfaces;
using SecureApiFoundation.Domain.Entities;
using SecureApiFoundation.Infrastructure.Database;

namespace SecureApiFoundation.Infrastructure.Repositories;

public class UserSessionRepository : IUserSessionRepository
{
    private readonly AppDbContext _context;

    public UserSessionRepository(AppDbContext context) => _context = context;

    public async Task<UserSession?> GetByIdAsync(Guid id, CancellationToken cancellationToken = default) =>
        await _context.UserSessions.FindAsync([id], cancellationToken);

    public async Task<UserSession?> GetActiveSessionByTokenHashAsync(string tokenHash, CancellationToken cancellationToken = default) =>
        await _context.UserSessions
            .FirstOrDefaultAsync(s => s.RefreshTokenHash == tokenHash && s.IsActive && !s.IsRevoked, cancellationToken);

    public async Task<IEnumerable<UserSession>> GetActiveSessionsByUserIdAsync(Guid userId, CancellationToken cancellationToken = default) =>
        await _context.UserSessions
            .Where(s => s.UserId == userId && s.IsActive && !s.IsRevoked && s.ExpiresAt > DateTime.UtcNow)
            .OrderByDescending(s => s.CreatedAt)
            .ToListAsync(cancellationToken);

    public async Task<UserSession> CreateAsync(UserSession session, CancellationToken cancellationToken = default)
    {
        _context.UserSessions.Add(session);
        await _context.SaveChangesAsync(cancellationToken);
        return session;
    }

    public async Task UpdateAsync(UserSession session, CancellationToken cancellationToken = default)
    {
        session.UpdatedAt = DateTime.UtcNow;
        _context.UserSessions.Update(session);
        await _context.SaveChangesAsync(cancellationToken);
    }

    public async Task RevokeAllUserSessionsAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        var sessions = await _context.UserSessions
            .Where(s => s.UserId == userId && s.IsActive)
            .ToListAsync(cancellationToken);

        var now = DateTime.UtcNow;
        foreach (var session in sessions)
        {
            session.IsActive = false;
            session.IsRevoked = true;
            session.RevokedAt = now;
            session.UpdatedAt = now;
        }

        await _context.SaveChangesAsync(cancellationToken);
    }
}
