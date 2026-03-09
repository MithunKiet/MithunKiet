using SecureApiFoundation.Application.Common;
using SecureApiFoundation.Application.DTOs;

namespace SecureApiFoundation.Application.Interfaces;

public interface IAuthService
{
    Task<Result<LoginResponse>> LoginAsync(LoginRequest request, string ipAddress, string userAgent, CancellationToken cancellationToken = default);
    Task<Result<RefreshTokenResponse>> RefreshTokenAsync(RefreshTokenRequest request, string ipAddress, string userAgent, CancellationToken cancellationToken = default);
    Task<Result> LogoutAsync(LogoutRequest request, Guid userId, CancellationToken cancellationToken = default);
    Task<Result> LogoutAllAsync(Guid userId, CancellationToken cancellationToken = default);
    Task<Result<IEnumerable<SessionDto>>> GetSessionsAsync(Guid userId, CancellationToken cancellationToken = default);
    Task<Result<UserDto>> RegisterAsync(RegisterRequest request, CancellationToken cancellationToken = default);
}
