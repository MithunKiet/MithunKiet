using SecureApiFoundation.Domain.Entities;

namespace SecureApiFoundation.Application.Interfaces;

public interface ITokenService
{
    string GenerateAccessToken(User user);
    string GenerateRefreshToken();
    string HashToken(string token);
    Guid? GetUserIdFromExpiredToken(string accessToken);
    DateTime GetAccessTokenExpiry();
    DateTime GetRefreshTokenExpiry();
}
