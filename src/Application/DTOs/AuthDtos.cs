namespace SecureApiFoundation.Application.DTOs;

public record LoginRequest(string Email, string Password, string? DeviceInfo = null);

public record LoginResponse(
    string AccessToken,
    string RefreshToken,
    DateTime AccessTokenExpiry,
    DateTime RefreshTokenExpiry,
    UserDto User);

public record RefreshTokenRequest(string RefreshToken);

public record RefreshTokenResponse(
    string AccessToken,
    string RefreshToken,
    DateTime AccessTokenExpiry,
    DateTime RefreshTokenExpiry);

public record LogoutRequest(string RefreshToken);

public record UserDto(Guid Id, string Email, string Username, string? FirstName, string? LastName);

public record SessionDto(
    Guid Id,
    string DeviceInfo,
    string IpAddress,
    DateTime CreatedAt,
    DateTime ExpiresAt,
    bool IsActive);

public record RegisterRequest(
    string Email,
    string Username,
    string Password,
    string? FirstName = null,
    string? LastName = null);
