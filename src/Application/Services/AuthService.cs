using SecureApiFoundation.Application.Common;
using SecureApiFoundation.Application.DTOs;
using SecureApiFoundation.Application.Interfaces;
using SecureApiFoundation.Domain.Entities;
using SecureApiFoundation.Domain.Enums;
using Microsoft.Extensions.Logging;

namespace SecureApiFoundation.Application.Services;

public class AuthService : IAuthService
{
    private readonly IUserRepository _userRepository;
    private readonly IUserSessionRepository _sessionRepository;
    private readonly ISecurityLogRepository _securityLogRepository;
    private readonly ITokenService _tokenService;
    private readonly IPasswordService _passwordService;
    private readonly ILogger<AuthService> _logger;

    private const int MaxFailedAttempts = 5;
    private const int LockoutMinutes = 15;

    public AuthService(
        IUserRepository userRepository,
        IUserSessionRepository sessionRepository,
        ISecurityLogRepository securityLogRepository,
        ITokenService tokenService,
        IPasswordService passwordService,
        ILogger<AuthService> logger)
    {
        _userRepository = userRepository;
        _sessionRepository = sessionRepository;
        _securityLogRepository = securityLogRepository;
        _tokenService = tokenService;
        _passwordService = passwordService;
        _logger = logger;
    }

    public async Task<Result<LoginResponse>> LoginAsync(LoginRequest request, string ipAddress, string userAgent, CancellationToken cancellationToken = default)
    {
        var user = await _userRepository.GetByEmailAsync(request.Email, cancellationToken);

        if (user is null)
        {
            _logger.LogWarning("Login failed: user not found for email {Email}", request.Email);
            return Result<LoginResponse>.Unauthorized("Invalid credentials.");
        }

        if (!user.IsActive)
        {
            await LogSecurityEventAsync(user.Id, SecurityLogAction.LoginFailed, ipAddress, userAgent, "Account inactive", false, cancellationToken);
            return Result<LoginResponse>.Unauthorized("Account is disabled.");
        }

        if (user.LockoutEnd.HasValue && user.LockoutEnd > DateTime.UtcNow)
        {
            await LogSecurityEventAsync(user.Id, SecurityLogAction.LoginFailed, ipAddress, userAgent, "Account locked", false, cancellationToken);
            return Result<LoginResponse>.Unauthorized($"Account is locked. Try again after {user.LockoutEnd:u}.");
        }

        if (!_passwordService.VerifyPassword(user.PasswordHash, request.Password))
        {
            user.FailedLoginAttempts++;
            if (user.FailedLoginAttempts >= MaxFailedAttempts)
            {
                user.LockoutEnd = DateTime.UtcNow.AddMinutes(LockoutMinutes);
                _logger.LogWarning("Account locked for user {UserId} after {Attempts} failed attempts", user.Id, user.FailedLoginAttempts);
                await LogSecurityEventAsync(user.Id, SecurityLogAction.AccountLocked, ipAddress, userAgent, "Too many failed attempts", false, cancellationToken);
            }

            await _userRepository.UpdateAsync(user, cancellationToken);
            await LogSecurityEventAsync(user.Id, SecurityLogAction.LoginFailed, ipAddress, userAgent, "Invalid password", false, cancellationToken);
            return Result<LoginResponse>.Unauthorized("Invalid credentials.");
        }

        // Reset failed attempts on successful login
        user.FailedLoginAttempts = 0;
        user.LockoutEnd = null;
        await _userRepository.UpdateAsync(user, cancellationToken);

        var refreshToken = _tokenService.GenerateRefreshToken();
        var session = new UserSession
        {
            UserId = user.Id,
            RefreshTokenHash = _tokenService.HashToken(refreshToken),
            DeviceInfo = request.DeviceInfo ?? "Unknown",
            IpAddress = ipAddress,
            UserAgent = userAgent,
            ExpiresAt = _tokenService.GetRefreshTokenExpiry(),
            IsActive = true
        };

        await _sessionRepository.CreateAsync(session, cancellationToken);
        await LogSecurityEventAsync(user.Id, SecurityLogAction.Login, ipAddress, userAgent, $"Session: {session.Id}", true, cancellationToken);

        var accessToken = _tokenService.GenerateAccessToken(user);
        return Result<LoginResponse>.Success(new LoginResponse(
            accessToken,
            refreshToken,
            _tokenService.GetAccessTokenExpiry(),
            session.ExpiresAt,
            MapToUserDto(user)));
    }

    public async Task<Result<RefreshTokenResponse>> RefreshTokenAsync(RefreshTokenRequest request, string ipAddress, string userAgent, CancellationToken cancellationToken = default)
    {
        var tokenHash = _tokenService.HashToken(request.RefreshToken);
        var session = await _sessionRepository.GetActiveSessionByTokenHashAsync(tokenHash, cancellationToken);

        if (session is null)
        {
            _logger.LogWarning("Refresh token not found or inactive. Possible token reuse.");
            return Result<RefreshTokenResponse>.Unauthorized("Invalid or expired refresh token.");
        }

        if (session.ExpiresAt < DateTime.UtcNow)
        {
            session.IsActive = false;
            session.RevokedAt = DateTime.UtcNow;
            await _sessionRepository.UpdateAsync(session, cancellationToken);
            await LogSecurityEventAsync(session.UserId, SecurityLogAction.TokenRefreshFailed, ipAddress, userAgent, "Token expired", false, cancellationToken);
            return Result<RefreshTokenResponse>.Unauthorized("Refresh token has expired.");
        }

        var user = await _userRepository.GetByIdAsync(session.UserId, cancellationToken);
        if (user is null || !user.IsActive)
        {
            return Result<RefreshTokenResponse>.Unauthorized("User not found or inactive.");
        }

        // Token rotation: revoke old session
        session.IsActive = false;
        session.IsRevoked = true;
        session.RevokedAt = DateTime.UtcNow;
        await _sessionRepository.UpdateAsync(session, cancellationToken);

        // Create new session
        var newRefreshToken = _tokenService.GenerateRefreshToken();
        var newSession = new UserSession
        {
            UserId = user.Id,
            RefreshTokenHash = _tokenService.HashToken(newRefreshToken),
            DeviceInfo = session.DeviceInfo,
            IpAddress = ipAddress,
            UserAgent = userAgent,
            ExpiresAt = _tokenService.GetRefreshTokenExpiry(),
            IsActive = true
        };

        await _sessionRepository.CreateAsync(newSession, cancellationToken);
        await LogSecurityEventAsync(user.Id, SecurityLogAction.TokenRefresh, ipAddress, userAgent, null, true, cancellationToken);

        var accessToken = _tokenService.GenerateAccessToken(user);
        return Result<RefreshTokenResponse>.Success(new RefreshTokenResponse(
            accessToken,
            newRefreshToken,
            _tokenService.GetAccessTokenExpiry(),
            newSession.ExpiresAt));
    }

    public async Task<Result> LogoutAsync(LogoutRequest request, Guid userId, CancellationToken cancellationToken = default)
    {
        var tokenHash = _tokenService.HashToken(request.RefreshToken);
        var session = await _sessionRepository.GetActiveSessionByTokenHashAsync(tokenHash, cancellationToken);

        if (session is null || session.UserId != userId)
        {
            return Result.Failure("Session not found.", 404);
        }

        session.IsActive = false;
        session.IsRevoked = true;
        session.RevokedAt = DateTime.UtcNow;
        await _sessionRepository.UpdateAsync(session, cancellationToken);
        await LogSecurityEventAsync(userId, SecurityLogAction.Logout, string.Empty, string.Empty, $"Session: {session.Id}", true, cancellationToken);

        return Result.Success();
    }

    public async Task<Result> LogoutAllAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        await _sessionRepository.RevokeAllUserSessionsAsync(userId, cancellationToken);
        await LogSecurityEventAsync(userId, SecurityLogAction.LogoutAll, string.Empty, string.Empty, "All sessions revoked", true, cancellationToken);
        return Result.Success();
    }

    public async Task<Result<IEnumerable<SessionDto>>> GetSessionsAsync(Guid userId, CancellationToken cancellationToken = default)
    {
        var sessions = await _sessionRepository.GetActiveSessionsByUserIdAsync(userId, cancellationToken);
        var dtos = sessions.Select(s => new SessionDto(
            s.Id,
            s.DeviceInfo,
            s.IpAddress,
            s.CreatedAt,
            s.ExpiresAt,
            s.IsActive));
        return Result<IEnumerable<SessionDto>>.Success(dtos);
    }

    public async Task<Result<UserDto>> RegisterAsync(RegisterRequest request, CancellationToken cancellationToken = default)
    {
        if (await _userRepository.EmailExistsAsync(request.Email, cancellationToken))
            return Result<UserDto>.Failure("Email is already registered.");

        if (await _userRepository.UsernameExistsAsync(request.Username, cancellationToken))
            return Result<UserDto>.Failure("Username is already taken.");

        var user = new User
        {
            Email = request.Email.ToLowerInvariant(),
            Username = request.Username,
            FirstName = request.FirstName,
            LastName = request.LastName,
            IsActive = true
        };

        user.PasswordHash = _passwordService.HashPassword(request.Password);
        var createdUser = await _userRepository.CreateAsync(user, cancellationToken);
        return Result<UserDto>.Success(MapToUserDto(createdUser));
    }

    private static UserDto MapToUserDto(User user) =>
        new(user.Id, user.Email, user.Username, user.FirstName, user.LastName);

    private async Task LogSecurityEventAsync(Guid userId, SecurityLogAction action, string ipAddress, string userAgent, string? details, bool isSuccess, CancellationToken cancellationToken)
    {
        try
        {
            await _securityLogRepository.CreateAsync(new SecurityLog
            {
                UserId = userId,
                Action = action,
                IpAddress = ipAddress,
                UserAgent = userAgent,
                Details = details,
                IsSuccess = isSuccess
            }, cancellationToken);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to write security log for user {UserId}", userId);
        }
    }
}
