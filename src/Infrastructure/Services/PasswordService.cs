using Microsoft.AspNetCore.Identity;
using SecureApiFoundation.Application.Interfaces;
using SecureApiFoundation.Domain.Entities;

namespace SecureApiFoundation.Infrastructure.Services;

public class PasswordService : IPasswordService
{
    private readonly IPasswordHasher<User> _passwordHasher;
    private static readonly User _dummyUser = new();

    public PasswordService(IPasswordHasher<User> passwordHasher)
    {
        _passwordHasher = passwordHasher;
    }

    public string HashPassword(string password) =>
        _passwordHasher.HashPassword(_dummyUser, password);

    public bool VerifyPassword(string hashedPassword, string providedPassword)
    {
        var result = _passwordHasher.VerifyHashedPassword(_dummyUser, hashedPassword, providedPassword);
        return result != PasswordVerificationResult.Failed;
    }
}
