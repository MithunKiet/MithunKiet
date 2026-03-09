using Microsoft.AspNetCore.Identity;
using SecureApiFoundation.Application.Interfaces;
using SecureApiFoundation.Domain.Entities;

namespace SecureApiFoundation.Infrastructure.Services;

public class PasswordService : IPasswordService
{
    private readonly IPasswordHasher<User> _passwordHasher = new PasswordHasher<User>();

    public string HashPassword(string password) =>
        _passwordHasher.HashPassword(null!, password);

    public bool VerifyPassword(string hashedPassword, string providedPassword)
    {
        var result = _passwordHasher.VerifyHashedPassword(null!, hashedPassword, providedPassword);
        return result != PasswordVerificationResult.Failed;
    }
}
