namespace SecureApiFoundation.Domain.Enums;

public enum SecurityLogAction
{
    Login,
    LoginFailed,
    Logout,
    LogoutAll,
    TokenRefresh,
    TokenRefreshFailed,
    TokenReuseDetected,
    PasswordChanged,
    AccountLocked
}
