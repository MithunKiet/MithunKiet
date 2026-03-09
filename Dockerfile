# =============================================
# Build Stage
# =============================================
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

# Copy project files and restore dependencies
COPY ["src/Domain/SecureApiFoundation.Domain.csproj", "Domain/"]
COPY ["src/Application/SecureApiFoundation.Application.csproj", "Application/"]
COPY ["src/Infrastructure/SecureApiFoundation.Infrastructure.csproj", "Infrastructure/"]
COPY ["src/Api/SecureApiFoundation.Api.csproj", "Api/"]

RUN dotnet restore "Api/SecureApiFoundation.Api.csproj"

# Copy all source files
COPY src/Domain/ Domain/
COPY src/Application/ Application/
COPY src/Infrastructure/ Infrastructure/
COPY src/Api/ Api/

# Build and publish
WORKDIR /src/Api
RUN dotnet publish "SecureApiFoundation.Api.csproj" -c Release -o /app/publish --no-restore

# =============================================
# Runtime Stage
# =============================================
FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app

# Create non-root user
RUN addgroup --system appgroup && adduser --system --ingroup appgroup appuser

# Create logs directory
RUN mkdir -p /app/logs && chown -R appuser:appgroup /app/logs

COPY --from=build /app/publish .

# Switch to non-root user
USER appuser

EXPOSE 8080
ENV ASPNETCORE_URLS=http://+:8080
ENV ASPNETCORE_ENVIRONMENT=Production

ENTRYPOINT ["dotnet", "SecureApiFoundation.Api.dll"]
