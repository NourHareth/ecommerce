using AmCart.UserService.Application.Interfaces;
using AmCart.UserService.Domain.Entities;
using AmCart.UserService.Infrastructure.Data;
using Microsoft.EntityFrameworkCore;
using System.Data;

namespace AmCart.UserService.Infrastructure.Repositories;

public class RefreshTokenRepository : IRefreshTokenRepository
{
    private readonly UserDbContext _db;

    public RefreshTokenRepository(UserDbContext db)
    {
        _db = db;
    }

    public async Task<RefreshToken?> GetByTokenHashAsync(string tokenHash, CancellationToken ct = default)
    {
        return await _db.RefreshTokens
            .Include(r => r.User)
            .FirstOrDefaultAsync(r => r.TokenHash == tokenHash && r.RevokedAt == null && r.ExpiresAt > DateTime.UtcNow, ct);
    }

    public async Task AddAsync(RefreshToken refreshToken, CancellationToken ct = default)
    {
        await _db.RefreshTokens.AddAsync(refreshToken, ct);
        await _db.SaveChangesAsync(ct);
    }

    public async Task RevokeAsync(RefreshToken refreshToken, CancellationToken ct = default)
    {
        refreshToken.RevokedAt = DateTime.UtcNow;
        _db.RefreshTokens.Update(refreshToken);
        await _db.SaveChangesAsync(ct);
    }

    public async Task<Guid?> ConsumeAsync(string tokenHash, CancellationToken ct = default)
    {
        var connection = _db.Database.GetDbConnection();
        var openedHere = connection.State != ConnectionState.Open;

        if (openedHere)
            await connection.OpenAsync(ct);

        try
        {
            await using var command = connection.CreateCommand();
            command.CommandText = """
                UPDATE refresh_tokens
                SET revoked_at = NOW()
                WHERE token_hash = @tokenHash
                  AND revoked_at IS NULL
                  AND expires_at > NOW()
                RETURNING user_id;
                """;

            var parameter = command.CreateParameter();
            parameter.ParameterName = "tokenHash";
            parameter.Value = tokenHash;
            command.Parameters.Add(parameter);

            var result = await command.ExecuteScalarAsync(ct);

            return result == null || result == DBNull.Value
                ? null
                : (Guid)result;
        }
        finally
        {
            if (openedHere)
                await connection.CloseAsync();
        }
    }

    public async Task RevokeAllForUserAsync(Guid userId, CancellationToken ct = default)
    {
        var tokens = await _db.RefreshTokens
            .Where(r => r.UserId == userId && r.RevokedAt == null)
            .ToListAsync(ct);

        foreach (var t in tokens)
            t.RevokedAt = DateTime.UtcNow;

        if (tokens.Count > 0)
        {
            _db.RefreshTokens.UpdateRange(tokens);
            await _db.SaveChangesAsync(ct);
        }
    }
}
