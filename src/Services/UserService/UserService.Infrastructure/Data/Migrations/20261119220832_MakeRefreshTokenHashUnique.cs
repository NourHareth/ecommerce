using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace AmCart.UserService.Infrastructure.Data.Migrations
{
    /// <inheritdoc />
    public partial class MakeRefreshTokenHashUnique : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_refresh_tokens_token_hash",
                table: "refresh_tokens");

            migrationBuilder.CreateIndex(
                name: "IX_refresh_tokens_token_hash",
                table: "refresh_tokens",
                column: "token_hash",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_refresh_tokens_token_hash",
                table: "refresh_tokens");

            migrationBuilder.CreateIndex(
                name: "IX_refresh_tokens_token_hash",
                table: "refresh_tokens",
                column: "token_hash");
        }
    }
}
