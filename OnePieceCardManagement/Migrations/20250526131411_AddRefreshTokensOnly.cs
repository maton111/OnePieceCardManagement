// Crea una nuova migration manualmente in Migrations/[Timestamp]_AddRefreshTokensOnly.cs

using Microsoft.EntityFrameworkCore.Migrations;
using Npgsql.EntityFrameworkCore.PostgreSQL.Metadata;

#nullable disable

namespace OnePieceCardManagement.Migrations
{
    /// <inheritdoc />
    public partial class AddRefreshTokensOnly : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Controlla se la tabella esiste già prima di crearla
            migrationBuilder.Sql(@"
                DO $$ 
                BEGIN
                    IF NOT EXISTS (SELECT FROM pg_tables WHERE schemaname = 'public' AND tablename = 'RefreshTokens') THEN
                        CREATE TABLE ""RefreshTokens"" (
                            ""Id"" SERIAL PRIMARY KEY,
                            ""Token"" character varying(500) NOT NULL,
                            ""UserId"" text NOT NULL,
                            ""ExpiryDate"" timestamp with time zone NOT NULL,
                            ""CreatedDate"" timestamp with time zone NOT NULL,
                            ""RevokedDate"" timestamp with time zone,
                            CONSTRAINT ""FK_RefreshTokens_AspNetUsers_UserId"" FOREIGN KEY (""UserId"") REFERENCES ""AspNetUsers"" (""Id"") ON DELETE CASCADE
                        );
                        
                        CREATE UNIQUE INDEX ""IX_RefreshTokens_Token"" ON ""RefreshTokens"" (""Token"");
                        CREATE INDEX ""IX_RefreshTokens_UserId"" ON ""RefreshTokens"" (""UserId"");
                        CREATE INDEX ""IX_RefreshTokens_ExpiryDate"" ON ""RefreshTokens"" (""ExpiryDate"");
                        CREATE INDEX ""IX_RefreshTokens_RevokedDate"" ON ""RefreshTokens"" (""RevokedDate"");
                    END IF;
                END $$;
            ");
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropTable(
                name: "RefreshTokens");
        }
    }
}