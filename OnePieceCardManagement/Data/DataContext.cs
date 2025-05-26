using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using OnePieceCardManagement.Models;

namespace OnePieceCardManagement.Data
{
    public class DataContext : IdentityDbContext
    {
        public DataContext(DbContextOptions<DataContext> options) : base(options)
        {
        }

        // DbSet per i refresh token
        public DbSet<RefreshToken> RefreshTokens { get; set; }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);

            // Configurazione per RefreshToken
            builder.Entity<RefreshToken>(entity =>
            {
                entity.HasKey(rt => rt.Id);

                entity.Property(rt => rt.Token)
                      .IsRequired()
                      .HasMaxLength(500);

                entity.Property(rt => rt.UserId)
                      .IsRequired();

                entity.Property(rt => rt.ExpiryDate)
                      .IsRequired();

                entity.Property(rt => rt.CreatedDate)
                      .IsRequired();

                entity.Property(rt => rt.RevokedDate)
                      .IsRequired(false);

                // Escludi esplicitamente le proprietà calcolate
                entity.Ignore(rt => rt.IsRevoked);
                entity.Ignore(rt => rt.IsExpired);
                entity.Ignore(rt => rt.IsActive);

                // Indici per migliorare le performance
                entity.HasIndex(rt => rt.Token)
                      .IsUnique();

                entity.HasIndex(rt => rt.UserId);

                entity.HasIndex(rt => rt.ExpiryDate);

                entity.HasIndex(rt => rt.RevokedDate);

                // Relazione con IdentityUser
                entity.HasOne(rt => rt.User)
                      .WithMany()
                      .HasForeignKey(rt => rt.UserId)
                      .OnDelete(DeleteBehavior.Cascade);
            });
        }
    }
}