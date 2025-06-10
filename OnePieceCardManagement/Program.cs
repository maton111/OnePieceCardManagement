using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using OnePieceCardManagement.Data;
using OnePieceCardManagement.Services;
using OnePieceCardManagement.Middleware;
using OnePieceCardManagement.Mappings;
using System.Text;
using OnePieceCardManagement.Models.Email;
using OnePieceCardManagement.Standards;
using Microsoft.Extensions.Options;
using Minio;
using OnePieceCardManagement.Configuration;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
var configuration = builder.Configuration;

builder.Services.AddControllers();

// Add AutoMapper - ADDED
builder.Services.AddAutoMapper(typeof(AuthenticationProfile),
                               typeof(CommonProfile),
                               typeof(TattoosProfile));

// Swagger/OpenAPI configuration
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo
    {
        Title = "One Piece Card Management API",
        Version = "v1",
        Description = "API for managing One Piece card collections with authentication"
    });

    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        In = ParameterLocation.Header,
        Description = "Please enter a valid JWT token",
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        BearerFormat = "JWT",
        Scheme = "Bearer"
    });

    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            new string[]{}
        }
    });
});

// Load MinIO configuration
builder.Services.Configure<MinioConfiguration>(
    builder.Configuration.GetSection("MinIO"));

// Register MinIO client
builder.Services.AddSingleton<IMinioClient>(serviceProvider =>
{
    var config = serviceProvider.GetRequiredService<IOptions<MinioConfiguration>>().Value;

    return new MinioClient()
        .WithEndpoint(config.Endpoint)
        .WithCredentials(config.AccessKey, config.SecretKey)
        .WithSSL(config.UseSSL)
        .Build();
});

// Register MinIO service
builder.Services.AddScoped<IMinioService, MinioService>();

// Database configuration
builder.Services.AddDbContext<DataContext>(options =>
    options.UseNpgsql(builder.Configuration.GetConnectionString("DefaultConnection")));

// Identity configuration
builder.Services.AddIdentity<IdentityUser, IdentityRole>(options =>
{
    // Password requirements
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequiredLength = 8;

    // User settings
    options.User.RequireUniqueEmail = true;
    options.SignIn.RequireConfirmedEmail = true;

    // Lockout settings
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;
})
.AddEntityFrameworkStores<DataContext>()
.AddDefaultTokenProviders();

// Token lifespan configuration
builder.Services.Configure<DataProtectionTokenProviderOptions>(opts =>
    opts.TokenLifespan = TimeSpan.FromHours(24)); // Email confirmation token validity

// JWT Authentication
var jwtSecret = builder.Configuration["JWT:Secret"];
if (string.IsNullOrEmpty(jwtSecret))
{
    throw new InvalidOperationException("JWT Secret is not configured. Please add JWT:Secret to your configuration.");
}

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.SaveToken = true;
    options.RequireHttpsMetadata = !builder.Environment.IsDevelopment(); // HTTPS solo in produzione
    options.TokenValidationParameters = new TokenValidationParameters()
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ClockSkew = TimeSpan.Zero, // Rimuove il buffer di 5 minuti di default
        ValidAudience = configuration["JWT:ValidAudience"],
        ValidIssuer = configuration["JWT:ValidIssuer"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret))
    };

    // Events per logging
    options.Events = new JwtBearerEvents
    {
        OnAuthenticationFailed = context =>
        {
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
            logger.LogWarning("JWT Authentication failed: {Exception}", context.Exception.Message);
            return Task.CompletedTask;
        },
        OnTokenValidated = context =>
        {
            var logger = context.HttpContext.RequestServices.GetRequiredService<ILogger<Program>>();
            logger.LogDebug("JWT Token validated successfully for user: {User}",
                context.Principal?.Identity?.Name);
            return Task.CompletedTask;
        }
    };
});

// Email configuration
var emailConfig = configuration.GetSection("EmailConfiguration").Get<EmailConfiguration>();
if (emailConfig == null)
{
    throw new InvalidOperationException("Email configuration is missing");
}
builder.Services.AddSingleton(emailConfig);



builder.Services.AddService();
builder.Services.AddRepository();
builder.Services.AddValidator();



// CORS (se necessario per frontend)
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAllOrigins", policy =>
    {
        policy.AllowAnyOrigin()
              .AllowAnyMethod()
              .AllowAnyHeader();
              //.AllowCredentials();
    });
});

// Rate limiting per sicurezza
builder.Services.AddRateLimiter(options =>
{
    options.AddFixedWindowLimiter("AuthPolicy", opt =>
    {
        opt.PermitLimit = 5;
        opt.Window = TimeSpan.FromMinutes(1);
        opt.QueueProcessingOrder = System.Threading.RateLimiting.QueueProcessingOrder.OldestFirst;
        opt.QueueLimit = 2;
    });
});

// Background service per la pulizia dei token scaduti
builder.Services.AddHostedService<TokenCleanupService>();

// Logging configuration
builder.Logging.ClearProviders();
builder.Logging.AddConsole();
builder.Logging.AddDebug();

if (builder.Environment.IsDevelopment())
{
    builder.Logging.SetMinimumLevel(LogLevel.Debug);
}
else
{
    builder.Logging.SetMinimumLevel(LogLevel.Information);
}

var app = builder.Build();

// Configure the HTTP request pipeline.

// Middleware di gestione delle eccezioni DEVE essere il primo
app.UseGlobalExceptionMiddleware();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "One Piece Card Management API V1");
        c.RoutePrefix = string.Empty; // Swagger UI at root
    });
}
else
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "One Piece Card Management API V1");
        c.RoutePrefix = string.Empty; // Swagger UI at root
    });

    // In produzione, usa il middleware personalizzato invece di UseExceptionHandler
    app.UseHsts();
}

app.UseHttpsRedirection();

// Security headers
app.Use(async (context, next) =>
{
    context.Response.Headers.Append("X-Content-Type-Options", "nosniff");
    context.Response.Headers.Append("X-Frame-Options", "DENY");
    context.Response.Headers.Append("X-XSS-Protection", "1; mode=block");
    context.Response.Headers.Append("Referrer-Policy", "strict-origin-when-cross-origin");
    await next();
});

app.UseCors("AllowAllOrigins");
app.UseRateLimiter();

app.UseAuthentication();
app.UseAuthorization();

// Apply rate limiting to auth endpoints
app.MapControllers().RequireRateLimiting("AuthPolicy");

// Health check endpoint
app.MapGet("/health", () => Results.Ok(new { Status = "Healthy", Timestamp = DateTime.UtcNow }))
   .WithName("HealthCheck")
   .WithOpenApi();

// Seed roles on startup
using (var scope = app.Services.CreateScope())
{
    var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole>>();
    var logger = scope.ServiceProvider.GetRequiredService<ILogger<Program>>();

    try
    {
        var roles = new[] { "Admin", "User", "Moderator" };

        foreach (var role in roles)
        {
            if (!await roleManager.RoleExistsAsync(role))
            {
                await roleManager.CreateAsync(new IdentityRole(role));
                logger.LogInformation("Created role: {Role}", role);
            }
        }
    }
    catch (Exception ex)
    {
        logger.LogError(ex, "Error occurred while seeding roles");
    }
}

app.Run();