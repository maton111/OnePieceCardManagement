using FluentValidation;
using OnePieceCardManagement.DTOs.Authentication.Request;
using OnePieceCardManagement.Services;
using OnePieceCardManagement.Validators;

namespace OnePieceCardManagement.Standards
{
    public static partial class ServiceCollectionExtensions
    {
        public static IServiceCollection AddService(this IServiceCollection services)
        {
            services.AddScoped<ITattoosService, TattoosService>();

            return services;
        }
        
        public static IServiceCollection AddRepository(this IServiceCollection services)
        {
            //services.AddScoped<IBaseRepository<Cards>, BaseRepository<Cards, pocketassistantContext>>();

            return services;
        }
        public static IServiceCollection AddValidator(this IServiceCollection services)
        {
            services.AddScoped<IValidator<RegisterUserDto>, RegisterUserValidator>();

            return services;
        }
    }
}
