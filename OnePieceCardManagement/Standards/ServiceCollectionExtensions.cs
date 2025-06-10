using FluentValidation;
using OnePieceCardManagement.Data;
using OnePieceCardManagement.DTOs.Authentication.Request;
using OnePieceCardManagement.DTOs.Tattoos;
using OnePieceCardManagement.Models;
using OnePieceCardManagement.Repository;
using OnePieceCardManagement.Services;
using OnePieceCardManagement.Validators;

namespace OnePieceCardManagement.Standards
{
    public static partial class ServiceCollectionExtensions
    {
        public static IServiceCollection AddService(this IServiceCollection services)
        {
            services.AddScoped<IAuthenticationService, AuthenticationService>();
            services.AddScoped<ITattoosService, TattoosService>();

            return services;
        }
        
        public static IServiceCollection AddRepository(this IServiceCollection services)
        {
            services.AddScoped<IRepository<Tattoos>, Repository<Tattoos, DataContext>>();
            services.AddScoped<IRepository<TattooStyles>, Repository<TattooStyles, DataContext>>();
            services.AddScoped<IRepository<TattooPositions>, Repository<TattooPositions, DataContext>>();


            return services;
        }
        public static IServiceCollection AddValidator(this IServiceCollection services)
        {
            services.AddScoped<IValidator<RegisterUserDto>, RegisterUserValidator>();
            services.AddScoped<IValidator<CreateTattooDto>, CreateTattooValidator>();
            services.AddScoped<IValidator<UpdateTattooDto>, UpdateTattooValidator>();

            return services;
        }
    }
}
