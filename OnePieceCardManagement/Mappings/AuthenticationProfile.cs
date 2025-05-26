using AutoMapper;
using OnePieceCardManagement.DTOs.Authentication.Request;
using OnePieceCardManagement.DTOs.Authentication.Response;
using OnePieceCardManagement.DTOs.Email;
using OnePieceCardManagement.DTOs;
using OnePieceCardManagement.Models;
using OnePieceCardManagement.Controllers;
using OnePieceCardManagement.Models.Authentication;
using OnePieceCardManagement.Models.Email;

namespace OnePieceCardManagement.Mappings
{
    public class AuthenticationProfile : Profile
    {
        public AuthenticationProfile()
        {
            // Request DTOs to Models
            CreateMap<RegisterUserDto, RegisterUser>().ReverseMap();
            CreateMap<LoginDto, LoginModel>().ReverseMap();
            CreateMap<OnePieceCardManagement.DTOs.Authentication.Request.RefreshTokenModelDto, RefreshTokenModel>().ReverseMap();
            CreateMap<ResetPasswordDto, ResetPassword>().ReverseMap();

            // Models to Response DTOs
            CreateMap<ResetPassword, ResetPasswordResponseDto>().ReverseMap();

            // RefreshToken entity mappings
            CreateMap<RefreshToken, OnePieceCardManagement.DTOs.RefreshTokenDto>()
                .ForMember(dest => dest.IsRevoked, opt => opt.MapFrom(src => src.IsRevoked))
                .ForMember(dest => dest.IsExpired, opt => opt.MapFrom(src => src.IsExpired))
                .ForMember(dest => dest.IsActive, opt => opt.MapFrom(src => src.IsActive));

            CreateMap<OnePieceCardManagement.DTOs.RefreshTokenDto, RefreshToken>()
                .ForMember(dest => dest.User, opt => opt.Ignore())
                .ForMember(dest => dest.IsRevoked, opt => opt.Ignore())
                .ForMember(dest => dest.IsExpired, opt => opt.Ignore())
                .ForMember(dest => dest.IsActive, opt => opt.Ignore());

            // Message mappings
            CreateMap<MessageDto, Message>()
                .ConstructUsing(src => new Message(src.To, src.Subject, src.Content));

            CreateMap<Message, MessageDto>()
                .ForMember(dest => dest.To, opt => opt.MapFrom(src => src.To.Select(x => x.Address)));
        }
    }
}
