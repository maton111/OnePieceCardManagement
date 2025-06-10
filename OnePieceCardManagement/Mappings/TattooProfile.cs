using AutoMapper;
using OnePieceCardManagement.DTOs.Tattoos;
using OnePieceCardManagement.Models;

namespace OnePieceCardManagement.Mappings
{
    public class TattoosProfile : Profile
    {
        public TattoosProfile()
        {
            // Request DTOs to Models
            CreateMap<CreateTattooDto, Tattoos>();
            CreateMap<UpdateTattooDto, Tattoos>()
                .ForMember(dest => dest.CreatedAt, opt => opt.Ignore())
                .ForMember(dest => dest.UpdatedAt, opt => opt.Ignore());

            // Models to Response DTOs
            CreateMap<Tattoos, TattooDto>();
        }
    }
}
