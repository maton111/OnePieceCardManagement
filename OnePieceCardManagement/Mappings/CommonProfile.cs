using AutoMapper;
using OnePieceCardManagement.DTOs.Common;
using OnePieceCardManagement.Utils;

namespace OnePieceCardManagement.Mappings
{
    public class CommonProfile : Profile
    {
        public CommonProfile()
        {
            // Generic ApiResponse mapping
            CreateMap(typeof(ApiResponse<>), typeof(ApiResponseDto<>)).ReverseMap();
        }
    }
}