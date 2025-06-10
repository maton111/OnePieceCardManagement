using OnePieceCardManagement.Data;
using OnePieceCardManagement.DTOs.Authentication.Request;
using AutoMapper;
using Microsoft.AspNetCore.Identity;
using OnePieceCardManagement.Models.Email;
using FluentValidation;
using OnePieceCardManagement.DTOs.Common;
using OnePieceCardManagement.DTOs.Tattoos;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using OnePieceCardManagement.Models;
using OnePieceCardManagement.Repository;
using System.Linq.Expressions;

namespace OnePieceCardManagement.Services
{
    public interface ITattoosService
    {
        Task<ApiResponseDto<List<TattooDto>>> GetAllTattoosAsync(TattooFilterDto filterDto);
        Task<ApiResponseDto<TattooDto>> GetTattooByIdAsync(int id);
        Task<ApiResponseDto<TattooDto>> CreateTattooAsync(CreateTattooDto createTattooDto);
        Task<ApiResponseDto<TattooDto>> UpdateTattooAsync(UpdateTattooDto updateTattooDto);
        Task<ApiResponseDto<object>> DeleteTattooAsync(int id);
        Task<ApiResponseDto<ImageUploadResponseDto>> UploadTattooImageAsync(int tattooId, IFormFile image);
        Task<ApiResponseDto<List<string>>> GetStylesAsync();
        Task<ApiResponseDto<List<string>>> GetPositionsAsync();
    }

    public class TattoosService : ITattoosService
    {
        private readonly IRepository<Tattoos> _tattooRepository;
        private readonly IRepository<TattooStyles> _styleRepository;
        private readonly IRepository<TattooPositions> _positionRepository;
        private readonly ILogger<TattoosService> _logger;
        private readonly IMapper _mapper;
        private readonly IValidator<CreateTattooDto> _createTattooValidator;
        private readonly IValidator<UpdateTattooDto> _updateTattooValidator;
        private readonly IMinioService _minioService; // You'll need to implement this for MinIO integration
        private readonly DataContext _context;

        public TattoosService(
            IRepository<Tattoos> tattooRepository,
            IRepository<TattooStyles> styleRepository,
            IRepository<TattooPositions> positionRepository,
            ILogger<TattoosService> logger,
            IMapper mapper,
            IValidator<CreateTattooDto> createTattooValidator,
            IValidator<UpdateTattooDto> updateTattooValidator,
            IMinioService minioService,
            DataContext context)
        {
            _tattooRepository = tattooRepository;
            _styleRepository = styleRepository;
            _positionRepository = positionRepository;
            _logger = logger;
            _mapper = mapper;
            _createTattooValidator = createTattooValidator;
            _updateTattooValidator = updateTattooValidator;
            _minioService = minioService;
            _context = context;
        }

        public async Task<ApiResponseDto<List<TattooDto>>> GetAllTattoosAsync(TattooFilterDto filterDto)
        {
            try
            {
                _logger.LogInformation("Fetching tattoos with filters: {@Filters}", filterDto);

                // Build filter expression
                Expression<Func<Tattoos, bool>> filter = t => true;

                if (!string.IsNullOrWhiteSpace(filterDto.Style))
                {
                    filter = CombineFilters(filter, t => t.Style == filterDto.Style);
                }

                if (!string.IsNullOrWhiteSpace(filterDto.Position))
                {
                    filter = CombineFilters(filter, t => t.Position == filterDto.Position);
                }

                if (filterDto.MinPrice.HasValue)
                {
                    filter = CombineFilters(filter, t => t.AveragePrice >= filterDto.MinPrice.Value);
                }

                if (filterDto.MaxPrice.HasValue)
                {
                    filter = CombineFilters(filter, t => t.AveragePrice <= filterDto.MaxPrice.Value);
                }

                if (filterDto.Rating.HasValue)
                {
                    filter = CombineFilters(filter, t => t.Rating >= filterDto.Rating.Value);
                }

                // Build ordering
                Func<IQueryable<Tattoos>, IOrderedQueryable<Tattoos>>? orderBy = null;
                if (!string.IsNullOrWhiteSpace(filterDto.Sort))
                {
                    var isDescending = filterDto.Order?.ToLower() == "desc";
                    orderBy = filterDto.Sort.ToLower() switch
                    {
                        "name" => q => isDescending ? q.OrderByDescending(t => t.Name) : q.OrderBy(t => t.Name),
                        "price" => q => isDescending ? q.OrderByDescending(t => t.AveragePrice) : q.OrderBy(t => t.AveragePrice),
                        "rating" => q => isDescending ? q.OrderByDescending(t => t.Rating) : q.OrderBy(t => t.Rating),
                        "date" => q => isDescending ? q.OrderByDescending(t => t.CreatedAt) : q.OrderBy(t => t.CreatedAt),
                        _ => q => q.OrderByDescending(t => t.CreatedAt)
                    };
                }
                else
                {
                    orderBy = q => q.OrderByDescending(t => t.CreatedAt);
                }

                var tattoos = await _tattooRepository.Find(filter, orderBy);
                var tattooDtos = _mapper.Map<List<TattooDto>>(tattoos);

                _logger.LogInformation("Found {Count} tattoos", tattooDtos.Count);

                return new ApiResponseDto<List<TattooDto>>
                {
                    IsSuccess = true,
                    Message = $"Found {tattooDtos.Count} tattoos",
                    StatusCode = 200,
                    Response = tattooDtos
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error fetching tattoos");
                return new ApiResponseDto<List<TattooDto>>
                {
                    IsSuccess = false,
                    Message = "An error occurred while fetching tattoos",
                    StatusCode = 500
                };
            }
        }

        public async Task<ApiResponseDto<TattooDto>> GetTattooByIdAsync(int id)
        {
            try
            {
                var tattoo = await _tattooRepository.Get(id);
                if (tattoo == null)
                {
                    _logger.LogWarning("Tattoo not found with ID: {Id}", id);
                    return new ApiResponseDto<TattooDto>
                    {
                        IsSuccess = false,
                        Message = "Tattoo not found",
                        StatusCode = 404
                    };
                }

                var tattooDto = _mapper.Map<TattooDto>(tattoo);
                _logger.LogInformation("Retrieved tattoo with ID: {Id}", id);

                return new ApiResponseDto<TattooDto>
                {
                    IsSuccess = true,
                    Message = "Tattoo retrieved successfully",
                    StatusCode = 200,
                    Response = tattooDto
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error fetching tattoo with ID: {Id}", id);
                return new ApiResponseDto<TattooDto>
                {
                    IsSuccess = false,
                    Message = "An error occurred while fetching the tattoo",
                    StatusCode = 500
                };
            }
        }

        public async Task<ApiResponseDto<TattooDto>> CreateTattooAsync(CreateTattooDto createTattooDto)
        {
            try
            {
                // Validate
                var validationResult = await _createTattooValidator.ValidateAsync(createTattooDto);
                if (!validationResult.IsValid)
                {
                    return new ApiResponseDto<TattooDto>
                    {
                        IsSuccess = false,
                        Message = "Validation failed",
                        StatusCode = 400,
                        Errors = validationResult.Errors
                    };
                }

                var tattoo = _mapper.Map<Tattoos>(createTattooDto);
                tattoo.CreatedAt = DateTime.UtcNow;
                tattoo.UpdatedAt = DateTime.UtcNow;

                var createdTattoo = await _tattooRepository.Insert(tattoo);
                var tattooDto = _mapper.Map<TattooDto>(createdTattoo);

                _logger.LogInformation("Created new tattoo with ID: {Id}", createdTattoo.Id);

                return new ApiResponseDto<TattooDto>
                {
                    IsSuccess = true,
                    Message = "Tattoo created successfully",
                    StatusCode = 201,
                    Response = tattooDto
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error creating tattoo");
                return new ApiResponseDto<TattooDto>
                {
                    IsSuccess = false,
                    Message = "An error occurred while creating the tattoo",
                    StatusCode = 500
                };
            }
        }

        public async Task<ApiResponseDto<TattooDto>> UpdateTattooAsync(UpdateTattooDto updateTattooDto)
        {
            try
            {
                // Validate
                var validationResult = await _updateTattooValidator.ValidateAsync(updateTattooDto);
                if (!validationResult.IsValid)
                {
                    return new ApiResponseDto<TattooDto>
                    {
                        IsSuccess = false,
                        Message = "Validation failed",
                        StatusCode = 400,
                        Errors = validationResult.Errors
                    };
                }

                var existingTattoo = await _tattooRepository.Get(updateTattooDto.Id);
                if (existingTattoo == null)
                {
                    _logger.LogWarning("Tattoo not found for update with ID: {Id}", updateTattooDto.Id);
                    return new ApiResponseDto<TattooDto>
                    {
                        IsSuccess = false,
                        Message = "Tattoo not found",
                        StatusCode = 404
                    };
                }

                // Map updates but preserve certain fields
                _mapper.Map(updateTattooDto, existingTattoo);
                existingTattoo.UpdatedAt = DateTime.UtcNow;

                var updatedTattoo = await _tattooRepository.Update(existingTattoo);
                var tattooDto = _mapper.Map<TattooDto>(updatedTattoo);

                _logger.LogInformation("Updated tattoo with ID: {Id}", updateTattooDto.Id);

                return new ApiResponseDto<TattooDto>
                {
                    IsSuccess = true,
                    Message = "Tattoo updated successfully",
                    StatusCode = 200,
                    Response = tattooDto
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error updating tattoo with ID: {Id}", updateTattooDto.Id);
                return new ApiResponseDto<TattooDto>
                {
                    IsSuccess = false,
                    Message = "An error occurred while updating the tattoo",
                    StatusCode = 500
                };
            }
        }

        public async Task<ApiResponseDto<object>> DeleteTattooAsync(int id)
        {
            try
            {
                var tattoo = await _tattooRepository.Get(id);
                if (tattoo == null)
                {
                    _logger.LogWarning("Tattoo not found for deletion with ID: {Id}", id);
                    return new ApiResponseDto<object>
                    {
                        IsSuccess = false,
                        Message = "Tattoo not found",
                        StatusCode = 404
                    };
                }

                // Delete image from MinIO if exists
                if (!string.IsNullOrWhiteSpace(tattoo.ImageUrl))
                {
                    try
                    {
                        await _minioService.DeleteFileAsync(tattoo.ImageUrl);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Failed to delete image from MinIO for tattoo ID: {Id}", id);
                    }
                }

                await _tattooRepository.Delete(id);
                _logger.LogInformation("Deleted tattoo with ID: {Id}", id);

                return new ApiResponseDto<object>
                {
                    IsSuccess = true,
                    Message = "Tattoo deleted successfully",
                    StatusCode = 204
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting tattoo with ID: {Id}", id);
                return new ApiResponseDto<object>
                {
                    IsSuccess = false,
                    Message = "An error occurred while deleting the tattoo",
                    StatusCode = 500
                };
            }
        }

        public async Task<ApiResponseDto<ImageUploadResponseDto>> UploadTattooImageAsync(int tattooId, IFormFile image)
        {
            try
            {
                var tattoo = await _tattooRepository.Get(tattooId);
                if (tattoo == null)
                {
                    _logger.LogWarning("Tattoo not found for image upload with ID: {Id}", tattooId);
                    return new ApiResponseDto<ImageUploadResponseDto>
                    {
                        IsSuccess = false,
                        Message = "Tattoo not found",
                        StatusCode = 404
                    };
                }

                // Delete old image if exists
                if (!string.IsNullOrWhiteSpace(tattoo.ImageUrl))
                {
                    try
                    {
                        await _minioService.DeleteFileAsync(tattoo.ImageUrl);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Failed to delete old image from MinIO");
                    }
                }

                // Upload new image
                var fileName = $"tattoo-{tattooId}-{Guid.NewGuid()}{Path.GetExtension(image.FileName)}";
                var imageUrl = await _minioService.UploadFileAsync(image, fileName, "tattoos");

                // Update tattoo with new image URL
                tattoo.ImageUrl = imageUrl;
                tattoo.UpdatedAt = DateTime.UtcNow;
                await _tattooRepository.Update(tattoo);

                _logger.LogInformation("Uploaded image for tattoo ID: {Id}, URL: {Url}", tattooId, imageUrl);

                return new ApiResponseDto<ImageUploadResponseDto>
                {
                    IsSuccess = true,
                    Message = "Image uploaded successfully",
                    StatusCode = 200,
                    Response = new ImageUploadResponseDto { ImageUrl = imageUrl }
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error uploading image for tattoo ID: {Id}", tattooId);
                return new ApiResponseDto<ImageUploadResponseDto>
                {
                    IsSuccess = false,
                    Message = "An error occurred while uploading the image",
                    StatusCode = 500
                };
            }
        }

        public async Task<ApiResponseDto<List<string>>> GetStylesAsync()
        {
            try
            {
                var styles = _styleRepository.GetAll().Result
                                             .Select(t => t.Name)
                                             .ToList();

                _logger.LogInformation("Retrieved {Count} unique styles", styles.Count);

                return new ApiResponseDto<List<string>>
                {
                    IsSuccess = true,
                    Message = $"Retrieved {styles.Count} styles",
                    StatusCode = 200,
                    Response = styles
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error fetching styles");
                return new ApiResponseDto<List<string>>
                {
                    IsSuccess = false,
                    Message = "An error occurred while fetching styles",
                    StatusCode = 500
                };
            }
        }

        public async Task<ApiResponseDto<List<string>>> GetPositionsAsync()
        {
            try
            {
                var positions = _positionRepository.GetAll().Result
                                                   .Select(t => t.Name)
                                                   .ToList();

                _logger.LogInformation("Retrieved {Count} unique positions", positions.Count);

                return new ApiResponseDto<List<string>>
                {
                    IsSuccess = true,
                    Message = $"Retrieved {positions.Count} positions",
                    StatusCode = 200,
                    Response = positions
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error fetching positions");
                return new ApiResponseDto<List<string>>
                {
                    IsSuccess = false,
                    Message = "An error occurred while fetching positions",
                    StatusCode = 500
                };
            }
        }

        // Helper method to combine filter expressions
        private Expression<Func<T, bool>> CombineFilters<T>(
            Expression<Func<T, bool>> filter1,
            Expression<Func<T, bool>> filter2)
        {
            var parameter = Expression.Parameter(typeof(T));
            var leftVisitor = new ReplaceExpressionVisitor(filter1.Parameters[0], parameter);
            var left = leftVisitor.Visit(filter1.Body);
            var rightVisitor = new ReplaceExpressionVisitor(filter2.Parameters[0], parameter);
            var right = rightVisitor.Visit(filter2.Body);
            return Expression.Lambda<Func<T, bool>>(Expression.AndAlso(left, right), parameter);
        }

        private class ReplaceExpressionVisitor : ExpressionVisitor
        {
            private readonly Expression _oldValue;
            private readonly Expression _newValue;

            public ReplaceExpressionVisitor(Expression oldValue, Expression newValue)
            {
                _oldValue = oldValue;
                _newValue = newValue;
            }

            public override Expression Visit(Expression node)
            {
                return node == _oldValue ? _newValue : base.Visit(node);
            }
        }
    }
}
