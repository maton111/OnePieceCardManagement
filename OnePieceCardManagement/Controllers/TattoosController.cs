using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OnePieceCardManagement.DTOs.Authentication.Request;
using OnePieceCardManagement.DTOs.Common;
using OnePieceCardManagement.DTOs.Email;
using System.Security.Claims;
using System;
using OnePieceCardManagement.Services;
using OnePieceCardManagement.DTOs.Tattoos;
using System.Linq;
using OnePieceCardManagement.Utils;

namespace OnePieceCardManagement.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class TattoosController : ControllerBase
    {
        private readonly ITattoosService _tattooService;
        private readonly ILogger<TattoosController> _logger;

        public TattoosController(
            ITattoosService tattooService,
            ILogger<TattoosController> logger)
        {
            _tattooService = tattooService;
            _logger = logger;
        }

        [HttpGet]
        public async Task<IActionResult> GetAllTattoos([FromQuery] TattooFilterDto filterDto)
        {
            _logger.LogInformation("Getting all tattoos with filters: {@Filters}", filterDto);
            var result = await _tattooService.GetAllTattoosAsync(filterDto);
            return StatusCode(result.StatusCode, result);
        }

        [HttpGet("{id}")]
        public async Task<IActionResult> GetTattoo(int id)
        {
            if (id <= 0)
            {
                return BadRequest(new ApiResponseDto<object>
                {
                    IsSuccess = false,
                    Message = "Invalid tattoo ID",
                    StatusCode = 400
                });
            }

            _logger.LogInformation("Getting tattoo with ID: {Id}", id);
            var result = await _tattooService.GetTattooByIdAsync(id);
            return StatusCode(result.StatusCode, result);
        }

        [HttpPost]
        public async Task<IActionResult> CreateTattoo([FromBody] CreateTattooDto createTattooDto)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(new ApiResponseDto<object>
                {
                    IsSuccess = false,
                    Message = "Invalid input data",
                    StatusCode = 400,
                    Response = ModelState
                });
            }

            _logger.LogInformation("Creating new tattoo: {Name}", createTattooDto.Name);
            var result = await _tattooService.CreateTattooAsync(createTattooDto);

            if (result.IsSuccess && result.Response != null)
            {
                return CreatedAtAction(
                    nameof(GetTattoo),
                    new { id = result.Response.Id },
                    result
                );
            }

            return StatusCode(result.StatusCode, result);
        }

        [HttpPut("{id}")]
        public async Task<IActionResult> UpdateTattoo(int id, [FromBody] UpdateTattooDto updateTattooDto)
        {
            if (id != updateTattooDto.Id)
            {
                return BadRequest(new ApiResponseDto<object>
                {
                    IsSuccess = false,
                    Message = "ID mismatch",
                    StatusCode = 400
                });
            }

            if (!ModelState.IsValid)
            {
                return BadRequest(new ApiResponseDto<object>
                {
                    IsSuccess = false,
                    Message = "Invalid input data",
                    StatusCode = 400,
                    Response = ModelState
                });
            }

            _logger.LogInformation("Updating tattoo with ID: {Id}", id);
            var result = await _tattooService.UpdateTattooAsync(updateTattooDto);
            return StatusCode(result.StatusCode, result);
        }

        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteTattoo(int id)
        {
            if (id <= 0)
            {
                return BadRequest(new ApiResponseDto<object>
                {
                    IsSuccess = false,
                    Message = "Invalid tattoo ID",
                    StatusCode = 400
                });
            }

            _logger.LogInformation("Deleting tattoo with ID: {Id}", id);
            var result = await _tattooService.DeleteTattooAsync(id);

            if (!result.IsSuccess)
            {
                return NoContent();
            }

            return StatusCode(result.StatusCode, result);
        }

        [HttpPost("{id}/image")]
        public async Task<IActionResult> UploadImage(int id, IFormFile image)
        {
            if (id <= 0)
            {
                return BadRequest(new ApiResponseDto<object>
                {
                    IsSuccess = false,
                    Message = "Invalid tattoo ID",
                    StatusCode = 400
                });
            }

            if (image == null || image.Length == 0)
            {
                return BadRequest(new ApiResponseDto<object>
                {
                    IsSuccess = false,
                    Message = "No image file provided",
                    StatusCode = 400
                });
            }

            // Validate file type
            var allowedImage = "image";
            var jpeg = ".jpeg";
            var jpg = ".jpg";
            var png = ".png";
            var webp = ".webp";
            if (!image.ContentDisposition.ToLower().Contains(allowedImage)
            && (!image.ContentDisposition.ToLower().Contains(jpeg)
             || !image.ContentDisposition.ToLower().Contains(jpg)
             || !image.ContentDisposition.ToLower().Contains(png)
             || !image.ContentDisposition.ToLower().Contains(webp)))
            {
                return BadRequest(new ApiResponseDto<object>
                {
                    IsSuccess = false,
                    Message = "Invalid file type. Only JPEG, PNG, and WebP are allowed",
                    StatusCode = 400
                });
            }

            // Validate file size (e.g., 5MB max)
            const int maxFileSize = 5 * 1024 * 1024; // 5MB
            if (image.Length > maxFileSize)
            {
                return BadRequest(new ApiResponseDto<object>
                {
                    IsSuccess = false,
                    Message = "File size exceeds 5MB limit",
                    StatusCode = 400
                });
            }

            _logger.LogInformation("Uploading image for tattoo ID: {Id}, File: {FileName}",
                id, image.FileName);

            var result = await _tattooService.UploadTattooImageAsync(id, image);
            return StatusCode(result.StatusCode, result);
        }

        [HttpGet("styles")]
        public async Task<IActionResult> GetStyles()
        {
            _logger.LogInformation("Getting all tattoo styles");
            var result = await _tattooService.GetStylesAsync();
            return StatusCode(result.StatusCode, result);
        }

        [HttpGet("positions")]
        public async Task<IActionResult> GetPositions()
        {
            _logger.LogInformation("Getting all tattoo positions");
            var result = await _tattooService.GetPositionsAsync();
            return StatusCode(result.StatusCode, result);
        }
    }
}
