using OnePieceCardManagement.Utils;
using System.Net;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using System.Security.Authentication;

namespace OnePieceCardManagement.Middleware
{
    public class GlobalExceptionMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly ILogger<GlobalExceptionMiddleware> _logger;
        private readonly IWebHostEnvironment _environment;

        public GlobalExceptionMiddleware(RequestDelegate next, ILogger<GlobalExceptionMiddleware> logger, IWebHostEnvironment environment)
        {
            _next = next;
            _logger = logger;
            _environment = environment;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            try
            {
                await _next(context);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "An unhandled exception occurred. RequestPath: {RequestPath}, Method: {Method}",
                    context.Request.Path, context.Request.Method);
                await HandleExceptionAsync(context, ex);
            }
        }

        private async Task HandleExceptionAsync(HttpContext context, Exception exception)
        {
            context.Response.ContentType = "application/json";

            var response = new ApiResponse<object>
            {
                IsSuccess = false,
                StatusCode = (int)HttpStatusCode.InternalServerError,
                Message = "An error occurred while processing your request"
            };

            switch (exception)
            {
                case ArgumentException argEx:
                    response.StatusCode = (int)HttpStatusCode.BadRequest;
                    response.Message = "Invalid argument provided";
                    if (_environment.IsDevelopment())
                        response.Response = new { Details = argEx.Message };
                    break;

                case UnauthorizedAccessException:
                    response.StatusCode = (int)HttpStatusCode.Unauthorized;
                    response.Message = "Unauthorized access";
                    break;

                case AuthenticationException:
                    response.StatusCode = (int)HttpStatusCode.Unauthorized;
                    response.Message = "Authentication failed";
                    break;

                case KeyNotFoundException:
                    response.StatusCode = (int)HttpStatusCode.NotFound;
                    response.Message = "Resource not found";
                    break;

                case InvalidOperationException invOpEx:
                    response.StatusCode = (int)HttpStatusCode.BadRequest;
                    response.Message = "Invalid operation";
                    if (_environment.IsDevelopment())
                        response.Response = new { Details = invOpEx.Message };
                    break;

                case DbUpdateException dbEx:
                    response.StatusCode = (int)HttpStatusCode.Conflict;
                    response.Message = "Database operation failed";
                    _logger.LogError(dbEx, "Database update exception occurred");
                    if (_environment.IsDevelopment())
                        response.Response = new { Details = dbEx.InnerException?.Message ?? dbEx.Message };
                    break;

                case TimeoutException:
                    response.StatusCode = (int)HttpStatusCode.RequestTimeout;
                    response.Message = "The request timed out";
                    break;

                case NotImplementedException:
                    response.StatusCode = (int)HttpStatusCode.NotImplemented;
                    response.Message = "Feature not implemented";
                    break;

                case HttpRequestException httpEx:
                    response.StatusCode = (int)HttpStatusCode.BadGateway;
                    response.Message = "External service error";
                    _logger.LogError(httpEx, "HTTP request exception occurred");
                    break;

                default:
                    // Log detailed error information for debugging
                    response.Message = "An internal server error occurred";
                    _logger.LogError(exception, "Unhandled exception occurred");

                    // In development, include more details
                    if (_environment.IsDevelopment())
                    {
                        response.Response = new
                        {
                            Details = exception.Message,
                            StackTrace = exception.StackTrace?.Split('\n').Take(10).ToArray()
                        };
                    }
                    break;
            }

            context.Response.StatusCode = response.StatusCode;

            var jsonResponse = JsonSerializer.Serialize(response, new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                WriteIndented = _environment.IsDevelopment()
            });

            await context.Response.WriteAsync(jsonResponse);
        }
    }

    // Extension method per registrare il middleware
    public static class GlobalExceptionMiddlewareExtensions
    {
        public static IApplicationBuilder UseGlobalExceptionMiddleware(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<GlobalExceptionMiddleware>();
        }
    }
}