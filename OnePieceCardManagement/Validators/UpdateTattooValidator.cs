using FluentValidation;
using OnePieceCardManagement.DTOs.Tattoos;

namespace OnePieceCardManagement.Validators
{
    public class UpdateTattooValidator : AbstractValidator<UpdateTattooDto>
    {
        public UpdateTattooValidator()
        {
            RuleFor(x => x.Id)
                .GreaterThan(0).WithMessage("Invalid tattoo ID");

            RuleFor(x => x.Name)
                .NotEmpty().WithMessage("Name is required")
                .MaximumLength(255).WithMessage("Name must not exceed 255 characters");

            RuleFor(x => x.Position)
                .NotEmpty().WithMessage("Position is required")
                .MaximumLength(100).WithMessage("Position must not exceed 100 characters");

            RuleFor(x => x.Style)
                .NotEmpty().WithMessage("Style is required")
                .MaximumLength(100).WithMessage("Style must not exceed 100 characters");

            RuleFor(x => x.AveragePrice)
                .GreaterThan(0).WithMessage("Average price must be greater than 0")
                .LessThanOrEqualTo(999999.99m).WithMessage("Average price is too high");

            RuleFor(x => x.Rating)
                .InclusiveBetween(1, 5).WithMessage("Rating must be between 1 and 5");

            RuleFor(x => x.ImageUrl)
                .MaximumLength(500).WithMessage("Image URL must not exceed 500 characters")
                .Must(BeAValidUrl).When(x => !string.IsNullOrWhiteSpace(x.ImageUrl))
                .WithMessage("Image URL must be a valid URL");
        }

        private bool BeAValidUrl(string? url)
        {
            if (string.IsNullOrWhiteSpace(url))
                return true;

            return Uri.TryCreate(url, UriKind.Absolute, out var result) &&
                   (result.Scheme == Uri.UriSchemeHttp || result.Scheme == Uri.UriSchemeHttps);
        }
    }
}
