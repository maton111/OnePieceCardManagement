using FluentValidation;
using OnePieceCardManagement.DTOs.Authentication.Request;

namespace OnePieceCardManagement.Validators
{
    public class RegisterUserValidator : AbstractValidator<RegisterUserDto>
    {
        public RegisterUserValidator()
        {
            RuleFor(x => x.Email)
                .NotEmpty().WithMessage("The email is required.")
                .EmailAddress().WithMessage("The email is wrong.");

            RuleFor(x => x.Username)
                .NotEmpty().WithMessage("The username is required.");
        }
    }
}
