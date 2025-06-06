using MimeKit;
using MailKit.Net.Smtp;
using OnePieceCardManagement.Models;
using OnePieceCardManagement.Data;
using Microsoft.EntityFrameworkCore;
using OnePieceCardManagement.DTOs.Authentication.Request;
using OnePieceCardManagement.DTOs.Authentication.Response;
using OnePieceCardManagement.DTOs.Common;
using OnePieceCardManagement.DTOs.Email;
using AutoMapper;
using Microsoft.AspNetCore.Identity;
using OnePieceCardManagement.Models.Email;
using OnePieceCardManagement.Models.Authentication;
using System.Security.Claims;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using OnePieceCardManagement.DTOs;
using FluentValidation;
using OnePieceCardManagement.Validators;
using Microsoft.AspNetCore.Mvc;

namespace OnePieceCardManagement.Services
{
    public interface ITattoosService
    {
    }

    public class TattoosService : ITattoosService
    {
        private readonly DataContext _context;
        private readonly ILogger<TattoosService> _logger;
        private readonly EmailConfiguration _emailConfig;
        private readonly IMapper _mapper;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly IValidator<RegisterUserDto> _registerUserValidator;
        private readonly IConfiguration _configuration;

        // Constants
        private const int JWT_EXPIRY_MINUTES = 15;
        private const int REFRESH_TOKEN_EXPIRY_DAYS = 7;

        public TattoosService(
            DataContext context,
            ILogger<TattoosService> logger,
            EmailConfiguration emailConfig,
            IMapper mapper,
            UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager,
            SignInManager<IdentityUser> signInManager,
            IValidator<RegisterUserDto> registerUserValidator,
            IConfiguration configuration)
        {
            _context = context;
            _logger = logger;
            _emailConfig = emailConfig;
            _mapper = mapper;
            _userManager = userManager;
            _roleManager = roleManager;
            _signInManager = signInManager;
            _registerUserValidator = registerUserValidator;
            _configuration = configuration;
        }


    }
}
