using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using OnePieceCardManagement.DTOs.Authentication.Request;
using OnePieceCardManagement.DTOs.Common;
using OnePieceCardManagement.DTOs.Email;
using System.Security.Claims;
using System;
using OnePieceCardManagement.Services;

namespace OnePieceCardManagement.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class TattoosController : ControllerBase
    {
        private readonly ITattoosService _tattosService;
        private readonly ILogger<AuthenticationController> _logger;

        public TattoosController(
            ITattoosService tattosService,
            ILogger<AuthenticationController> logger)
        {
            _tattosService = tattosService;
            _logger = logger;
        }

    }
}
