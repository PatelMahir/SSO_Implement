using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using SSO_Implement.Database;
using SSO_Implement.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
namespace SSO_Implement.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly ApplicationDbContext _context;
        private readonly IConfiguration _configuration;
        public AuthenticationController(
            UserManager<IdentityUser> userManager, 
            SignInManager<IdentityUser> signInManager, 
            ApplicationDbContext context, 
            IConfiguration configuration)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _context = context;
            _configuration = configuration;
        }
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            if(!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            var user = new IdentityUser
            {
                UserName = model.Username,
                Email = model.Email,
            };
            var result= await _userManager.CreateAsync
                (user,model.Password);
            if (result.Succeeded)
            {
                return Ok(new { Result = "User registered successfully" });
            }
            return BadRequest(result.Errors);
        }
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody]LoginModel model)
        {
            if(!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            var user = await _userManager.FindByNameAsync(model.Username);
            if(user!=null&&await _userManager.CheckPasswordAsync(user, model.Password))
            {
                var token = GenerateJwtToken(user);
                return Ok(new { Token = token });
            }
            return Unauthorized("Invalid Username or Password");
        }
        [HttpPost("generate-sso-token")]
        [Authorize]
        public async Task<IActionResult>GenerateSSOToken()
        {
            try
            {
                var userId = User.FindFirstValue("User_Id");
                var user = await _userManager.FindByIdAsync(userId);
                if(user==null)
                {
                    return NotFound("User not found");
                }
                var ssoToken = new SSOToken
                {
                    UserId = user.Id,
                    Token=Guid.NewGuid().ToString(),
                    ExpiryDate = DateTime.UtcNow.AddMinutes(10),
                    IsUsed = false
                };
                _context.SSOTokens.Add(ssoToken);
                await _context.SaveChangesAsync();
                return Ok(new { SSOToken = ssoToken.Token });
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Internal server error:{ex.Message}");
            }
        }
        [HttpPost("validate-sso-token")]
        [Authorize]
        public async Task<IActionResult> ValidateSSOToken([FromBody]ValidateSSOTokenRequest request)
        {
            try
            {
                if(!ModelState.IsValid)
                {
                    return BadRequest(ModelState);
                }
                var ssoToken = await _context.SSOTokens.SingleOrDefaultAsync(t => t.Token == request.SSOToken);
                if (ssoToken == null || ssoToken.IsUsed || ssoToken.ExpiryDate < DateTime.UtcNow)
                {
                    return BadRequest("Invalid or expired SSO Token");
                }
                ssoToken.IsUsed = true;
                _context.SSOTokens.Update(ssoToken);
                await _context.SaveChangesAsync();
                var user = await _userManager.FindByIdAsync(ssoToken.UserId);
                var newJwtToken = GenerateJwtToken(user);
                return Ok(new
                {
                    TokenOptions = newJwtToken,
                    UserDetails = new
                    {
                        Username = user.UserName,
                        Email = user.Email,
                        UserId = user.Id
                    }
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, $"Internal server error:{ex.Message}");
            }
        }
        private string GenerateJwtToken(IdentityUser user)
        {
            var claims = new List<Claim>
            {
                new Claim("User_Id",user.Id.ToString()),
                new Claim(ClaimTypes.NameIdentifier,user.UserName),
                new Claim(ClaimTypes.Email,user.Email),
                new Claim(JwtRegisteredClaimNames.Sub,user.Id.ToString())
            };
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var token=new JwtSecurityToken(
                issuer: _configuration["Jwt:Issuer"],
                audience: _configuration["Jwt:Audience"],
                claims:claims,
                expires:DateTime.UtcNow.AddMinutes(30),
                signingCredentials: creds);
            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}