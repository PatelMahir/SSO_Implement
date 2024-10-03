using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
namespace SSO_Implement.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class DemoController : ControllerBase
    {
        [HttpGet("public-data")]
        public IActionResult GetPublicData()
        {
            var publicData = new { Message = "This is public data accessible without authentication " };
            return Ok(publicData);
        }
        [Authorize]
        [HttpGet("protected-data")]
        public IActionResult GetProtectedData()
        {
            var protectedData = new { Message = "This is protected data accessible only with authentication" };
            return Ok(protectedData);
        }
    }
}