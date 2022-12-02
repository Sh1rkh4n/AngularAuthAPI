using AngularAuthAPI.Context;
using AngularAuthAPI.Helpers;
using AngularAuthAPI.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Generic;
using System.Diagnostics.Metrics;
using System.IdentityModel.Tokens.Jwt;
using System.Runtime.Intrinsics.X86;
using System.Security.Claims;
using System.Text;
using System.Text.RegularExpressions;

namespace AngularAuthAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly AppDbContext _authContext;

        public UserController(AppDbContext appDbContext)
        {
            _authContext = appDbContext;    
        }

        [HttpPost("authenticate")]
        public async Task<IActionResult> Authenticate([FromBody] User userObj)
        {
            if(userObj == null)
                return BadRequest();

            var user = await _authContext.Users.FirstOrDefaultAsync(x=>x.Username == userObj.Username);
            if (user == null)
                return NotFound(new { Message = "User Not Found!" });

            if (!PasswordHasher.VerifyPassword(userObj.Password, user.Password))
            {
                return BadRequest(new { Message = "Password is Incorrect"});
            }

            user.Token= CreateJwt(user);

            //var userpw = await _authContext.Users.FirstOrDefaultAsync(x => x.Username == userObj.Username && x.Password == userObj.Password);
            //if (userpw == null)
            //    return NotFound(new { Message = "User's password is incorrect!" });

            return Ok(new 
            { 
                Token = user.Token,
                Message = "Login Success!"
            });
        }

        [HttpPost("register")]
        public async Task<IActionResult> RegisterUser([FromBody] User userObj)
        {
            if (userObj == null)
                return BadRequest();

            //Check Username

            if (await CheckUserNameExistAsync(userObj.Username))
                return BadRequest(new { Message = "Username Already Exists!" });

            //Check Email
            if (await CheckEmailExistAsync(userObj.Email))
                return BadRequest(new { Message = "Email Already Exists!" });

            //Check Password Strength
            var pass = CheckPasswordStrength(userObj.Password);
            if(!string.IsNullOrEmpty(pass))
                return BadRequest(new { Message = pass.ToString()});

            userObj.Password = PasswordHasher.HashPassword(userObj.Password);
            userObj.Role = "User";
            userObj.Token = "";
            await _authContext.Users.AddAsync(userObj);
            await _authContext.SaveChangesAsync();
            return Ok(new
            {
                Message = "User Registered!"
            });
        }

        private Task<bool> CheckUserNameExistAsync(string username)
            => _authContext.Users.AnyAsync(x => x.Username == username);

        private Task<bool> CheckEmailExistAsync(string email)
            => _authContext.Users.AnyAsync(x => x.Email == email);

        private static string CheckPasswordStrength(string password)
        {
            StringBuilder sb = new StringBuilder();

            //You may use this regex with multiple lookahead assertions(conditions):

            //      ^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[#?!@$%^&*-]).{8,}$
            //      ^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[\W]).{8,}$
            //      ^\x00-\x7F
            //This regex will enforce these rules:

            //    At least one upper case English letter, (?=.*?[A-Z])
            //    At least one lower case English letter, (?=.*?[a-z])
            //    At least one digit, (?=.*?[0-9])
            //    At least one special character, (?=.*?[#?!@$%^&*-])  changed to below
            //    At least one match of any non-word character, (?=.*?[\W])
            //    At pattern for Non-Unicode chars, ^\x00-\x7F (not used now)
            //    Minimum eight in length.{8,} (with the anchors)

            //if (password.Length < 8)
            //    sb.Append("Minimum password length is 8" + Environment.NewLine);
            //if (!(
            //    Regex.IsMatch(password, "[a-z]") &&
            //    Regex.IsMatch(password, "[A-Z]") &&
            //    Regex.IsMatch(password, "[0-9]")))
            //    sb.Append("Password should be alphanumeric" + Environment.NewLine);

            if (!Regex.IsMatch(password, "^(?=.*?[A-Z])(?=.*?[a-z])(?=.*?[0-9])(?=.*?[\\W]).{8,}$"))
                sb.Append(
                    "Password should be alphanumeric," + Environment.NewLine +
                    "min length of 8 chars," + Environment.NewLine +
                    "least 1 UPPERCASE char, " + Environment.NewLine +
                    "least 1 lowercase char, " + Environment.NewLine +
                    "least 1 any special (?!+@ etc.) char !" + Environment.NewLine
                    );
            return sb.ToString();  
        }

        private string CreateJwt(User user)
        {
            var jwTokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("veryverysecret.....");
            var identity = new ClaimsIdentity(new Claim[]
            {
                new Claim(ClaimTypes.Role, user.Role),
                new Claim(ClaimTypes.Name,$"{user.FirstName} {user.LastName}"),
            });

            var credentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = identity,
                Expires = DateTime.Now.AddSeconds(50000),
                SigningCredentials = credentials
            };

            var token = jwTokenHandler.CreateToken(tokenDescriptor);
            return jwTokenHandler.WriteToken(token);
        }

        [Authorize] 
        [HttpGet]
        public async Task <ActionResult<User>> GetAllUsers()
        {
            return Ok(await _authContext.Users.ToListAsync());
        }
    }
}
