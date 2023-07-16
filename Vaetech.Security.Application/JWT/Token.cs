using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Vaetech.Security.Application.JWT
{
    public class Token
    {
        private string __JWTkey { get; set; } = "jeGcjDOL5UlsuusFncCzWBQ7RKNUSesmQRMSGkVb1";
        private double __JWTExpirationTime { get; set; } = 50;
        public Token() { }
        public Token(string jwtKey, double jwtExpirationTime) {
            __JWTkey = jwtKey;
            __JWTExpirationTime = jwtExpirationTime;
        }
        public void SetJWTkey(string value) => __JWTkey = value;
        public void SetJWTExpirationTime(double value) => __JWTExpirationTime = value;
        public UserToken CreateToken(string uniqueName, string publicKey)
        {   
            return CreateToken(new List<Claim>
            {
                new Claim("PublicKey",publicKey),
                new Claim(JwtRegisteredClaimNames.UniqueName, uniqueName)                
            });
        }
        public UserToken CreateToken(Guid guidUser,string userName, string publicKey)
        {
            return CreateToken(new List<Claim>
            {
                new Claim("PublicKey",publicKey),
                new Claim("GuidUser", guidUser.ToString()),
                new Claim(JwtRegisteredClaimNames.UniqueName, userName)                
            });
        }        

        public UserToken CreateToken(Guid guidUser, string userName, string fullName, string email, int groupAccessId, string publicKey)
        {
            return CreateToken(new List<Claim>
            {
                new Claim("PublicKey",publicKey),
                new Claim("GuidUser", guidUser.ToString()),
                new Claim("FullName", fullName),
                new Claim("Email", email),
                new Claim("GroupAccessId", groupAccessId.ToString()),
                new Claim(JwtRegisteredClaimNames.UniqueName, userName)                
            });     
        }

        private UserToken CreateToken(IEnumerable<Claim> claims)
        {            
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(__JWTkey));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var expiration = DateTime.UtcNow.AddMinutes(__JWTExpirationTime);

            var token = new JwtSecurityToken(
                null,
                claims: claims,
                expires: expiration,
                signingCredentials: creds);

            return new UserToken
            {
                Token = new JwtSecurityTokenHandler().WriteToken(token),
                Expiration = expiration
            };
        }
    }
    public class UserToken
    {
        public string Token { get; set; }
        public DateTime Expiration { get; set; }
    }
    public enum UserTypesEnum
    {
        UserClient = 1,
        UserAdministrator = 2
    }
}
