using System;
using System.Text;
using System.Security.Cryptography;
using Vaetech.Data.ContentResult;

namespace Vaetech.Security.Application.MD5
{
    public class CryptoEx
    {
        private static string key { get; set; } = "A!1x0THhi%XjjvYdzc2x@bob$009Xabcdxyzmvkj@shjskdf1213$234242342";
        public static EncryptResult Encrypt(string text)
        {
            using (var md5 = new MD5CryptoServiceProvider())
            {
                using (var tdes = new TripleDESCryptoServiceProvider())
                {
                    tdes.Key = md5.ComputeHash(UTF8Encoding.UTF8.GetBytes(key));
                    tdes.Mode = CipherMode.ECB;
                    tdes.Padding = PaddingMode.PKCS7;

                    using (var transform = tdes.CreateEncryptor())
                    {
                        byte[] textBytes = UTF8Encoding.UTF8.GetBytes(text);
                        byte[] bytes = transform.TransformFinalBlock(textBytes, 0, textBytes.Length);

                        return new EncryptResult(Convert.ToBase64String(bytes, 0, bytes.Length), bytes);
                    }
                }
            }
        }

        public static DecryptResult Decrypt(string cipher)
        {
            using (var md5 = new MD5CryptoServiceProvider())
            {
                using (var tdes = new TripleDESCryptoServiceProvider())
                {
                    tdes.Key = md5.ComputeHash(UTF8Encoding.UTF8.GetBytes(key));
                    tdes.Mode = CipherMode.ECB;
                    tdes.Padding = PaddingMode.PKCS7;

                    using (var transform = tdes.CreateDecryptor())
                    {
                        byte[] cipherBytes = Convert.FromBase64String(cipher);
                        byte[] bytes = transform.TransformFinalBlock(cipherBytes, 0, cipherBytes.Length);
                        return new DecryptResult(UTF8Encoding.UTF8.GetString(bytes), bytes);
                    }
                }
            }
        }
    }
}
