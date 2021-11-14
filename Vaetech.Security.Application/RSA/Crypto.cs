using System;
using System.Security.Cryptography;
using System.Text;
using Vaetech.Data.ContentResult;

namespace Vaetech.Security.Application.RSA
{
    public class Crypto
    {
        public static EncryptResult Encrypt(string plainText, RSAParameters rSAKeyInfo)
        {
            if (string.IsNullOrEmpty(plainText))
                throw new ArgumentNullException("The plainText cannot be empty.");

            //Create a UnicodeEncoder to convert between byte array and string.
            UnicodeEncoding ByteConverter = new UnicodeEncoding();
            byte[] dataToEncrypt = ByteConverter.GetBytes(plainText);

            return Encrypt(dataToEncrypt, rSAKeyInfo);
        }
        public static EncryptResult Encrypt(byte[] dataToEncrypt, RSAParameters rSAKeyInfo)
        {            
            EncryptResult encryptResult = new EncryptResult();
                        
            //Create a new instance of RSACryptoServiceProvider.
            using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
            {
                //Import the RSA Key information. This only needs toinclude the public key information.
                RSA.ImportParameters(rSAKeyInfo);

                //Encrypt the passed byte array and specify OAEP padding.                  
                encryptResult.EncryptedInBytes = RSA.Encrypt(dataToEncrypt, false);
                encryptResult.Encrypted = Convert.ToBase64String(encryptResult.EncryptedInBytes);
            }
            return encryptResult;
        }
        public static DecryptResult Decrypt(string cipherText, RSAParameters rSAKeyInfo)
        {
            if (string.IsNullOrEmpty(cipherText))
                throw new ArgumentNullException("The cipherText cannot be empty.");            

            byte[] cipherTextInBytes = ASCIIEncoding.ASCII.GetBytes(cipherText);            

            return Decrypt(cipherTextInBytes, rSAKeyInfo);
        }
        public static DecryptResult Decrypt(byte[] dataToDecrypt, RSAParameters rSAKeyInfo)
        {
            DecryptResult decryptResult = new DecryptResult();
            UnicodeEncoding ByteConverter = new UnicodeEncoding();
            //Create a new instance of RSACryptoServiceProvider.
            using (RSACryptoServiceProvider RSA = new RSACryptoServiceProvider())
            {               
                //Import the RSA Key information. This needs to include the private key information.
                RSA.ImportParameters(rSAKeyInfo);

                //Decrypt the passed byte array and specify OAEP padding.              
                decryptResult.DecodedInBytes = RSA.Decrypt(dataToDecrypt, false);
                decryptResult.Decoded = ByteConverter.GetString(decryptResult.DecodedInBytes);
            }
            return decryptResult;
        }
        public static EncryptResult TryEncrypt(string plainText, RSAParameters rSAKeyInfo)
            => Try.Catch(() => Encrypt(plainText, rSAKeyInfo)).Item1;
        public static DecryptResult TryDecrypt(string cipherText, RSAParameters rSAKeyInfo)
            => Try.Catch(() => Decrypt(cipherText, rSAKeyInfo)).Item1;
    }
}
