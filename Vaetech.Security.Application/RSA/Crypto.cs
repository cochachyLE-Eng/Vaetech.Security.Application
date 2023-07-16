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
                encryptResult.EncodedInBytes = RSA.Encrypt(dataToEncrypt, false);
                encryptResult.Encoded = Convert.ToBase64String(encryptResult.EncodedInBytes);
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
        public string RSAEncrypt(string str, string publicKey)
        {
            //---Creates a new instance of RSACryptoServiceProvider---              
            RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
            //---Loads the public key---  
            RSA.FromXmlString(publicKey);
            byte[] EncryptedStr = null;

            //---Encrypts the string---  
            EncryptedStr = RSA.Encrypt(ASCIIEncoding.ASCII.GetBytes(str), false);

            //---Converts the encrypted byte array to string---              
            StringBuilder s = new StringBuilder();
            for (int i = 0; i <= EncryptedStr.Length - 1; i++)
            {
                //Console.WriteLine(EncryptedStr(i))  
                if (i != EncryptedStr.Length - 1)
                {
                    s.Append(EncryptedStr[i] + " ");
                }
                else
                {
                    s.Append(EncryptedStr[i]);
                }
            }

            return s.ToString();
        }

        public string RSADecrypt(string str, string privateKey)
        {
            //---Creates a new instance of RSACryptoServiceProvider---  
            RSACryptoServiceProvider RSA = new RSACryptoServiceProvider();
            //---Loads the private key---  
            RSA.FromXmlString(privateKey);

            //---Decrypts the string---  
            byte[] DecryptedStr = RSA.Decrypt(ASCIIEncoding.ASCII.GetBytes(str), false);
            //---Converts the decrypted byte array to string---  
            StringBuilder s = new StringBuilder();
            
            for (int i = 0; i <= DecryptedStr.Length - 1; i++)
            {
                //Console.WriteLine(DecryptedStr(i))  
                s.Append(System.Convert.ToChar(DecryptedStr[i]));
            }
            //Console.WriteLine(s)  
            return s.ToString();
        }
        public static EncryptResult TryEncrypt(string plainText, RSAParameters rSAKeyInfo)
            => Try.Catch(() => Encrypt(plainText, rSAKeyInfo)).Item1;
        public static DecryptResult TryDecrypt(string cipherText, RSAParameters rSAKeyInfo)
            => Try.Catch(() => Decrypt(cipherText, rSAKeyInfo)).Item1;
    }
}
