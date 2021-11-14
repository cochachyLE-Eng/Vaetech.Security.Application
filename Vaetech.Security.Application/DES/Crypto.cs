using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Vaetech.Data.ContentResult;

namespace Vaetech.Security.Application.DES
{
    public class Crypto 
    {        
        public static EncryptResult Encrypt(string plainText, string password)
        {            
            if (string.IsNullOrEmpty(password))
                throw new ArgumentNullException("The password cannot be empty.");

            byte[] key = ASCIIEncoding.ASCII.GetBytes(password);

            return Encrypt(plainText, key, key);
        }
        public static EncryptResult Encrypt(string plainText, byte[] Key, byte[] IV)
        {
            EncryptResult cryptoResult = new EncryptResult();

            // Check arguments.
            if (string.IsNullOrEmpty(plainText))
                throw new ArgumentNullException("The plainText cannot be empty.");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("The Key cannot be empty.");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("The IV cannot be empty.");

            // Create the streams used for encryption.
            using (DESCryptoServiceProvider encryptor = new DESCryptoServiceProvider())
            using (MemoryStream msEncrypt = new MemoryStream())
            using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor.CreateEncryptor(Key, IV), CryptoStreamMode.Write))
            {
                using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                {
                    //Write all data to the stream.
                    swEncrypt.Write(plainText);
                }
                cryptoResult.EncryptedInBytes = msEncrypt.ToArray();
                cryptoResult.Encrypted = Convert.ToBase64String(msEncrypt.GetBuffer(), 0, (int)msEncrypt.Length);
            }
            
            return cryptoResult;
        }
        public static DecryptResult Decrypt(string cipherText, string password)
        {
            if (string.IsNullOrEmpty(password))
                throw new ArgumentNullException("The cipherText cannot be empty.");
            if (string.IsNullOrEmpty(password))
                throw new ArgumentNullException("The password cannot be empty.");

            byte[] cipherTextInBytes = ASCIIEncoding.ASCII.GetBytes(cipherText);
            byte[] key = ASCIIEncoding.ASCII.GetBytes(password);

            return Decrypt(cipherTextInBytes, key, key);
        }
        public static DecryptResult Decrypt(byte[] cipherTextInBytes, byte[] Key, byte[] IV)
        {
            DecryptResult decryptResult = new DecryptResult();
            if (cipherTextInBytes == null || cipherTextInBytes.Length <= 0)
                throw new ArgumentNullException("The cipherText cannot be empty.");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("The Key cannot be empty.");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("The IV cannot be empty.");

            using (DESCryptoServiceProvider cryptoProvider = new DESCryptoServiceProvider())
            using (MemoryStream memoryStream = new MemoryStream(cipherTextInBytes))                
            using (CryptoStream cryptoStream = new CryptoStream(memoryStream, cryptoProvider.CreateDecryptor(Key, IV), CryptoStreamMode.Read))
            using (StreamReader reader = new StreamReader(cryptoStream))
            {                
                decryptResult.Decoded = reader.ReadToEnd();
                decryptResult.DecodedInBytes = ASCIIEncoding.ASCII.GetBytes(decryptResult.Decoded);             
            }
            return decryptResult;
        }
        public static EncryptResult TryEncrypt(string plainText, string password)
            => Try.Catch(() => Encrypt(plainText, password)).Item1;                
        public static DecryptResult TryDecrypt(string cipherText, string password)
            => Try.Catch(() => Decrypt(cipherText, password)).Item1;
    }
}
