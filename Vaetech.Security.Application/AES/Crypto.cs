using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Vaetech.Data.ContentResult;

namespace Vaetech.Security.Application.AES
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

            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create an encryptor to perform the stream transform.
                ICryptoTransform encryptor = aesAlg.CreateEncryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for encryption.
                using (MemoryStream msEncrypt = new MemoryStream())               
                using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                {
                    using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                    {
                        //Write all data to the stream.
                        swEncrypt.Write(plainText);
                    }
                    cryptoResult.EncodedInBytes = msEncrypt.ToArray();
                    cryptoResult.Encoded = Convert.ToBase64String(msEncrypt.GetBuffer(), 0, (int)msEncrypt.Length);
                }
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
        public static DecryptResult Decrypt(byte[] cipherText, byte[] Key, byte[] IV)
        {
            DecryptResult decryptResult = new DecryptResult();

            // Check arguments.
            if (cipherText == null || cipherText.Length <= 0)
                throw new ArgumentNullException("cipherText");
            if (Key == null || Key.Length <= 0)
                throw new ArgumentNullException("Key");
            if (IV == null || IV.Length <= 0)
                throw new ArgumentNullException("IV");            

            // Create an Aes object with the specified key and IV.
            using (Aes aesAlg = Aes.Create())
            {
                aesAlg.Key = Key;
                aesAlg.IV = IV;

                // Create a decryptor to perform the stream transform.
                ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key, aesAlg.IV);

                // Create the streams used for decryption.
                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                {
                    // Read the decrypted bytes from the decrypting stream and place them in a string.
                    decryptResult.Decoded = srDecrypt.ReadToEnd();
                    decryptResult.DecodedInBytes = ASCIIEncoding.ASCII.GetBytes(decryptResult.Decoded);
                }
            }

            return decryptResult;
        }
        public static EncryptResult TryEncrypt(string plainText, string password)
            => Try.Catch(() => Encrypt(plainText, password)).Item1;
        public static DecryptResult TryDecrypt(string cipherText, string password)
            => Try.Catch(() => Decrypt(cipherText, password)).Item1;
    }
}
