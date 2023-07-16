using System;
using Xunit;

namespace Vaetech.Security.Application.XUnit
{
    public class AESUnitTest
    {
        [Fact]
        public void ValidingEncryptDecrypt()
        {
            string text = "#123456789";
            string pass = "1*23&7#rts%t";
            var encryptRs = AES.CryptoEx.Encrypt(text, pass);
            var decryptRs = AES.CryptoEx.Decrypt(encryptRs.Encoded, pass);

            Assert.Equal(text, decryptRs.Decoded);
        }
    }
}
