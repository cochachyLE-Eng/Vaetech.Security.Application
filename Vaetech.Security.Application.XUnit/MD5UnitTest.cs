using System;
using Vaetech.Data.ContentResult;
using Xunit;

namespace Vaetech.Security.Application.XUnit
{
    public class MD5UnitTest
    {
        [Fact]
        public void HashStringMD5()
        {
            string text = "abc1*23doAs&%&&Tsz>32/1";
            EncryptResult encryptRs = MD5.CryptoEx.Encrypt(text);
            DecryptResult decryptRs = MD5.CryptoEx.Decrypt(encryptRs.Encoded);

            Assert.Equal(text, decryptRs.Decoded);
        }
    }
}
