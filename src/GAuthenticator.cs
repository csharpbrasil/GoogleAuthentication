using System;
using System.Linq;
using System.Runtime.Remoting.Metadata.W3cXsd2001;
using System.Security.Cryptography;
using System.Text;


namespace GoogleAuthentication
{
    public class GAuthenticator
    {
        public string Identity { get; internal set; }
        public string Issuer { get; internal set; }
        public byte[] Secret { get; internal set; }

        public Int64 Timestamp { get; set; }
        public int Offset { get; set; }
        public byte[] Hmac { get; set; }
        public byte[] HmacPart1 { get => Hmac.Take(Offset).ToArray(); }
        public byte[] HmacPart2 { get => Hmac.Skip(Offset).Take(4).ToArray(); }
        public byte[] HmacPart3 { get => Hmac.Skip(Offset + 4).ToArray(); }

        public int OneTimePassword
        {
            get
            {
                if (Secret == null || Secret.Length == 0) return 0;

                // REFERENCE: https://tools.ietf.org/html/rfc4226
                Timestamp = Convert.ToInt64(GetUnixTimestamp() / 30);
                var data = BitConverter.GetBytes(Timestamp).Reverse().ToArray();
                Hmac = new HMACSHA1(Secret).ComputeHash(data);
                Offset = Hmac.Last() & 0x0F;
                return (
                    ((Hmac[Offset + 0] & 0x7f) << 24) |
                    ((Hmac[Offset + 1] & 0xff) << 16) |
                    ((Hmac[Offset + 2] & 0xff) << 8) |
                    (Hmac[Offset + 3] & 0xff)
                        ) % 1000000;
            }
        }

        public string QRCodeUrl 
        { 
            get
            {
                var base32Secret = Base32.Encode(Secret);
                var _issuer = (string.IsNullOrEmpty(Issuer) ? string.Empty : string.Format("%26issuer%3D{0}", Issuer));
                return $"https://chart.apis.google.com/chart?chs=200x200&cht=qr&chl=otpauth://totp/{Identity}%3Fsecret%3D{base32Secret}{_issuer}";
            }
        }

        private static Int64 GetUnixTimestamp()
        {
            return Convert.ToInt64(Math.Round((DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0)).TotalSeconds));
        }

        public GAuthenticator(string identity, string issuer, string secret)
        {
            Identity = identity;
            Issuer = issuer;
            Secret = new System.Text.ASCIIEncoding().GetBytes(secret);
        }

        public GAuthenticator(string identity, byte[] secret)
        {
            Identity = identity;
            Secret = secret;
        }
    }

    public static class Base32
    {
        private const int IN_BYTE_SIZE = 8;
        private const int OUT_BYTE_SIZE = 5;
        private static char[] alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".ToCharArray();

        public static string Encode(byte[] data)
        {
            int i = 0, index = 0, digit = 0;
            int current_byte, next_byte;
            StringBuilder result = new StringBuilder((data.Length + 7) * IN_BYTE_SIZE / OUT_BYTE_SIZE);

            while (i < data.Length)
            {
                current_byte = (data[i] >= 0) ? data[i] : (data[i] + 256); // Unsign

                /* Is the current digit going to span a byte boundary? */
                if (index > (IN_BYTE_SIZE - OUT_BYTE_SIZE))
                {
                    if ((i + 1) < data.Length)
                        next_byte = (data[i + 1] >= 0) ? data[i + 1] : (data[i + 1] + 256);
                    else
                        next_byte = 0;

                    digit = current_byte & (0xFF >> index);
                    index = (index + OUT_BYTE_SIZE) % IN_BYTE_SIZE;
                    digit <<= index;
                    digit |= next_byte >> (IN_BYTE_SIZE - index);
                    i++;
                }
                else
                {
                    digit = (current_byte >> (IN_BYTE_SIZE - (index + OUT_BYTE_SIZE))) & 0x1F;
                    index = (index + OUT_BYTE_SIZE) % IN_BYTE_SIZE;
                    if (index == 0)
                        i++;
                }
                result.Append(alphabet[digit]);
            }

            return result.ToString();
        }
    }

    public class Util
    {
        private string ByteArray2String(byte[] value)
        {
            SoapHexBinary shb = new SoapHexBinary(value);
            return shb.ToString();
        }
    }
}