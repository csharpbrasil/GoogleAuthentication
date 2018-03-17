using System;
using System.Linq;
using System.Runtime.Remoting.Metadata.W3cXsd2001;
using System.Security.Cryptography;
using System.Text;


namespace GoogleAuthentication
{
    public class GAuthenticator
    {
        private int _secondsToGo;

        public int SecondsToGo
        {
            get { return _secondsToGo; }
            private set { _secondsToGo = value; if (SecondsToGo == 30) CalculateOneTimePassword(); }
        }

        private string _identity;

        public string Identity
        {
            get { return _identity; }
            set { _identity = value; CalculateOneTimePassword(); }
        }

        private string _issuer;

        public string Issuer
        {
            get { return _issuer; }
            set { _issuer = value; }
        }

        private int _qrcodesize = 200;

        public int QRCodeSize
        {
            get { return _qrcodesize; }
            set { _qrcodesize = value; }
        }

        private byte[] _secret;

        public byte[] Secret
        {
            get { return _secret; }
            set { _secret = value; CalculateOneTimePassword(); }
        }

        public string QRCodeUrl
        {
            get { return GetQRCodeUrl(); }
        }

        private Int64 _timestamp;

        public Int64 Timestamp
        {
            get { return _timestamp; }
            private set { _timestamp = value; }
        }

        private byte[] _hmac;

        public byte[] Hmac
        {
            get { return _hmac; }
            private set { _hmac = value; }
        }

        public byte[] HmacPart1
        {
            get { return _hmac.Take(Offset).ToArray(); }
        }

        public byte[] HmacPart2
        {
            get { return _hmac.Skip(Offset).Take(4).ToArray(); }
        }

        public byte[] HmacPart3
        {
            get { return _hmac.Skip(Offset + 4).ToArray(); }
        }

        private int _offset;

        public int Offset
        {
            get { return _offset; }
            private set { _offset = value; }
        }

        private int _oneTimePassword;

        public int OneTimePassword
        {
            get { return _oneTimePassword; }
            set { _oneTimePassword = value; }
        }

        private string GetQRCodeUrl()
        {
            // https://code.google.com/p/google-authenticator/wiki/KeyUriFormat
            var base32Secret = Base32.Encode(Secret);
            return string.Format("http://chart.apis.google.com/chart?chs={0}x{0}&cht=qr&chl=otpauth://totp/{1}%3Fsecret%3D{2}{3}", QRCodeSize, Identity, base32Secret, (string.IsNullOrEmpty(Issuer) ? string.Empty : string.Format("%26issuer%3D{0}", Issuer)));
        }

        private void CalculateOneTimePassword()
        {
            if (_secret != null && _secret.Length > 0)
            {
                // https://tools.ietf.org/html/rfc4226
                Timestamp = Convert.ToInt64(GetUnixTimestamp() / 30);
                var data = BitConverter.GetBytes(Timestamp).Reverse().ToArray();
                Hmac = new HMACSHA1(Secret).ComputeHash(data);
                Offset = Hmac.Last() & 0x0F;
                OneTimePassword = (
                    ((Hmac[Offset + 0] & 0x7f) << 24) |
                    ((Hmac[Offset + 1] & 0xff) << 16) |
                    ((Hmac[Offset + 2] & 0xff) << 8) |
                    (Hmac[Offset + 3] & 0xff)
                        ) % 1000000;
            }
        }

        private static Int64 GetUnixTimestamp()
        {
            return Convert.ToInt64(Math.Round((DateTime.UtcNow - new DateTime(1970, 1, 1, 0, 0, 0)).TotalSeconds));
        }

        public void setSecretKey(string secretKey)
        {
            Secret = new System.Text.ASCIIEncoding().GetBytes(secretKey);
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