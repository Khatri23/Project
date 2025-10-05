using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
namespace PasswordLessAuth
{
    [StructLayout(LayoutKind.Sequential)]
    public struct Pair
    {
        public IntPtr first;
        public IntPtr second;
    }
    public class PublicKey_Crypto
    {
        
        [DllImport("ecc.dll",CallingConvention=CallingConvention.Cdecl)]
        public static extern Pair  GeneratePublicKey(string private_key);
        
        [DllImport("ecc.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern Pair GenerateSignature(string PR, string msg);
        
        [DllImport("ecc.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern void Free_keys(IntPtr keys);

        [DllImport("ecc.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern bool Verify_Signature(string PUa, string PUb, string hash, string s, string r);

        [DllImport("ecc.dll", CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr Response(string PUa,string PUb,string PR);

        [DllImport("ecc.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr HS256(string data, string key);

        [DllImport("ecc.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern IntPtr checksum(string PUa, string PUb);

        [DllImport("ecc.dll", CallingConvention = CallingConvention.Cdecl)]
        private static extern Pair Challange(string PUa, string PUb);

        public static string HMAC(string data,string key)
        {
            IntPtr ptr=HS256(data,key);
            string value=Marshal.PtrToStringAnsi(ptr);
            Free_keys(ptr);
            return value;
        }
        public static string Checksum(string PUa, string PUb) {
            IntPtr ptr=checksum(PUa, PUb);
            string value=Marshal.PtrToStringAnsi(ptr);
            Free_keys(ptr);
            return value;
        }
        public static string[] Server_challange(string PUa, string PUb) { //return the hash of the point 
            Pair obj=Challange(PUa, PUb);
            string[] value = new string[3];
            IntPtr ptr = obj.first;
            string publickey=Marshal.PtrToStringAnsi(ptr);
            Free_keys(ptr);
            value[0] = publickey.Substring(0, 64);
            value[1]=publickey.Substring(64, 64);
            ptr = obj.second;
            value[2] = Marshal.PtrToStringAnsi(ptr);
            Free_keys(ptr );
            return value;
        }
        public static string sha256(string hexMsg)
        {
                // Convert hex string to byte array
                byte[] msgBytes = HexToBytes(hexMsg);
                string hashHex;
                // Compute SHA-256
                using (SHA256 sha = SHA256.Create())
                {
                    byte[] hashBytes = sha.ComputeHash(msgBytes);
                    hashHex = BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
                }
                return hashHex;
        }
        public static byte[] HexToBytes(string hex)
        {
            if (hex.Length % 2 != 0)
                throw new ArgumentException("Invalid hex string length");

            byte[] bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
            }
            return bytes;
        }
        public static void PRF(string secret,string label,string seed)
        {
            string[] A = new string[4];
            string SEED = label + seed;
            A[0] = SEED;
            for(int i = 1; i <= 3; i++)
            {
                A[i] = HMAC(A[i - 1], secret);
            }
            string Session_secret = HMAC(A[1]+SEED, secret);
            string MAC_secret=HMAC(A[2]+SEED, secret);
            string IV=HMAC(A[3]+SEED, secret);
            Console.WriteLine("Session secret: " + Session_secret);
            Console.WriteLine("MAC secret: " + MAC_secret);
            Console.WriteLine("IV: " + IV);
        }

    }
}

