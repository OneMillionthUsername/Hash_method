using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;

namespace Hash
{
    internal static class HashService
    {
        private const int keySize = 64;
        private const int iterations = 350000;
        private static readonly HashAlgorithmName sHA512 = HashAlgorithmName.SHA512;


        public static string HashPassword(string password, out byte[] salt)
        {
            salt = RandomNumberGenerator.GetBytes(keySize);
            var hash = Rfc2898DeriveBytes.Pbkdf2(Encoding.UTF8.GetBytes(password), salt, iterations, sHA512, keySize);

            //Der Rückgabewert muss in der DB gespeichert werden.
            return Convert.ToHexString(hash);
        }

        public static bool VerfiyPassword(string password, string hash, byte[] salt)
        {
            //hash muss aus der Datenbank eingelesen werden.
            var hashToCompare = Rfc2898DeriveBytes.Pbkdf2(password, salt, iterations, sHA512, keySize);
            return CryptographicOperations.FixedTimeEquals(hashToCompare, Convert.FromHexString(hash));
        }
    }
}
