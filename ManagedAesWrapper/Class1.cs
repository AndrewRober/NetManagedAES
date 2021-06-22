using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace ManagedAesWrapper
{
    public static class Cryptography
    {
        #region Settings

        private static int _iterations = 2;
        private static int _keySize = 256;

        private static string _hash = "SHA1";
        private static string _salt = "7uk6pizraa3jz2xb";
        private static string _vector = "41a8moaa120rti62";

        #endregion

        public static string Encrypt(string value, string password) => Encrypt<AesManaged>(value, password);

        public static string Encrypt<T>(string value, string password)
                where T : SymmetricAlgorithm, new()
        {
            var vectorBytes = Encoding.ASCII.GetBytes(_vector);
            var saltBytes = Encoding.ASCII.GetBytes(_salt);
            var valueBytes = Encoding.UTF8.GetBytes(value);

            byte[] encrypted;
            using (var cipher = new T { Mode = CipherMode.CBC })
            {
                using (var enc = cipher.CreateEncryptor(
                    new PasswordDeriveBytes(password, saltBytes, _hash, _iterations).GetBytes(_keySize / 8), vectorBytes))
                using (var to = new MemoryStream())
                using (var writer = new CryptoStream(to, enc, CryptoStreamMode.Write))
                {
                    writer.Write(valueBytes, 0, valueBytes.Length);
                    writer.FlushFinalBlock();
                    encrypted = to.ToArray();
                }

                cipher.Clear();
            }
            return Convert.ToBase64String(encrypted);
        }

        public static string Decrypt(string value, string password) => Decrypt<AesManaged>(value, password);

        public static string Decrypt<T>(string value, string password) where T : SymmetricAlgorithm, new()
        {
            var vectorBytes = Encoding.ASCII.GetBytes(_vector);
            var saltBytes = Encoding.ASCII.GetBytes(_salt);
            var valueBytes = Convert.FromBase64String(value);

            byte[] decrypted;
            var decryptedByteCount = 0;

            using (var cipher = new T() { Mode = CipherMode.CBC })
                try
                {
                    using (var dec = cipher.CreateDecryptor(
                        new PasswordDeriveBytes(password, saltBytes, _hash, _iterations).GetBytes(_keySize / 8),
                        vectorBytes))
                    using (var from = new MemoryStream(valueBytes))
                    using (var reader = new CryptoStream(from, dec, CryptoStreamMode.Read))
                    {
                        decrypted = new byte[valueBytes.Length];
                        decryptedByteCount = reader.Read(decrypted, 0, decrypted.Length);
                    }
                }
                catch
                {
                    return string.Empty;
                }
                finally
                {
                    cipher.Clear();
                }

            return Encoding.UTF8.GetString(decrypted, 0, decryptedByteCount);
        }

    }
}
