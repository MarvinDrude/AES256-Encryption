using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace PWManager.Encryptions {
    public static class Encryption {
        
        private const int AES256KeySize = 256;
        
        private const int AES256SaltSize = 128;
        
        private const int AES256KeyIterations = 60000;
        
        private const int AES256PairSize = 16;
        
        private const int AES256HMACKeySize = 256;
        
        private const int AES256HMACLength = 512;
        
        public static byte[] AESEncrypt(byte[] clear, byte[] password) {

            byte[] encrypted = null;
            byte[] salt = new byte[AES256SaltSize / 8];
            
            GenerateRandomBytes(salt);

            using(var key = GenerateKey(password, salt)) {

                using(Aes aes = new AesManaged()) {

                    SetupAES256(aes, key.GetBytes(AES256KeySize / 8), key.GetBytes(aes.BlockSize / 8));

                    using(MemoryStream ms = new MemoryStream()) {

                        byte[] hmac = HashHMAC(key.GetBytes(AES256HMACKeySize / 8), clear);
                        
                        WritePublicInformation(ms, salt, key.GetBytes(AES256PairSize / 8), hmac);

                        using(CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write)) {

                            cs.Write(clear, 0, clear.Length);
                            cs.Close();

                        }

                        encrypted = ms.ToArray();

                    }

                }

            }

            return encrypted;

        }

        public static byte[] AESDecrypt(byte[] input, byte[] password) {

            byte[] decrypted = null;

            byte[] salt = new byte[AES256SaltSize / 8];
            byte[] pair = new byte[AES256PairSize / 8];
            byte[] hmac = new byte[AES256HMACLength / 8];

            GetPublicInformation(input, salt, pair, hmac);
            
            int infoSize = salt.Length + pair.Length + hmac.Length;
            byte[] encrypted = new byte[input.Length - infoSize];
            Buffer.BlockCopy(input, infoSize, encrypted, 0, encrypted.Length);

            using(var key = GenerateKey(password, salt)) {

                using(Aes aes = new AesManaged()) {

                    SetupAES256(aes, key.GetBytes(AES256KeySize / 8), key.GetBytes(aes.BlockSize / 8));

                    using(MemoryStream ms = new MemoryStream()) {

                        try {

                            using(CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Write)) {

                                cs.Write(encrypted, 0, encrypted.Length);
                                cs.Close();

                            }

                            decrypted = ms.ToArray();

                        } catch(Exception e) {

                            decrypted = new byte[1];

                        }

                    }

                }

            }

            return decrypted;

        }

        public static bool VerifyLate(byte[] input, byte[] password) {

            byte[] cP = new byte[password.Length];
            Buffer.BlockCopy(password, 0, cP, 0, cP.Length);

            byte[] decrypted = AESDecrypt(input, password);

            byte[] salt = new byte[AES256SaltSize / 8];
            byte[] pair = new byte[AES256PairSize / 8];
            byte[] hmac = new byte[AES256HMACLength / 8];

            GetPublicInformation(input, salt, pair, hmac);

            using(var key = GenerateKey(cP, salt)) {

                key.GetBytes(AES256KeySize / 8);
                key.GetBytes(16);

                byte[] newHMAC = HashHMAC(key.GetBytes(AES256HMACKeySize / 8), decrypted);
                key.GetBytes(AES256PairSize);

                return newHMAC.SequenceEqual(hmac);

            }

        }

        public static bool VerifyEarly(byte[] input, byte[] password) {

            byte[] salt = new byte[AES256SaltSize / 8];
            byte[] pair = new byte[AES256PairSize / 8];
            byte[] hmac = new byte[AES256HMACLength / 8];

            GetPublicInformation(input, salt, pair, hmac);

            using(var key = GenerateKey(password, salt)) {

                key.GetBytes(AES256KeySize / 8);
                key.GetBytes(16);
                key.GetBytes(AES256HMACKeySize / 8);

                byte[] pPair = key.GetBytes(AES256PairSize / 8);
                
                return pPair.SequenceEqual(pair);

            }

        }

        private static void GetPublicInformation(byte[] input, byte[] salt, byte[] pair, byte[] hmac) {

            byte[] info = new byte[salt.Length + pair.Length + hmac.Length];
            Buffer.BlockCopy(input, 0, info, 0, info.Length);

            Buffer.BlockCopy(info, 0, salt, 0, salt.Length);
            Buffer.BlockCopy(info, salt.Length, pair, 0, pair.Length);
            Buffer.BlockCopy(info, salt.Length + pair.Length, hmac, 0, hmac.Length);

        }

        private static void WritePublicInformation(Stream s, byte[] salt, byte[] pair, byte[] hash) {

            s.Write(salt, 0, salt.Length);
            s.Write(pair, 0, pair.Length);
            s.Write(hash, 0, hash.Length);

        }

        private static void SetupAES256(Aes aes, byte[] key, byte[] iv) {
            
            aes.KeySize = AES256KeySize;
            aes.Key = key;
            aes.IV = iv;
            aes.Padding = PaddingMode.PKCS7;
            aes.Mode = CipherMode.CBC;

        }

        private static byte[] HashHMAC(byte[] key, byte[] message) {

            var hash = new HMACSHA512(key);
            return hash.ComputeHash(message);

        }
        
        private static Rfc2898DeriveBytes GenerateKey(byte[] password, byte[] salt) {

            var key = new Rfc2898DeriveBytes(password, salt, AES256KeyIterations);
            DestroyArray(password);

            return key;

        }

        private static void GenerateRandomBytes(byte[] array) {

            using(RNGCryptoServiceProvider provider = new RNGCryptoServiceProvider()) {

                provider.GetBytes(array);

            }

        }

        public static void DestroyArray(byte[] array) {

            Array.Clear(array, 0, array.Length);
            GenerateRandomBytes(array);
            Array.Resize(ref array, 1);
            array = null;

        }

    }
}
