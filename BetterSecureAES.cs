using SimpleCrypto;
using System.Linq;
using System;

namespace BetterSecureAESLib
{
    public class BetterSecureAES
    {
        public static ProtoRandom.ProtoRandom random = new ProtoRandom.ProtoRandom(5);

        public static byte[] Encrypt(byte[] input, byte[] password)
        {
            if (input == null)
            {
                throw new Exception("Can not encrypt null data.");
            }

            if (input.Length == 0)
            {
                throw new Exception("Can not encrypt empty data.");
            }

            if (password == null)
            {
                throw new Exception("Can not use a null password.");
            }

            if (password.Length == 0)
            {
                throw new Exception("Can not use a empty password.");
            }

            int keySize1 = random.GetRandomInt32(5, 16), keySize2 = random.GetRandomInt32(3, 12);
            byte[] key1 = random.GetRandomBytes(keySize1), key2 = random.GetRandomBytes(keySize2);

            byte[] dataHash = CalculateHash(input), completeKey = Combine(key1, key2, password);

            byte[] encrypted = EncryptAES256(input, completeKey);
            int encryptedDataLength = encrypted.Length;

            byte[] newData = Combine
                (
                    dataHash,
                    BitConverter.GetBytes(keySize1), key1,
                    BitConverter.GetBytes(encryptedDataLength), encrypted,
                    BitConverter.GetBytes(keySize2), key2
                );

            int keySize3 = random.GetRandomInt32(5, 10);
            byte[] key3 = random.GetRandomBytes(keySize3);

            newData = EncryptAES256(newData, Combine(password, key3));
            byte[] newEncrypted = Combine(BitConverter.GetBytes(keySize3), key3, newData);

            return newEncrypted;
        }

        public static byte[] Decrypt(byte[] input, byte[] password)
        {
            if (input == null)
            {
                throw new Exception("Can not decrypt null data.");
            }

            if (input.Length == 0)
            {
                throw new Exception("Can not decrypt empty data.");
            }

            if (password == null)
            {
                throw new Exception("Can not use a null password.");
            }

            if (password.Length == 0)
            {
                throw new Exception("Can not use a empty password.");
            }

            try
            {
                int keySize3 = BitConverter.ToInt32(input.Take(4).ToArray(), 0);
                input = input.Skip(4).ToArray();

                byte[] key3 = input.Take(keySize3).ToArray();
                input = input.Skip(keySize3).ToArray();

                byte[] decrypted = DecryptAES256(input, Combine(password, key3));
                input = decrypted;

                byte[] dataHash = input.Take(64).ToArray();
                input = input.Skip(64).ToArray();

                int keySize1 = BitConverter.ToInt32(input.Take(4).ToArray(), 0);
                input = input.Skip(4).ToArray();

                byte[] key1 = input.Take(keySize1).ToArray();
                input = input.Skip(keySize1).ToArray();

                int encryptedDataLength = BitConverter.ToInt32(input.Take(4).ToArray(), 0);
                input = input.Skip(4).ToArray();

                byte[] encryptedData = input.Take(encryptedDataLength).ToArray();
                input = input.Skip(encryptedDataLength).ToArray();

                int keySize2 = BitConverter.ToInt32(input.Take(4).ToArray(), 0);
                input = input.Skip(4).ToArray();

                byte[] key2 = input.Take(keySize2).ToArray();

                byte[] completeKey = Combine(key1, key2, password);
                byte[] decryptedData = DecryptAES256(encryptedData, completeKey);
                byte[] newHash = CalculateHash(decryptedData);

                if (!CompareByteArrays(dataHash, newHash))
                {
                    throw new Exception("Failed to decrypt data.");
                }

                return decryptedData;
            }
            catch
            {
                throw new Exception("Failed to decrypt data.");
            }
        }

        private static byte[] EncryptAES256(byte[] input, byte[] password)
        {
            return SimpleAES.Encrypt(input, SimpleAES.GetSecureKey(password));
        }

        private static byte[] DecryptAES256(byte[] input, byte[] password)
        {
            return SimpleAES.Decrypt(input, SimpleAES.GetSecureKey(password));
        }

        public static byte[] Combine(params byte[][] arrays)
        {
            byte[] ret = new byte[arrays.Sum(x => x.Length)];
            int offset = 0;

            foreach (byte[] data in arrays)
            {
                Buffer.BlockCopy(data, 0, ret, offset, data.Length);
                offset += data.Length;
            }

            return ret;
        }

        private static bool CompareByteArrays(byte[] first, byte[] second)
        {
            if (first.Length != second.Length)
            {
                return false;
            }

            for (int i = 0; i < first.Length; i++)
            {
                if (first[i] != second[i])
                {
                    return false;
                }
            }

            return true;
        }

        private static byte[] CalculateHash(byte[] input)
        {
            return SimpleHashing.SHA3.Keccak.Keccak512.ComputeHash(input);
        }
    }
}