using System.Security.Cryptography;
using System.Text;
using System.Configuration;
using Microsoft.Extensions.Configuration;

namespace encryption_decryption_api.Services;

public class StenographService
{
    public byte[] AES_Encrypt(byte[] bytesToBeEncrypted, byte[] passwordBytes)
    {
        byte[] encryptedBytes = null;

        //En az 8 byte salt dizisi
        byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

        using (MemoryStream ms = new MemoryStream())
        {
            using (RijndaelManaged AES = new RijndaelManaged())
            {
                AES.KeySize = 256;
                AES.BlockSize = 128;

                var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                AES.Key = key.GetBytes(AES.KeySize / 8);
                AES.IV = key.GetBytes(AES.BlockSize / 8);

                AES.Mode = CipherMode.CBC;

                using (var cs = new CryptoStream(ms, AES.CreateEncryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(bytesToBeEncrypted, 0, bytesToBeEncrypted.Length);
                    cs.Close();
                }

                encryptedBytes = ms.ToArray();
            }
        }

        return encryptedBytes;
    }
    public byte[] AES_Decrypt(byte[] bytesToBeDecrypted, byte[] passwordBytes)
    {
        byte[] decryptedBytes = null;

        //En az 8 byte salt dizisi
        byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

        using (MemoryStream ms = new MemoryStream())
        {
            using (RijndaelManaged AES = new RijndaelManaged())
            {
                AES.KeySize = 256;
                AES.BlockSize = 128;

                var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                AES.Key = key.GetBytes(AES.KeySize / 8);
                AES.IV = key.GetBytes(AES.BlockSize / 8);

                AES.Mode = CipherMode.CBC;

                using (var cs = new CryptoStream(ms, AES.CreateDecryptor(), CryptoStreamMode.Write))
                {
                    cs.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
                    cs.Close();
                }

                decryptedBytes = ms.ToArray();
            }
        }

        return decryptedBytes;
    }
    public string EncryptString(string text, string password)
    {
        if (String.IsNullOrEmpty(password))
        {
            password = new ConfigurationBuilder()
                .AddJsonFile("appsettings.json")
                .Build()
                .GetSection("AppSettings")["SecretKey"];
            ;
        }

        byte[] baPwd = Encoding.UTF8.GetBytes(password);

        // şifre SHA256 ile hashleniyor.
        byte[] baPwdHash = SHA256Managed.Create().ComputeHash(baPwd);

        byte[] baText = Encoding.UTF8.GetBytes(text);

        byte[] baSalt = GetRandomBytes();
        byte[] baEncrypted = new byte[baSalt.Length + baText.Length];

        // Salt dizisi ve text dizisi birleştiriliyor.
        for (int i = 0; i < baSalt.Length; i++)
            baEncrypted[i] = baSalt[i];
        for (int i = 0; i < baText.Length; i++)
            baEncrypted[i + baSalt.Length] = baText[i];

        baEncrypted = AES_Encrypt(baEncrypted, baPwdHash);

        string result = Convert.ToBase64String(baEncrypted);
        return result;
    }
    public string DecryptString(string text, string password)
    {
        if (String.IsNullOrEmpty(password))
        {
            password = new ConfigurationBuilder()
                .AddJsonFile("appsettings.json")
                .Build()
                .GetSection("AppSettings")["SecretKey"];
            ;
        }

        byte[] baPwd = Encoding.UTF8.GetBytes(password);

        // şifre SHA256 ile hashleniyor.
        byte[] baPwdHash = SHA256Managed.Create().ComputeHash(baPwd);

        byte[] baText = Convert.FromBase64String(text);

        byte[] baDecrypted = AES_Decrypt(baText, baPwdHash);

        // Salt kaldırılıyor
        int saltLength = GetSaltLength();
        byte[] baResult = new byte[baDecrypted.Length - saltLength];
        for (int i = 0; i < baResult.Length; i++)
            baResult[i] = baDecrypted[i + saltLength];

        string result = Encoding.UTF8.GetString(baResult);
        return result;
    }
    public static byte[] GetRandomBytes()
    {
        int saltLength = GetSaltLength();
        byte[] ba = new byte[saltLength];
        RNGCryptoServiceProvider.Create().GetBytes(ba);
        return ba;
    }
    public static int GetSaltLength()
    {
        return 8;
    }
}