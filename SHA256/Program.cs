using System;
using System.Text;

public class SHA256
{
    private const int kichthuockhoi = 64;
    private const int kichthuocmabam = 64;

    private uint[] H;

    public SHA256()
    {
        // Khởi tạo giá trị hash ban đầu
        H = new uint[]
        {
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
        };
    }

    // Hàm băm chính SHA-256
    public byte[] BamDuLieu(byte[] data)
    {
        byte[] chieudaidulieu = DemDuLieu(data);
        int totalChunks = chieudaidulieu.Length / kichthuockhoi;

        for (int i = 0; i < totalChunks; i++)
        {
            XuLyKhoi(chieudaidulieu, i * kichthuockhoi);
        }

        byte[] ketquabam = new byte[kichthuocmabam];
        for (int i = 0; i < H.Length; i++)
        {
            byte[] hashValueBytes = BitConverter.GetBytes(H[i]);
            Array.Reverse(hashValueBytes);
            Array.Copy(hashValueBytes, 0, ketquabam, i * 4, 4);
        }

        return ketquabam;
    }

    // Thêm Bit và chia dữ liệu thành các khối
    private byte[] DemDuLieu(byte[] data)
    {

        int chieudaibandau = data.Length;
        int chieudaiphandem = kichthuockhoi - (chieudaibandau % kichthuockhoi);
        int chieudaidulieu = chieudaibandau + chieudaiphandem;
        byte[] dulieudadem = new byte[chieudaidulieu];
        Array.Copy(data, dulieudadem, chieudaibandau);
        dulieudadem[chieudaibandau] = 0x80;
        Array.Clear(dulieudadem, chieudaibandau + 1, chieudaiphandem - 1);
        long chieudaibit = (long)chieudaibandau * 8;
        byte[] mangbytedodaibit = BitConverter.GetBytes(chieudaibit);
        Array.Reverse(mangbytedodaibit);
        Array.Copy(mangbytedodaibit, 0, dulieudadem, chieudaidulieu - 8, 8);
        return dulieudadem;
    }

    // Xử lý một khối 512-bit
    private void XuLyKhoi(byte[] data, int chisobatdau)
    {
        uint[] words = new uint[64];
        for (int i = 0; i < 16; i++)
        {
            words[i] = BitConverter.ToUInt32(data, chisobatdau + i * 4);
        }

        for (int i = 16; i < 64; i++)
        {
            uint s0 = XoayPhai(words[i - 15], 7) ^ XoayPhai(words[i - 15], 18) ^ (words[i - 15] >> 3);
            uint s1 = XoayPhai(words[i - 2], 17) ^ XoayPhai(words[i - 2], 19) ^ (words[i - 2] >> 10);
            words[i] = words[i - 16] + s0 + words[i - 7] + s1;
        }

        uint a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];

        for (int i = 0; i < 64; i++)
        {
            uint s1 = XoayPhai(e, 6) ^ XoayPhai(e, 11) ^ XoayPhai(e, 25);
            uint ch = (e & f) ^ (~e & g);
            uint temp1 = h + s1 + ch + K[i] + words[i];
            uint s0 = XoayPhai(a, 2) ^ XoayPhai(a, 13) ^ XoayPhai(a, 22);
            uint maj = (a & b) ^ (a & c) ^ (b & c);
            uint temp2 = s0 + maj;

            h = g;
            g = f;
            f = e;
            e = d + temp1;
            d = c;
            c = b;
            b = a;
            a = temp1 + temp2;
        }

        H[0] += a;
        H[1] += b;
        H[2] += c;
        H[3] += d;
        H[4] += e;
        H[5] += f;
        H[6] += g;
        H[7] += h;
    }

    // Phép xoay phải
    private uint XoayPhai(uint value, int count)
    {
        return (value >> count) | (value << (32 - count));
    }

    // Các hằng số được sử dụng trong SHA-256
    private static readonly uint[] K = new uint[]
    {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };
}

public class Program
{
    public static void Main(string[] args)
    {
        // Chuỗi nhập từ người dùng
        Console.Write("Nhap vao mot chuoi bat ky: ");
        string input = Console.ReadLine();

        // Tính toán giá trị
        SHA256 hasher = new SHA256();
        byte[] hash = hasher.BamDuLieu(Encoding.UTF8.GetBytes(input));

        // In ra giá trị 
        Console.Write("Gia tri SHA-256 hash cua \"{0}\" la: ", input);
        foreach (byte b in hash)
        {
            Console.Write(b.ToString("x2"));
        }
        Console.WriteLine();
    }
}

