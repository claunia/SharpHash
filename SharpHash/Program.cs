//
//  Program.cs
//
//  Author:
//       Natalia Portillo <claunia@claunia.com>
//
//  Copyright (c) 2015 © Claunia.com
//
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program.  If not, see <http://www.gnu.org/licenses/>.

using System;
using System.Reflection;
using System.IO;
using System.Text;
using System.Diagnostics;

namespace SharpHash
{
    class MainClass
    {
        public static void Main(string[] args)
        {
            object[] attributes = typeof(MainClass).Assembly.GetCustomAttributes(typeof(AssemblyTitleAttribute), false);
            string AssemblyTitle = ((AssemblyTitleAttribute)attributes[0]).Title;
            attributes = typeof(MainClass).Assembly.GetCustomAttributes(typeof(AssemblyCopyrightAttribute), false);
            Version AssemblyVersion = typeof(MainClass).Assembly.GetName().Version;
            string AssemblyCopyright = ((AssemblyCopyrightAttribute)attributes[0]).Copyright;

            Console.WriteLine("{0} {1}", AssemblyTitle, AssemblyVersion);
            Console.WriteLine("{0}", AssemblyCopyright);
            Console.WriteLine();

            if (args.Length != 1)
            {
                Console.WriteLine("Please specify file to hash.");
                return;
            }

            if (!File.Exists(args[0]))
            {
                Console.WriteLine("Specified file cannot be found.");
                return;
            }

            FileStream fileStream = new FileStream(args[0], FileMode.Open, FileAccess.Read);

            const Int64 bufferSize = 131072;
            byte[] dataBuffer;

            Console.WriteLine("Checking for magic's file executable in path");
            bool thereIsMagic;

            try
            {
                Process p = new Process();
                p.StartInfo.UseShellExecute = false;
                p.StartInfo.RedirectStandardOutput = true;
                p.StartInfo.RedirectStandardError = true;
                p.StartInfo.FileName = "file";
                p.Start();
                p.StandardOutput.ReadToEnd();
                p.WaitForExit();

                thereIsMagic = true;
                Console.WriteLine("magic's file found in path");
            }
            catch
            {
                thereIsMagic = false;
                Console.WriteLine("magic's file not found in path");
            }

            string magic = "", applePair = "", mimeType = "", mimeEncoding = "";

            if (thereIsMagic)
            {
                Process magicProcess = new Process();
                magicProcess.StartInfo.UseShellExecute = false;
                magicProcess.StartInfo.RedirectStandardOutput = true;
                magicProcess.StartInfo.RedirectStandardError = true;
                magicProcess.StartInfo.FileName = "file";

                magicProcess.StartInfo.Arguments = "--brief --preserve-date " + args[0];
                magicProcess.Start();
                magic = magicProcess.StandardOutput.ReadToEnd();
                magicProcess.WaitForExit();

                magicProcess.StartInfo.Arguments = "--brief --preserve-date --apple " + args[0];
                magicProcess.Start();
                applePair = magicProcess.StandardOutput.ReadToEnd();
                magicProcess.WaitForExit();

                magicProcess.StartInfo.Arguments = "--brief --preserve-date --mime-type " + args[0];
                magicProcess.Start();
                mimeType = magicProcess.StandardOutput.ReadToEnd();
                magicProcess.WaitForExit();

                magicProcess.StartInfo.Arguments = "--brief --preserve-date --mime-encoding " + args[0];
                magicProcess.Start();
                mimeEncoding = magicProcess.StandardOutput.ReadToEnd();
                magicProcess.WaitForExit();
            }

            Console.WriteLine("Initializing CRC16...");
            Checksums.CRC16Context crc16Context = new Checksums.CRC16Context();
            crc16Context.Init();

            Console.WriteLine("Initializing CRC32...");
            Checksums.CRC32Context crc32Context = new Checksums.CRC32Context();
            crc32Context.Init();

            Console.WriteLine("Initializing CRC64...");
            Checksums.CRC64Context crc64Context = new Checksums.CRC64Context();
            crc64Context.Init();

            Console.WriteLine("Initializing Fletcher-16...");
            Checksums.Fletcher16Context fletcher16Context = new Checksums.Fletcher16Context();
            fletcher16Context.Init();

            Console.WriteLine("Initializing Fletcher-32...");
            Checksums.Fletcher32Context fletcher32Context = new Checksums.Fletcher32Context();
            fletcher32Context.Init();

            Console.WriteLine("Initializing Adler-32...");
            Checksums.Adler32Context adler32Context = new Checksums.Adler32Context();
            adler32Context.Init();

            Console.WriteLine("Initializing MD5...");
            Checksums.MD5Context md5Context = new Checksums.MD5Context();
            md5Context.Init();

            Console.WriteLine("Initializing RIPEMD160...");
            Checksums.RIPEMD160Context ripemd160Context = new Checksums.RIPEMD160Context();
            ripemd160Context.Init();

            Console.WriteLine("Initializing SHA1...");
            Checksums.SHA1Context sha1Context = new Checksums.SHA1Context();
            sha1Context.Init();

            Console.WriteLine("Initializing SHA2-256...");
            Checksums.SHA256Context sha256Context = new Checksums.SHA256Context();
            sha256Context.Init();

            Console.WriteLine("Initializing SHA2-384...");
            Checksums.SHA384Context sha384Context = new Checksums.SHA384Context();
            sha384Context.Init();

            Console.WriteLine("Initializing SHA2-512...");
            Checksums.SHA512Context sha512Context = new Checksums.SHA512Context();
            sha512Context.Init();

//            Console.WriteLine("Initializing SHA3-512...");
//            Checksums.SHA3Context sha3Context = new Checksums.SHA3Context();
//            sha3Context.Init();

            Console.WriteLine("Initializing SpamSum...");
            Checksums.SpamSumContext spamsumContext = new Checksums.SpamSumContext();
            spamsumContext.Init();

            if (fileStream.Length > bufferSize)
            {
                int offset;
                long remainder = fileStream.Length % bufferSize;

                for (offset = 0; offset < (fileStream.Length - remainder); offset += (int)bufferSize)
                {
                    Console.Write("\rHashing offset {0}", offset);
                    dataBuffer = new byte[bufferSize];
                    fileStream.Read(dataBuffer, 0, (int)bufferSize);
                    crc16Context.Update(dataBuffer);
                    crc32Context.Update(dataBuffer);
                    crc64Context.Update(dataBuffer);
                    fletcher16Context.Update(dataBuffer);
                    fletcher32Context.Update(dataBuffer);
                    adler32Context.Update(dataBuffer);
                    md5Context.Update(dataBuffer);
                    ripemd160Context.Update(dataBuffer);
                    sha1Context.Update(dataBuffer);
                    sha256Context.Update(dataBuffer);
                    sha384Context.Update(dataBuffer);
                    sha512Context.Update(dataBuffer);
//                    sha3Context.Update(dataBuffer);
                    spamsumContext.Update(dataBuffer);
                }

                dataBuffer = new byte[remainder];

                fileStream.Read(dataBuffer, 0, (int)remainder);
                crc16Context.Update(dataBuffer);
                crc32Context.Update(dataBuffer);
                crc64Context.Update(dataBuffer);
                fletcher16Context.Update(dataBuffer);
                fletcher32Context.Update(dataBuffer);
                adler32Context.Update(dataBuffer);
                md5Context.Update(dataBuffer);
                ripemd160Context.Update(dataBuffer);
                sha1Context.Update(dataBuffer);
                sha256Context.Update(dataBuffer);
                sha384Context.Update(dataBuffer);
                sha512Context.Update(dataBuffer);
//                sha3Context.Update(dataBuffer);
                spamsumContext.Update(dataBuffer);
            }
            else
            {
                dataBuffer = new byte[fileStream.Length];

                fileStream.Read(dataBuffer, 0, (int)fileStream.Length);
                crc16Context.Update(dataBuffer);
                crc32Context.Update(dataBuffer);
                crc64Context.Update(dataBuffer);
                fletcher16Context.Update(dataBuffer);
                fletcher32Context.Update(dataBuffer);
                adler32Context.Update(dataBuffer);
                md5Context.Update(dataBuffer);
                ripemd160Context.Update(dataBuffer);
                sha1Context.Update(dataBuffer);
                sha256Context.Update(dataBuffer);
                sha384Context.Update(dataBuffer);
                sha512Context.Update(dataBuffer);
//                sha3Context.Update(dataBuffer);
                spamsumContext.Update(dataBuffer);
            }

            byte[] crc16Hash = crc16Context.Final();
            byte[] crc32Hash = crc32Context.Final();
            byte[] crc64Hash = crc64Context.Final();
            byte[] fletcher16Hash = fletcher16Context.Final();
            byte[] fletcher32Hash = fletcher32Context.Final();
            byte[] adler32Hash = adler32Context.Final();
            byte[] md5Hash = md5Context.Final();
            byte[] ripemd160Hash = ripemd160Context.Final();
            byte[] sha1Hash = sha1Context.Final();
            byte[] sha256Hash = sha256Context.Final();
            byte[] sha384Hash = sha384Context.Final();
            byte[] sha512Hash = sha512Context.Final();
//            byte[] sha3Hash = sha3Context.Final();
            string spamsumHash = spamsumContext.End();

            Console.WriteLine();
            Console.WriteLine();
            if (thereIsMagic)
            {
                Console.Write("magic's Description = {0}", magic);
                Console.Write("Apple OSType Pair = {0}", applePair);
                Console.Write("MIME Type = {0}", mimeType);
                Console.Write("MIME Encoding = {0}", mimeEncoding);
                Console.WriteLine();
            }
            Console.WriteLine("CRC16: {0}", stringify(crc16Hash));
            Console.WriteLine("CRC32: {0}", stringify(crc32Hash));
            Console.WriteLine("CRC64: {0}", stringify(crc64Hash));
            Console.WriteLine("Fletcher-16: {0}", stringify(fletcher16Hash));
            Console.WriteLine("Fletcher-32: {0}", stringify(fletcher32Hash));
            Console.WriteLine("Adler-32: {0}", stringify(adler32Hash));
            Console.WriteLine("MD5: {0}", stringify(md5Hash));
            Console.WriteLine("RIPEMD160: {0}", stringify(ripemd160Hash));
            Console.WriteLine("SHA1: {0}", stringify(sha1Hash));
            Console.WriteLine("SHA2-256: {0}", stringify(sha256Hash));
            Console.WriteLine("SHA2-384: {0}", stringify(sha384Hash));
            Console.WriteLine("SHA2-512: {0}", stringify(sha512Hash));
//            Console.WriteLine("SHA3-512: {0}", stringify(sha3Hash));
            Console.WriteLine("SpamSum: {0}", spamsumHash);

            fileStream.Close();
        }

        static string stringify(byte[] hash)
        {
            StringBuilder hashOutput = new StringBuilder();

            for (int i = 0; i < hash.Length; i++)
            {
                hashOutput.Append(hash[i].ToString("x2"));
            }

            return hashOutput.ToString();
        }
    }
}
