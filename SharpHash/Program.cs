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
using System.Threading;

namespace SharpHash
{
    class MainClass
    {
        public static void Main(string[] args)
        {
            // Gets assembly information to create application output header
            object[] attributes = typeof(MainClass).Assembly.GetCustomAttributes(typeof(AssemblyTitleAttribute), false);
            string AssemblyTitle = ((AssemblyTitleAttribute)attributes[0]).Title;
            attributes = typeof(MainClass).Assembly.GetCustomAttributes(typeof(AssemblyCopyrightAttribute), false);
            Version AssemblyVersion = typeof(MainClass).Assembly.GetName().Version;
            string AssemblyCopyright = ((AssemblyCopyrightAttribute)attributes[0]).Copyright;

            Console.WriteLine("{0} {1}", AssemblyTitle, AssemblyVersion);
            Console.WriteLine("{0}", AssemblyCopyright);
            Console.WriteLine();

            string filename;
            bool outputXml;

            // Checks arguments
            if (args.Length == 2 && args[0] == "--xml")
            {
                filename = args[1];
                outputXml = true;
            }
            else if (args.Length != 1)
            {
                Console.WriteLine("Please specify file to hash.");
                return;
            }
            else
                filename = args[0];

            if (!File.Exists(filename))
            {
                Console.WriteLine("Specified file cannot be found.");
                return;
            }

            FileStream fileStream = new FileStream(filename, FileMode.Open, FileAccess.Read);
            FileInfo fi = new FileInfo(filename);

            FileHash fh = new FileHash();

            // Gets filesystem information
            fh.atime = fi.LastAccessTimeUtc;
            fh.attributes = fi.Attributes;
            fh.ctime = fi.CreationTimeUtc;
            fh.length = fi.Length;
            fh.mtime = fi.LastWriteTimeUtc;
            fh.name = fi.Name;
            fh.path = Path.GetDirectoryName(fi.FullName);

            // Sets a 128Kbyte buffer
            const Int64 bufferSize = 131072;
            byte[] dataBuffer = new byte[bufferSize];

            Console.WriteLine("Checking for magic's file executable in path");
            bool thereIsMagic;

            // Try's to execute "file", to see if magic is installed in path
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

            // If it is installed, calls it to get information about file
            if (thereIsMagic)
            {
                Process magicProcess = new Process();
                magicProcess.StartInfo.UseShellExecute = false;
                magicProcess.StartInfo.RedirectStandardOutput = true;
                magicProcess.StartInfo.RedirectStandardError = true;
                magicProcess.StartInfo.FileName = "file";

                magicProcess.StartInfo.Arguments = "--brief --preserve-date " + filename;
                magicProcess.Start();
                fh.magic = correctTrailingNewLine(magicProcess.StandardOutput.ReadToEnd());
                magicProcess.WaitForExit();

                magicProcess.StartInfo.Arguments = "--brief --preserve-date --apple " + filename;
                magicProcess.Start();
                fh.applePair = correctTrailingNewLine(magicProcess.StandardOutput.ReadToEnd());
                magicProcess.WaitForExit();

                magicProcess.StartInfo.Arguments = "--brief --preserve-date --mime-type " + filename;
                magicProcess.Start();
                fh.mimeType = correctTrailingNewLine(magicProcess.StandardOutput.ReadToEnd());
                magicProcess.WaitForExit();

                magicProcess.StartInfo.Arguments = "--brief --preserve-date --mime-encoding " + filename;
                magicProcess.Start();
                fh.mimeEncoding = correctTrailingNewLine(magicProcess.StandardOutput.ReadToEnd());
                magicProcess.WaitForExit();
            }

            // Threads
            Thread tCRC16;
            Thread tCRC32;
            Thread tCRC64;
            Thread tFletcher16;
            Thread tFletcher32;
            Thread tAdler32;
            Thread tMD5;
            Thread tRIPEMD160;
            Thread tSHA1;
            Thread tSHA256;
            Thread tSHA384;
            Thread tSHA512;
            Thread tSHA3;
            Thread tSpamSum;

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

            Console.WriteLine("Initializing SHA3-512...");
            Checksums.SHA3Context sha3Context = new Checksums.SHA3Context();
            sha3Context.Init();

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

                    // Initialize a thread per algorithm
                    // TODO: Is there a way to reuse the threads? Start() fails if called more than one time
                    tCRC16 = new Thread(() => crc16Context.Update(dataBuffer));
                    tCRC16.IsBackground = true;
                    tCRC16.Name = "CRC16";

                    tCRC32 = new Thread(() => crc32Context.Update(dataBuffer));
                    tCRC32.IsBackground = true;
                    tCRC32.Name = "CRC32";

                    tCRC64 = new Thread(() => crc64Context.Update(dataBuffer));
                    tCRC64.IsBackground = true;
                    tCRC64.Name = "CRC64";

                    tFletcher16 = new Thread(() => fletcher16Context.Update(dataBuffer));
                    tFletcher16.IsBackground = true;
                    tFletcher16.Name = "Fletcher-16";

                    tFletcher32 = new Thread(() => fletcher32Context.Update(dataBuffer));
                    tFletcher32.IsBackground = true;
                    tFletcher32.Name = "Fletcher-32";

                    tAdler32 = new Thread(() => adler32Context.Update(dataBuffer));
                    tAdler32.IsBackground = true;
                    tAdler32.Name = "Adler-32";

                    tMD5 = new Thread(() => md5Context.Update(dataBuffer));
                    tMD5.IsBackground = true;
                    tMD5.Name = "MD5";

                    tRIPEMD160 = new Thread(() => ripemd160Context.Update(dataBuffer));
                    tRIPEMD160.IsBackground = true;
                    tRIPEMD160.Name = "RIPEMD160";

                    tSHA1 = new Thread(() => sha1Context.Update(dataBuffer));
                    tSHA1.IsBackground = true;
                    tSHA1.Name = "SHA1";

                    tSHA256 = new Thread(() => sha256Context.Update(dataBuffer));
                    tSHA256.IsBackground = true;
                    tSHA256.Name = "SHA256";

                    tSHA384 = new Thread(() => sha384Context.Update(dataBuffer));
                    tSHA384.IsBackground = true;
                    tSHA384.Name = "SHA384";

                    tSHA512 = new Thread(() => sha512Context.Update(dataBuffer));
                    tSHA512.IsBackground = true;
                    tSHA512.Name = "SHA512";

                    tSHA3 = new Thread(() => sha3Context.Update(dataBuffer));
                    tSHA3.IsBackground = true;
                    tSHA3.Name = "SHA3";

                    tSpamSum = new Thread(() => spamsumContext.Update(dataBuffer));
                    tSpamSum.IsBackground = true;
                    tSpamSum.Name = "SpamSum";

                    // Start all algorithms
                    tCRC16.Start();
                    tCRC32.Start();
                    tCRC64.Start();
                    tFletcher16.Start();
                    tFletcher32.Start();
                    tAdler32.Start();
                    tMD5.Start();
                    tRIPEMD160.Start();
                    tSHA1.Start();
                    tSHA256.Start();
                    tSHA384.Start();
                    tSHA512.Start();
                    tSHA3.Start();
                    tSpamSum.Start();

                    // Wait until all have finished
                    while (tCRC16.IsAlive || tCRC32.IsAlive || tCRC64.IsAlive ||
                        tFletcher16.IsAlive || tFletcher32.IsAlive || tAdler32.IsAlive ||
                        tMD5.IsAlive || tRIPEMD160.IsAlive || tSHA1.IsAlive ||
                        tSHA256.IsAlive || tSHA384.IsAlive || tSHA512.IsAlive ||
                        tSHA3.IsAlive || tSpamSum.IsAlive);
                }

                dataBuffer = new byte[remainder];

                // Initialize a thread per algorithm
                // TODO: Is there a way to reuse the threads? Start() fails if called more than one time
                tCRC16 = new Thread(() => crc16Context.Update(dataBuffer));
                tCRC16.IsBackground = true;
                tCRC16.Name = "CRC16";

                tCRC32 = new Thread(() => crc32Context.Update(dataBuffer));
                tCRC32.IsBackground = true;
                tCRC32.Name = "CRC32";

                tCRC64 = new Thread(() => crc64Context.Update(dataBuffer));
                tCRC64.IsBackground = true;
                tCRC64.Name = "CRC64";

                tFletcher16 = new Thread(() => fletcher16Context.Update(dataBuffer));
                tFletcher16.IsBackground = true;
                tFletcher16.Name = "Fletcher-16";

                tFletcher32 = new Thread(() => fletcher32Context.Update(dataBuffer));
                tFletcher32.IsBackground = true;
                tFletcher32.Name = "Fletcher-32";

                tAdler32 = new Thread(() => adler32Context.Update(dataBuffer));
                tAdler32.IsBackground = true;
                tAdler32.Name = "Adler-32";

                tMD5 = new Thread(() => md5Context.Update(dataBuffer));
                tMD5.IsBackground = true;
                tMD5.Name = "MD5";

                tRIPEMD160 = new Thread(() => ripemd160Context.Update(dataBuffer));
                tRIPEMD160.IsBackground = true;
                tRIPEMD160.Name = "RIPEMD160";

                tSHA1 = new Thread(() => sha1Context.Update(dataBuffer));
                tSHA1.IsBackground = true;
                tSHA1.Name = "SHA1";

                tSHA256 = new Thread(() => sha256Context.Update(dataBuffer));
                tSHA256.IsBackground = true;
                tSHA256.Name = "SHA256";

                tSHA384 = new Thread(() => sha384Context.Update(dataBuffer));
                tSHA384.IsBackground = true;
                tSHA384.Name = "SHA384";

                tSHA512 = new Thread(() => sha512Context.Update(dataBuffer));
                tSHA512.IsBackground = true;
                tSHA512.Name = "SHA512";

                tSHA3 = new Thread(() => sha3Context.Update(dataBuffer));
                tSHA3.IsBackground = true;
                tSHA3.Name = "SHA3";

                tSpamSum = new Thread(() => spamsumContext.Update(dataBuffer));
                tSpamSum.IsBackground = true;
                tSpamSum.Name = "SpamSum";

                // Start all algorithms
                tCRC16.Start();
                tCRC32.Start();
                tCRC64.Start();
                tFletcher16.Start();
                tFletcher32.Start();
                tAdler32.Start();
                tMD5.Start();
                tRIPEMD160.Start();
                tSHA1.Start();
                tSHA256.Start();
                tSHA384.Start();
                tSHA512.Start();
                tSHA3.Start();
                tSpamSum.Start();

                // Wait until all have finished
                while (tCRC16.IsAlive || tCRC32.IsAlive || tCRC64.IsAlive ||
                    tFletcher16.IsAlive || tFletcher32.IsAlive || tAdler32.IsAlive ||
                    tMD5.IsAlive || tRIPEMD160.IsAlive || tSHA1.IsAlive ||
                    tSHA256.IsAlive || tSHA384.IsAlive || tSHA512.IsAlive ||
                    tSHA3.IsAlive || tSpamSum.IsAlive);
            }
            else
            {
                dataBuffer = new byte[fileStream.Length];

                fileStream.Read(dataBuffer, 0, (int)fileStream.Length);

                // Initialize a thread per algorithm
                // TODO: Is there a way to reuse the threads? Start() fails if called more than one time
                tCRC16 = new Thread(() => crc16Context.Update(dataBuffer));
                tCRC16.IsBackground = true;
                tCRC16.Name = "CRC16";

                tCRC32 = new Thread(() => crc32Context.Update(dataBuffer));
                tCRC32.IsBackground = true;
                tCRC32.Name = "CRC32";

                tCRC64 = new Thread(() => crc64Context.Update(dataBuffer));
                tCRC64.IsBackground = true;
                tCRC64.Name = "CRC64";

                tFletcher16 = new Thread(() => fletcher16Context.Update(dataBuffer));
                tFletcher16.IsBackground = true;
                tFletcher16.Name = "Fletcher-16";

                tFletcher32 = new Thread(() => fletcher32Context.Update(dataBuffer));
                tFletcher32.IsBackground = true;
                tFletcher32.Name = "Fletcher-32";

                tAdler32 = new Thread(() => adler32Context.Update(dataBuffer));
                tAdler32.IsBackground = true;
                tAdler32.Name = "Adler-32";

                tMD5 = new Thread(() => md5Context.Update(dataBuffer));
                tMD5.IsBackground = true;
                tMD5.Name = "MD5";

                tRIPEMD160 = new Thread(() => ripemd160Context.Update(dataBuffer));
                tRIPEMD160.IsBackground = true;
                tRIPEMD160.Name = "RIPEMD160";

                tSHA1 = new Thread(() => sha1Context.Update(dataBuffer));
                tSHA1.IsBackground = true;
                tSHA1.Name = "SHA1";

                tSHA256 = new Thread(() => sha256Context.Update(dataBuffer));
                tSHA256.IsBackground = true;
                tSHA256.Name = "SHA256";

                tSHA384 = new Thread(() => sha384Context.Update(dataBuffer));
                tSHA384.IsBackground = true;
                tSHA384.Name = "SHA384";

                tSHA512 = new Thread(() => sha512Context.Update(dataBuffer));
                tSHA512.IsBackground = true;
                tSHA512.Name = "SHA512";

                tSHA3 = new Thread(() => sha3Context.Update(dataBuffer));
                tSHA3.IsBackground = true;
                tSHA3.Name = "SHA3";

                tSpamSum = new Thread(() => spamsumContext.Update(dataBuffer));
                tSpamSum.IsBackground = true;
                tSpamSum.Name = "SpamSum";

                // Start all algorithms
                tCRC16.Start();
                tCRC32.Start();
                tCRC64.Start();
                tFletcher16.Start();
                tFletcher32.Start();
                tAdler32.Start();
                tMD5.Start();
                tRIPEMD160.Start();
                tSHA1.Start();
                tSHA256.Start();
                tSHA384.Start();
                tSHA512.Start();
                tSHA3.Start();
                tSpamSum.Start();

                // Wait until all have finished
                while (tCRC16.IsAlive || tCRC32.IsAlive || tCRC64.IsAlive ||
                    tFletcher16.IsAlive || tFletcher32.IsAlive || tAdler32.IsAlive ||
                    tMD5.IsAlive || tRIPEMD160.IsAlive || tSHA1.IsAlive ||
                    tSHA256.IsAlive || tSHA384.IsAlive || tSHA512.IsAlive ||
                    tSHA3.IsAlive || tSpamSum.IsAlive);
            }

            // Close the file asap
            fileStream.Close();

            // Gets final step of algorithms
            fh.crc16 = crc16Context.Final();
            fh.crc32 = crc32Context.Final();
            fh.crc64 = crc64Context.Final();
            fh.fletcher16 = fletcher16Context.Final();
            fh.fletcher32 = fletcher32Context.Final();
            fh.adler32 = adler32Context.Final();
            fh.md5 = md5Context.Final();
            fh.ripemd160 = ripemd160Context.Final();
            fh.sha1 = sha1Context.Final();
            fh.sha256 = sha256Context.Final();
            fh.sha384 = sha384Context.Final();
            fh.sha512 = sha512Context.Final();
            fh.sha3 = sha3Context.Final();
            fh.spamsum = spamsumContext.End();

            // If first argument is "--xml", outputs XML of information to stdout
            if (outputXml)
            {
                Console.WriteLine();
                System.Xml.Serialization.XmlSerializer fhSerializer = new System.Xml.Serialization.XmlSerializer(fh.GetType());
                fhSerializer.Serialize(Console.Out, fh);
                Console.WriteLine();
            }
            // If not, use a human output
            else
            {
                Console.WriteLine();
                Console.WriteLine();
                Console.WriteLine("File name: {0}", fh.name);
                Console.WriteLine("File path: {0}", fh.path);
                Console.WriteLine("File length: {0}", fh.length);
                Console.WriteLine("File attributes: {0}", fh.attributes);
                Console.WriteLine("File creation time: {0}", fh.ctime);
                Console.WriteLine("File last modification time: {0}", fh.mtime);
                Console.WriteLine("File last access time: {0}", fh.atime);
                if (thereIsMagic)
                {
                    Console.WriteLine("magic's Description = {0}", fh.magic);
                    Console.WriteLine("Apple OSType Pair = {0}", fh.applePair);
                    Console.WriteLine("MIME Type = {0}", fh.mimeType);
                    Console.WriteLine("MIME Encoding = {0}", fh.mimeEncoding);
                }
                Console.WriteLine("CRC16: {0}", stringify(fh.crc16));
                Console.WriteLine("CRC32: {0}", stringify(fh.crc32));
                Console.WriteLine("CRC64: {0}", stringify(fh.crc64));
                Console.WriteLine("Fletcher-16: {0}", stringify(fh.fletcher16));
                Console.WriteLine("Fletcher-32: {0}", stringify(fh.fletcher32));
                Console.WriteLine("Adler-32: {0}", stringify(fh.adler32));
                Console.WriteLine("MD5: {0}", stringify(fh.md5));
                Console.WriteLine("RIPEMD160: {0}", stringify(fh.ripemd160));
                Console.WriteLine("SHA1: {0}", stringify(fh.sha1));
                Console.WriteLine("SHA2-256: {0}", stringify(fh.sha256));
                Console.WriteLine("SHA2-384: {0}", stringify(fh.sha384));
                Console.WriteLine("SHA2-512: {0}", stringify(fh.sha512));
                Console.WriteLine("SHA3-512: {0}", stringify(fh.sha3));
                Console.WriteLine("SpamSum: {0}", fh.spamsum);
            }
        }

        /// <summary>
        /// Returns a hexadecimal representation, lowercase, of a byte array. Endian agnostic, translates byte-by-byte
        /// </summary>
        /// <param name="hash">Hash.</param>
        static string stringify(byte[] hash)
        {
            StringBuilder hashOutput = new StringBuilder();

            for (int i = 0; i < hash.Length; i++)
            {
                hashOutput.Append(hash[i].ToString("x2"));
            }

            return hashOutput.ToString();
        }

        /// <summary>
        /// Remove trailing new lines (Mac, Win, UNIX and Acorn formats) from a string, as magic stdout are trailed.
        /// </summary>
        /// <returns>Corrected string. Null if original string is onle a newline</returns>
        /// <param name="uglyString">String that may have a trailing newline</param>
        static string correctTrailingNewLine(string uglyString)
        {
            byte[] uglyBytes = Encoding.UTF8.GetBytes(uglyString);
            byte[] prettyBytes;

            if (uglyBytes == null)
                return null;

            if (uglyBytes.Length == 0)
                return null;

            if (uglyBytes[uglyBytes.Length - 1] == 0x0A || uglyBytes[uglyBytes.Length - 1] == 0x0D)
            {
                if (uglyBytes.Length == 1)
                    return null;

                if (uglyBytes.Length >= 2)
                {
                    if ((uglyBytes[uglyBytes.Length - 1] == 0x0A && uglyBytes[uglyBytes.Length - 2] == 0x0D) ||
                       (uglyBytes[uglyBytes.Length - 2] == 0x0A && uglyBytes[uglyBytes.Length - 1] == 0x0D))
                    {
                        if (uglyBytes.Length == 2)
                            return null;

                        prettyBytes = new byte[uglyBytes.Length - 2];
                        Array.Copy(uglyBytes, 0, prettyBytes, 0, uglyBytes.Length - 2);
                        return Encoding.UTF8.GetString(prettyBytes);
                    }
                }

                prettyBytes = new byte[uglyBytes.Length - 1];
                Array.Copy(uglyBytes, 0, prettyBytes, 0, uglyBytes.Length - 1);
                return Encoding.UTF8.GetString(prettyBytes);
            }

            return uglyString;
        }
    }
}
