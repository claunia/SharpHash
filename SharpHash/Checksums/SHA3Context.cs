//
//  SHA3Context.cs
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

using System.Text;
using System.IO;
using SHA3;
using System;

namespace SharpHash.Checksums
{
    /// <summary>
    /// Provides a UNIX similar API to Mohammad Mahdi Saffari's SHA3.
    /// </summary>
    public class SHA3Context
    {
        SHA3WorkaroundForMono _sha3Provider;

        /// <summary>
        /// Initializes the SHA3 hash provider
        /// </summary>
        public void Init()
        {
            _sha3Provider = new SHA3WorkaroundForMono(512);
        }

        /// <summary>
        /// Updates the hash with data.
        /// </summary>
        /// <param name="data">Data buffer.</param>
        /// <param name="len">Length of buffer to hash.</param>
        public void Update(byte[] data, uint len)
        {
            _sha3Provider.TransformBlock(data, 0, (int)len, data, 0);
        }

        /// <summary>
        /// Updates the hash with data.
        /// </summary>
        /// <param name="data">Data buffer.</param>
        public void Update(byte[] data)
        {
            Update(data, (uint)data.Length);
        }

        /// <summary>
        /// Returns a byte array of the hash value.
        /// </summary>
        public byte[] Final()
        {
            _sha3Provider.WorkaroundTransformFinalBlock(new byte[0], 0, 0);
            return _sha3Provider.Hash;
        }

        /// <summary>
        /// Returns a hexadecimal representation of the hash value.
        /// </summary>
        public string End()
        {
            _sha3Provider.WorkaroundTransformFinalBlock(new byte[0], 0, 0);
            StringBuilder sha3Output = new StringBuilder();

            for (int i = 0; i < _sha3Provider.Hash.Length; i++)
            {
                sha3Output.Append(_sha3Provider.Hash[i].ToString("x2"));
            }

            return sha3Output.ToString();
        }

        /// <summary>
        /// Gets the hash of a file
        /// </summary>
        /// <param name="filename">File path.</param>
        public byte[] File(string filename)
        {
            FileStream fileStream = new FileStream(filename, FileMode.Open);
            return _sha3Provider.ComputeHash(fileStream);
        }

        /// <summary>
        /// Gets the hash of a file in hexadecimal and as a byte array.
        /// </summary>
        /// <param name="filename">File path.</param>
        /// <param name="hash">Byte array of the hash value.</param>
        public string File(string filename, out byte[] hash)
        {
            FileStream fileStream = new FileStream(filename, FileMode.Open);
            hash = _sha3Provider.ComputeHash(fileStream);
            StringBuilder sha3Output = new StringBuilder();

            for (int i = 0; i < hash.Length; i++)
            {
                sha3Output.Append(hash[i].ToString("x2"));
            }

            return sha3Output.ToString();
        }

        /// <summary>
        /// Gets the hash of the specified data buffer.
        /// </summary>
        /// <param name="data">Data buffer.</param>
        /// <param name="len">Length of the data buffer to hash.</param>
        /// <param name="hash">Byte array of the hash value.</param>
        public string Data(byte[] data, uint len, out byte[] hash)
        {
            hash = _sha3Provider.ComputeHash(data, 0, (int)len);
            StringBuilder sha3Output = new StringBuilder();

            for (int i = 0; i < hash.Length; i++)
            {
                sha3Output.Append(hash[i].ToString("x2"));
            }

            return sha3Output.ToString();
        }

        /// <summary>
        /// Gets the hash of the specified data buffer.
        /// </summary>
        /// <param name="data">Data buffer.</param>
        /// <param name="hash">Byte array of the hash value.</param>
        public string Data(byte[] data, out byte[] hash)
        {
            return Data(data, (uint)data.Length, out hash);
        }
    }

    // This is a workaround for Mono
    // Mono calls Initialize() on HashAlgorithm.cs, making SHA3.Hash be null
    // .NET Framework does not
    //
    // This snippet then does detect if running under Mono, if so it is doing
    // the same code, but without that call.
    // Under .NET Framework, just calls base().
    //
    // Following snippet:
    //
    // System.Security.Cryptography.HashAlgorithm.cs
    //
    // Authors:
    //  Matthew S. Ford (Matthew.S.Ford@Rose-Hulman.Edu)
    //  Sebastien Pouliot (sebastien@ximian.com)
    //
    // Copyright 2001 by Matthew S. Ford.
    // Portions (C) 2002 Motus Technologies Inc. (http://www.motus.com)
    // Copyright (C) 2004-2006 Novell, Inc (http://www.novell.com)
    //
    // Permission is hereby granted, free of charge, to any person obtaining
    // a copy of this software and associated documentation files (the
    // "Software"), to deal in the Software without restriction, including
    // without limitation the rights to use, copy, modify, merge, publish,
    // distribute, sublicense, and/or sell copies of the Software, and to
    // permit persons to whom the Software is furnished to do so, subject to
    // the following conditions:
    // 
    // The above copyright notice and this permission notice shall be
    // included in all copies or substantial portions of the Software.
    // 
    // THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
    // EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    // MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
    // NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
    // LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
    // OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
    // WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
    //
    public class SHA3WorkaroundForMono : SHA3Managed
    {
        public SHA3WorkaroundForMono(int hashBitLength) : base (hashBitLength)
        { }

        public byte[] WorkaroundTransformFinalBlock (byte[] inputBuffer, int inputOffset, int inputCount) 
        {
            // Check for Mono
            Type t = Type.GetType ("Mono.Runtime");

            // Not under Mono
            if (t == null)
            {
                return base.TransformFinalBlock(inputBuffer, inputOffset, inputCount);
            }
            // Under Mono
            else
            {
                if (inputBuffer == null)
                    throw new ArgumentNullException("inputBuffer");
                if (inputCount < 0)
                    throw new ArgumentException("inputCount");
                // ordered to avoid possible integer overflow
                if (inputOffset > inputBuffer.Length - inputCount)
                {
                    throw new ArgumentException("inputOffset + inputCount", 
                        "Overflow");
                }

                byte[] outputBuffer = new byte [inputCount];

                // note: other exceptions are handled by Buffer.BlockCopy
                Buffer.BlockCopy(inputBuffer, inputOffset, outputBuffer, 0, inputCount);

                HashCore(inputBuffer, inputOffset, inputCount);
                HashValue = HashFinal();
                // Offending line
                //Initialize ();

                return outputBuffer;
            }
        }
    }
}

