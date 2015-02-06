//
//  XmlHash.cs
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
using System.IO;

namespace SharpHash
{
    public struct FileHash
    {
        /// <summary>
        /// File attributes
        /// </summary>
        public FileAttributes attributes;
        /// <summary>
        /// File creation time (UTC)
        /// </summary>
        public DateTime ctime;
        /// <summary>
        /// File last access time (UTC)
        /// </summary>
        public DateTime atime;
        /// <summary>
        /// File last modification time (UTC)
        /// </summary>
        public DateTime mtime;
        /// <summary>
        /// File path
        /// </summary>
        public string path;
        /// <summary>
        /// Filename
        /// </summary>
        public string name;
        /// <summary>
        /// File length
        /// </summary>
        public long length;
        /// <summary>
        /// File Adler32 checksum
        /// </summary>
        public byte[] adler32;
        /// <summary>
        /// File CRC16 checksum
        /// </summary>
        public byte[] crc16;
        /// <summary>
        /// File CRC32 checksum
        /// </summary>
        public byte[] crc32;
        /// <summary>
        /// File CRC64 checksum
        /// </summary>
        public byte[] crc64;
        /// <summary>
        /// File Fletcher-16 checksum
        /// </summary>
        public byte[] fletcher16;
        /// <summary>
        /// File Fletcher-32 checksum
        /// </summary>
        public byte[] fletcher32;
        /// <summary>
        /// File MD5 hash
        /// </summary>
        public byte[] md5;
        /// <summary>
        /// File RIPEMD160 hash
        /// </summary>
        public byte[] ripemd160;
        /// <summary>
        /// File SHA1 hash
        /// </summary>
        public byte[] sha1;
        /// <summary>
        /// File SHA2-256 hash
        /// </summary>
        public byte[] sha256;
        /// <summary>
        /// File SHA2-384 hash
        /// </summary>
        public byte[] sha384;
        /// <summary>
        /// File SHA2-512 hash
        /// </summary>
        public byte[] sha512;
        /// <summary>
        /// File SHA3-512 hash
        /// </summary>
        public byte[] sha3;
        /// <summary>
        /// File SpamSum hash
        /// </summary>
        public string spamsum;
        /// <summary>
        /// Description given by libmagic
        /// </summary>
        public string magic;
        /// <summary>
        /// Apple OSType pair given by libmagic
        /// </summary>
        public string applePair;
        /// <summary>
        /// MIME type given by libmagic
        /// </summary>
        public string mimeType;
        /// <summary>
        /// MIME encoding given by libmagic
        /// </summary>
        public string mimeEncoding;
    }
}

