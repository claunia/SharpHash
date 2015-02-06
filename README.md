SharpHash v1.00
===============

Implements UNIX style to .NET Framework hashing algorithms, and some other hash/checksum algorithms purely in managed code.

Copyright © 2015 Natalia Portillo <claunia@claunia.com>

Uses code from other project, copyright and license in their respective source files.

Usage
=====

SharpHash.exe <filename>

Features
========

* Calculates MD5, RIPEMD160, SHA1, SHA2-256, SHA2-384 and SHA2-512 using .NET Framework classes.
* Calculates CRC16-IBM (same as old archivers), CRC32-ANSI (same as Zip) and CRC64-ECMA (same as Xz) using entirely managed code, without static tables.
* Calculates Adler-32, Fletcher-16 and Fletcher-32 using entirely managed code.
* Calculates SpamSum (fuzzy hashing, from ssdeep), using entirely managed code manually converted from ssdeep's C source.
* Calculates SHA3-512 using jdluzen's library
* And if file (from magic) is found in path, uses it to get a format description, Apple CREATOR/TYPE OSType pair, MIME type and MIME encoding.

To-Do
=====

See TODO file.
