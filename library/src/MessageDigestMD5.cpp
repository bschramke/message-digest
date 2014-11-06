/**
 * @file MessageDigestMD5.cpp
 *
 * Copyright (c) 2014 Björn Schramke. All rights reserved.
 *
 * SPDX-License-Identifier: BSL-1.0
 *
 * based on:
 * md5.h and md5.c
 * from hash-library by Stephan Brume
 * (http://create.stephan-brumme.com/hash-library)
 *
 * Copyright (c) 2014 Stephan Brumme. All rights reserved.
 * see http://create.stephan-brumme.com/disclaimer.html
 *
 */

#include "MessageDigest/MessageDigestMD5.hpp"
#include "MessageDigest/MessageDigest.hpp"

#include <iostream>

// big endian architectures need #define __BYTE_ORDER __BIG_ENDIAN
#ifndef _MSC_VER
#include <endian.h>
#endif

static MessageDigestImplRegistrar<MessageDigestMD5> registrar("MD5");

namespace
{
  // mix functions for processBlock()
  inline uint32_t f1(uint32_t b, uint32_t c, uint32_t d)
  {
    return d ^ (b & (c ^ d)); // original: f = (b & c) | ((~b) & d);
  }

  inline uint32_t f2(uint32_t b, uint32_t c, uint32_t d)
  {
    return c ^ (d & (b ^ c)); // original: f = (b & d) | (c & (~d));
  }

  inline uint32_t f3(uint32_t b, uint32_t c, uint32_t d)
  {
    return b ^ c ^ d;
  }

  inline uint32_t f4(uint32_t b, uint32_t c, uint32_t d)
  {
    return c ^ (b | ~d);
  }

  inline uint32_t rotate(uint32_t a, uint32_t c)
  {
    return (a << c) | (a >> (32 - c));
  }
}

MessageDigestMD5::MessageDigestMD5()
{
  reset();
}

std::string MessageDigestMD5::getAlgorithm() const
{
  return "MD5";
}

void MessageDigestMD5::reset()
{
  _numBytes   = 0;
  _bufferSize = 0;

  // according to RFC 1321 section 3.3
  _hash[0] = 0x67452301;
  _hash[1] = 0xefcdab89;
  _hash[2] = 0x98badcfe;
  _hash[3] = 0x10325476;
}

std::unique_ptr<MessageDigestImpl> MessageDigestMD5::create()
{
  return std::unique_ptr<MessageDigestImpl>(new MessageDigestMD5());
}

std::string MessageDigestMD5::digest()
{
  // convert hash to string
  static const char dec2hex[16+1] = "0123456789abcdef";

  // save old hash if buffer is partially filled
  uint32_t oldHash[4];
  oldHash[0] = _hash[0];
  oldHash[1] = _hash[1];
  oldHash[2] = _hash[2];
  oldHash[3] = _hash[3];

  // process remaining bytes
  processBuffer();

  // create hash string
  char hashBuffer[HASH_SIZE*8+1];
  size_t offset = 0;
  for (int i = 0; i < HASH_SIZE; i++)
  {
    hashBuffer[offset++] = dec2hex[(_hash[i] >>  4) & 15];
    hashBuffer[offset++] = dec2hex[ _hash[i]        & 15];
    hashBuffer[offset++] = dec2hex[(_hash[i] >> 12) & 15];
    hashBuffer[offset++] = dec2hex[(_hash[i] >>  8) & 15];
    hashBuffer[offset++] = dec2hex[(_hash[i] >> 20) & 15];
    hashBuffer[offset++] = dec2hex[(_hash[i] >> 16) & 15];
    hashBuffer[offset++] = dec2hex[(_hash[i] >> 28) & 15];
    hashBuffer[offset++] = dec2hex[(_hash[i] >> 24) & 15];
  }

  // zero-terminated string
  hashBuffer[offset] = 0;

  // restore old hash
  _hash[0] = oldHash[0];
  _hash[1] = oldHash[1];
  _hash[2] = oldHash[2];
  _hash[3] = oldHash[3];

  return hashBuffer;
}

void MessageDigestMD5::update(const void *data, const size_t offset, const size_t len)
{
  const uint8_t* current = (const uint8_t*) data + offset;
  size_t numBytes = len;

  if (_bufferSize > 0)
  {
    while (numBytes > 0 && _bufferSize < BLOCK_SIZE)
    {
      _buffer[_bufferSize++] = *current++;
      numBytes--;
    }
  }

  // full buffer
  if (_bufferSize == BLOCK_SIZE)
  {
    processBlock(_buffer);
    _numBytes  += BLOCK_SIZE;
    _bufferSize = 0;
  }

  // no more data ?
  if (numBytes == 0)
    return;

  // process full blocks
  while (numBytes >= BLOCK_SIZE)
  {
    processBlock(current);
    current    += BLOCK_SIZE;
    _numBytes += BLOCK_SIZE;
    numBytes   -= BLOCK_SIZE;
  }

  // keep remaining bytes in buffer
  while (numBytes > 0)
  {
    _buffer[_bufferSize++] = *current++;
    numBytes--;
  }
}

void MessageDigestMD5::processBlock(const void *data)
{
  // get last hash
  uint32_t a = _hash[0];
  uint32_t b = _hash[1];
  uint32_t c = _hash[2];
  uint32_t d = _hash[3];

  // data represented as 16x 32-bit words
  const uint32_t* words = (uint32_t*) data;

  // first round
  a = rotate(a + f1(b,c,d) + words[0]  + 0xd76aa478,  7) + b;
  d = rotate(d + f1(a,b,c) + words[1]  + 0xe8c7b756, 12) + a;
  c = rotate(c + f1(d,a,b) + words[2]  + 0x242070db, 17) + d;
  b = rotate(b + f1(c,d,a) + words[3]  + 0xc1bdceee, 22) + c;

  a = rotate(a + f1(b,c,d) + words[4]  + 0xf57c0faf,  7) + b;
  d = rotate(d + f1(a,b,c) + words[5]  + 0x4787c62a, 12) + a;
  c = rotate(c + f1(d,a,b) + words[6]  + 0xa8304613, 17) + d;
  b = rotate(b + f1(c,d,a) + words[7]  + 0xfd469501, 22) + c;

  a = rotate(a + f1(b,c,d) + words[8]  + 0x698098d8,  7) + b;
  d = rotate(d + f1(a,b,c) + words[9]  + 0x8b44f7af, 12) + a;
  c = rotate(c + f1(d,a,b) + words[10] + 0xffff5bb1, 17) + d;
  b = rotate(b + f1(c,d,a) + words[11] + 0x895cd7be, 22) + c;

  a = rotate(a + f1(b,c,d) + words[12] + 0x6b901122,  7) + b;
  d = rotate(d + f1(a,b,c) + words[13] + 0xfd987193, 12) + a;
  c = rotate(c + f1(d,a,b) + words[14] + 0xa679438e, 17) + d;
  b = rotate(b + f1(c,d,a) + words[15] + 0x49b40821, 22) + c;

  // second round
  a = rotate(a + f2(b,c,d) + words[1]  + 0xf61e2562,  5) + b;
  d = rotate(d + f2(a,b,c) + words[6]  + 0xc040b340,  9) + a;
  c = rotate(c + f2(d,a,b) + words[11] + 0x265e5a51, 14) + d;
  b = rotate(b + f2(c,d,a) + words[0]  + 0xe9b6c7aa, 20) + c;

  a = rotate(a + f2(b,c,d) + words[5]  + 0xd62f105d,  5) + b;
  d = rotate(d + f2(a,b,c) + words[10] + 0x02441453,  9) + a;
  c = rotate(c + f2(d,a,b) + words[15] + 0xd8a1e681, 14) + d;
  b = rotate(b + f2(c,d,a) + words[4]  + 0xe7d3fbc8, 20) + c;

  a = rotate(a + f2(b,c,d) + words[9]  + 0x21e1cde6,  5) + b;
  d = rotate(d + f2(a,b,c) + words[14] + 0xc33707d6,  9) + a;
  c = rotate(c + f2(d,a,b) + words[3]  + 0xf4d50d87, 14) + d;
  b = rotate(b + f2(c,d,a) + words[8]  + 0x455a14ed, 20) + c;

  a = rotate(a + f2(b,c,d) + words[13] + 0xa9e3e905,  5) + b;
  d = rotate(d + f2(a,b,c) + words[2]  + 0xfcefa3f8,  9) + a;
  c = rotate(c + f2(d,a,b) + words[7]  + 0x676f02d9, 14) + d;
  b = rotate(b + f2(c,d,a) + words[12] + 0x8d2a4c8a, 20) + c;

  // third round
  a = rotate(a + f3(b,c,d) + words[5]  + 0xfffa3942,  4) + b;
  d = rotate(d + f3(a,b,c) + words[8]  + 0x8771f681, 11) + a;
  c = rotate(c + f3(d,a,b) + words[11] + 0x6d9d6122, 16) + d;
  b = rotate(b + f3(c,d,a) + words[14] + 0xfde5380c, 23) + c;

  a = rotate(a + f3(b,c,d) + words[1]  + 0xa4beea44,  4) + b;
  d = rotate(d + f3(a,b,c) + words[4]  + 0x4bdecfa9, 11) + a;
  c = rotate(c + f3(d,a,b) + words[7]  + 0xf6bb4b60, 16) + d;
  b = rotate(b + f3(c,d,a) + words[10] + 0xbebfbc70, 23) + c;

  a = rotate(a + f3(b,c,d) + words[13] + 0x289b7ec6,  4) + b;
  d = rotate(d + f3(a,b,c) + words[0]  + 0xeaa127fa, 11) + a;
  c = rotate(c + f3(d,a,b) + words[3]  + 0xd4ef3085, 16) + d;
  b = rotate(b + f3(c,d,a) + words[6]  + 0x04881d05, 23) + c;

  a = rotate(a + f3(b,c,d) + words[9]  + 0xd9d4d039,  4) + b;
  d = rotate(d + f3(a,b,c) + words[12] + 0xe6db99e5, 11) + a;
  c = rotate(c + f3(d,a,b) + words[15] + 0x1fa27cf8, 16) + d;
  b = rotate(b + f3(c,d,a) + words[2]  + 0xc4ac5665, 23) + c;

  // fourth round
  a = rotate(a + f4(b,c,d) + words[0]  + 0xf4292244,  6) + b;
  d = rotate(d + f4(a,b,c) + words[7]  + 0x432aff97, 10) + a;
  c = rotate(c + f4(d,a,b) + words[14] + 0xab9423a7, 15) + d;
  b = rotate(b + f4(c,d,a) + words[5]  + 0xfc93a039, 21) + c;

  a = rotate(a + f4(b,c,d) + words[12] + 0x655b59c3,  6) + b;
  d = rotate(d + f4(a,b,c) + words[3]  + 0x8f0ccc92, 10) + a;
  c = rotate(c + f4(d,a,b) + words[10] + 0xffeff47d, 15) + d;
  b = rotate(b + f4(c,d,a) + words[1]  + 0x85845dd1, 21) + c;

  a = rotate(a + f4(b,c,d) + words[8]  + 0x6fa87e4f,  6) + b;
  d = rotate(d + f4(a,b,c) + words[15] + 0xfe2ce6e0, 10) + a;
  c = rotate(c + f4(d,a,b) + words[6]  + 0xa3014314, 15) + d;
  b = rotate(b + f4(c,d,a) + words[13] + 0x4e0811a1, 21) + c;

  a = rotate(a + f4(b,c,d) + words[4]  + 0xf7537e82,  6) + b;
  d = rotate(d + f4(a,b,c) + words[11] + 0xbd3af235, 10) + a;
  c = rotate(c + f4(d,a,b) + words[2]  + 0x2ad7d2bb, 15) + d;
  b = rotate(b + f4(c,d,a) + words[9]  + 0xeb86d391, 21) + c;

  // update hash
  _hash[0] += a;
  _hash[1] += b;
  _hash[2] += c;
  _hash[3] += d;
}

/// process final block, less than 64 bytes
void MessageDigestMD5::processBuffer()
{
  // the input bytes are considered as bits strings, where the first bit is the most significant bit of the byte

  // - append "1" bit to message
  // - append "0" bits until message length in bit mod 512 is 448
  // - append length as 64 bit integer

  // number of bits
  size_t paddedLength = _bufferSize * 8;

  // plus one bit set to 1 (always appended)
  paddedLength++;

  // number of bits must be (numBits % 512) = 448
  size_t lower11Bits = paddedLength & 511;
  if (lower11Bits <= 448)
    paddedLength +=       448 - lower11Bits;
  else
    paddedLength += 512 + 448 - lower11Bits;
  // convert from bits to bytes
  paddedLength /= 8;

  // only needed if additional data flows over into a second block
  unsigned char extra[BLOCK_SIZE];

  // append a "1" bit, 128 => binary 10000000
  if (_bufferSize < BLOCK_SIZE)
    _buffer[_bufferSize] = 128;
  else
    extra[0] = 128;

  size_t i;
  for (i = _bufferSize + 1; i < BLOCK_SIZE; i++)
    _buffer[i] = 0;
  for (; i < paddedLength; i++)
    extra[i - BLOCK_SIZE] = 0;

  // add message length in bits as 64 bit number
  uint64_t msgBits = 8 * (_numBytes + _bufferSize);
  // find right position
  unsigned char* addLength;
  if (paddedLength < BLOCK_SIZE)
    addLength = _buffer + paddedLength;
  else
    addLength = extra + paddedLength - BLOCK_SIZE;

  // must be little endian
  *addLength++ = msgBits & 0xFF; msgBits >>= 8;
  *addLength++ = msgBits & 0xFF; msgBits >>= 8;
  *addLength++ = msgBits & 0xFF; msgBits >>= 8;
  *addLength++ = msgBits & 0xFF; msgBits >>= 8;
  *addLength++ = msgBits & 0xFF; msgBits >>= 8;
  *addLength++ = msgBits & 0xFF; msgBits >>= 8;
  *addLength++ = msgBits & 0xFF; msgBits >>= 8;
  *addLength++ = msgBits & 0xFF;

  // process blocks
  processBlock(_buffer);
  // flowed over into a second block ?
  if (paddedLength > BLOCK_SIZE)
    processBlock(extra);
}

