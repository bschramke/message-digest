/**
 * @file MessageDigestSHA1.cpp
 *
 * Copyright (c) 2014 Björn Schramke. All rights reserved.
 *
 * SPDX-License-Identifier: BSL-1.0
 *
 * based on:
 * sha1.h and sha1.cpp
 * from hash-library by Stephan Brume
 * (http://create.stephan-brumme.com/hash-library)
 *
 * Copyright (c) 2014 Stephan Brumme. All rights reserved.
 * see http://create.stephan-brumme.com/disclaimer.html
 *
 */

#include "MessageDigest/MessageDigestSHA1.hpp"
#include "MessageDigest/MessageDigest.hpp"

#include <iostream>

// big endian architectures need #define __BYTE_ORDER __BIG_ENDIAN
#ifndef _MSC_VER
#include <endian.h>
#endif

static MessageDigestImplRegistrar<MessageDigestSHA1> registrar("SHA1");

namespace
{
  // mix functions for processBlock()
  inline uint32_t f1(uint32_t b, uint32_t c, uint32_t d)
  {
    return d ^ (b & (c ^ d)); // original: f = (b & c) | ((~b) & d);
  }

  inline uint32_t f2(uint32_t b, uint32_t c, uint32_t d)
  {
    return b ^ c ^ d;
  }

  inline uint32_t f3(uint32_t b, uint32_t c, uint32_t d)
  {
    return (b & c) | (b & d) | (c & d);
  }

}

MessageDigestSHA1::MessageDigestSHA1()
{
  reset();
}

std::string MessageDigestSHA1::getAlgorithm() const
{
  return "SHA1";
}

void MessageDigestSHA1::reset()
{
  _numBytes   = 0;
  _bufferSize = 0;

  // according to RFC 3174 section 6.1
  _hash[0] = 0x67452301;
  _hash[1] = 0xefcdab89;
  _hash[2] = 0x98badcfe;
  _hash[3] = 0x10325476;
  _hash[4] = 0xc3d2e1f0;

}

std::unique_ptr<MessageDigestImpl> MessageDigestSHA1::create()
{
  return std::unique_ptr<MessageDigestImpl>(new MessageDigestSHA1());
}

std::string MessageDigestSHA1::digest()
{
  // convert hash to string
  static constexpr char dec2hex[16+1] = "0123456789abcdef";

  // save old hash if buffer is partially filled
  uint32_t oldHash[HASH_SIZE];
  for (int i = 0; i < HASH_SIZE; i++)
    {
      oldHash[i] = _hash[i];
    }

  // process remaining bytes
  processBuffer();

  // create hash string
  char hashBuffer[HASH_SIZE*8+1];
  size_t offset = 0;
  for (int i = 0; i < HASH_SIZE; i++)
    {
      hashBuffer[offset++] = dec2hex[(_hash[i] >> 28) & 15];
      hashBuffer[offset++] = dec2hex[(_hash[i] >> 24) & 15];
      hashBuffer[offset++] = dec2hex[(_hash[i] >> 20) & 15];
      hashBuffer[offset++] = dec2hex[(_hash[i] >> 16) & 15];
      hashBuffer[offset++] = dec2hex[(_hash[i] >> 12) & 15];
      hashBuffer[offset++] = dec2hex[(_hash[i] >>  8) & 15];
      hashBuffer[offset++] = dec2hex[(_hash[i] >>  4) & 15];
      hashBuffer[offset++] = dec2hex[ _hash[i]        & 15];

      // restore old hash
      _hash[i] = oldHash[i];
    }

  // zero-terminated string
  hashBuffer[offset] = 0;

  // convert to std::string
  return hashBuffer;
}

void MessageDigestSHA1::update(const void *data, const size_t offset, const size_t len)
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

void MessageDigestSHA1::processBlock(const void *data)
{
  /* Constants defined in SHA-1   */
  static constexpr uint32_t K[] =    {
    0x5A827999,
    0x6ED9EBA1,
    0x8F1BBCDC,
    0xCA62C1D6
  };

  // get last hash
  uint32_t a = _hash[0];
  uint32_t b = _hash[1];
  uint32_t c = _hash[2];
  uint32_t d = _hash[3];
  uint32_t e = _hash[4];

  // data represented as 16x 32-bit words
  const uint32_t* input = (uint32_t*) data;

  // convert to big endian
  uint32_t words[80];
  for (int i = 0; i < 16; i++)
    {
#if defined(__BYTE_ORDER) && (__BYTE_ORDER != 0) && (__BYTE_ORDER == __BIG_ENDIAN)
      words[i] = input[i];
#else
      words[i] = swap32(input[i]);
#endif
    }

  // extend to 80 words
  for (int i = 16; i < 80; i++)
    {
      words[i] = rotateLeft(words[i-3] ^ words[i-8] ^ words[i-14] ^ words[i-16], 1);
    }

  // first round
  for (int i = 0; i < 4; i++)
    {
      int offset = 5*i;
      e += rotateLeft(a,5) + f1(b,c,d) + words[offset  ] + K[0]; b = rotateLeft(b,30);
      d += rotateLeft(e,5) + f1(a,b,c) + words[offset+1] + K[0]; a = rotateLeft(a,30);
      c += rotateLeft(d,5) + f1(e,a,b) + words[offset+2] + K[0]; e = rotateLeft(e,30);
      b += rotateLeft(c,5) + f1(d,e,a) + words[offset+3] + K[0]; d = rotateLeft(d,30);
      a += rotateLeft(b,5) + f1(c,d,e) + words[offset+4] + K[0]; c = rotateLeft(c,30);
    }

  // second round
  for (int i = 4; i < 8; i++)
    {
      int offset = 5*i;
      e += rotateLeft(a,5) + f2(b,c,d) + words[offset  ] + K[1]; b = rotateLeft(b,30);
      d += rotateLeft(e,5) + f2(a,b,c) + words[offset+1] + K[1]; a = rotateLeft(a,30);
      c += rotateLeft(d,5) + f2(e,a,b) + words[offset+2] + K[1]; e = rotateLeft(e,30);
      b += rotateLeft(c,5) + f2(d,e,a) + words[offset+3] + K[1]; d = rotateLeft(d,30);
      a += rotateLeft(b,5) + f2(c,d,e) + words[offset+4] + K[1]; c = rotateLeft(c,30);
    }

  // third round
  for (int i = 8; i < 12; i++)
    {
      int offset = 5*i;
      e += rotateLeft(a,5) + f3(b,c,d) + words[offset  ] + K[2]; b = rotateLeft(b,30);
      d += rotateLeft(e,5) + f3(a,b,c) + words[offset+1] + K[2]; a = rotateLeft(a,30);
      c += rotateLeft(d,5) + f3(e,a,b) + words[offset+2] + K[2]; e = rotateLeft(e,30);
      b += rotateLeft(c,5) + f3(d,e,a) + words[offset+3] + K[2]; d = rotateLeft(d,30);
      a += rotateLeft(b,5) + f3(c,d,e) + words[offset+4] + K[2]; c = rotateLeft(c,30);
    }

  // fourth round
  for (int i = 12; i < 16; i++)
    {
      int offset = 5*i;
      e += rotateLeft(a,5) + f2(b,c,d) + words[offset  ] + K[3]; b = rotateLeft(b,30);
      d += rotateLeft(e,5) + f2(a,b,c) + words[offset+1] + K[3]; a = rotateLeft(a,30);
      c += rotateLeft(d,5) + f2(e,a,b) + words[offset+2] + K[3]; e = rotateLeft(e,30);
      b += rotateLeft(c,5) + f2(d,e,a) + words[offset+3] + K[3]; d = rotateLeft(d,30);
      a += rotateLeft(b,5) + f2(c,d,e) + words[offset+4] + K[3]; c = rotateLeft(c,30);
    }

  // update hash
  _hash[0] += a;
  _hash[1] += b;
  _hash[2] += c;
  _hash[3] += d;
  _hash[4] += e;
}

/// process final block, less than 64 bytes
void MessageDigestSHA1::processBuffer()
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

  // must be big endian
  *addLength++ = (msgBits >> 56) & 0xFF;
  *addLength++ = (msgBits >> 48) & 0xFF;
  *addLength++ = (msgBits >> 40) & 0xFF;
  *addLength++ = (msgBits >> 32) & 0xFF;
  *addLength++ = (msgBits >> 24) & 0xFF;
  *addLength++ = (msgBits >> 16) & 0xFF;
  *addLength++ = (msgBits >>  8) & 0xFF;
  *addLength   =  msgBits        & 0xFF;

  // process blocks
  processBlock(_buffer);
  // flowed over into a second block ?
  if (paddedLength > BLOCK_SIZE)
    processBlock(extra);
}

