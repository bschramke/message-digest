/**
 * @file MessageDigestSHA512.cpp
 *
 * Copyright (c) 2015 Björn Schramke. All rights reserved.
 *
 * SPDX-License-Identifier: BSL-1.0
 *
 * based on:
 * sha256.h and sha256.cpp
 * from hash-library by Stephan Brume
 * (http://create.stephan-brumme.com/hash-library)
 *
 * Copyright (c) 2014 Stephan Brumme. All rights reserved.
 * see http://create.stephan-brumme.com/disclaimer.html
 *
 */

#include "MessageDigest/MessageDigestSHA512.hpp"
#include "MessageDigest/MessageDigest.hpp"

#include <iostream>

// big endian architectures need #define __BYTE_ORDER __BIG_ENDIAN
#ifndef _MSC_VER
#include <endian.h>
#endif

static MessageDigestImplRegistrar<MessageDigestSHA512> registrar("SHA512");

namespace
{
  /**
   * @brief The circular left shift operation
   */
  inline uint64_t rotateLeft(uint64_t a, uint64_t c)
  {
    return (a << c) | (a >> (64 - c));
  }

  /**
   * @brief The circular right shift operation
   */
  inline uint64_t rotateRight(uint64_t a, uint64_t c)
  {
    return (a >> c) | (a << (64 - c));
  }

  // mix functions for processBlock()
  inline uint64_t f1(uint64_t e, uint64_t f, uint64_t g)
  {
    uint64_t term1 = rotateRight(e, 14) ^ rotateRight(e, 18) ^ rotateRight(e, 41);
    uint64_t term2 = (e & f) ^ (~e & g); //(g ^ (e & (f ^ g)))
    return term1 + term2;
  }

  inline uint64_t f2(uint64_t a, uint64_t b, uint64_t c)
  {
    uint64_t term1 = rotateRight(a, 28) ^ rotateRight(a, 34) ^ rotateRight(a, 39);
    uint64_t term2 = ((a | b) & c) | (a & b); //(a & (b ^ c)) ^ (b & c);
    return term1 + term2;
  }

  inline uint64_t f3(uint64_t a)
  {
    return rotateRight(a, 1) ^ rotateRight(a, 8) ^ (a >> 7);
  }

  inline uint64_t f4(uint64_t a)
  {
    return rotateRight(a, 19) ^ rotateRight(a, 61) ^ (a >> 6);
  }
}

MessageDigestSHA512::MessageDigestSHA512()
{
  reset();
}

std::string MessageDigestSHA512::getAlgorithm() const
{
  return "SHA256";
}

void MessageDigestSHA512::reset()
{
  _numBytes   = 0;
  _bufferSize = 0;

  // according to RFC 6234 section 6.3
  _hash[0] = 0x6a09e667f3bcc908;
  _hash[1] = 0xbb67ae8584caa73b;
  _hash[2] = 0x3c6ef372fe94f82b;
  _hash[3] = 0xa54ff53a5f1d36f1;
  _hash[4] = 0x510e527fade682d1;
  _hash[5] = 0x9b05688c2b3e6c1f;
  _hash[6] = 0x1f83d9abfb41bd6b;
  _hash[7] = 0x5be0cd19137e2179;

}

std::unique_ptr<MessageDigestImpl> MessageDigestSHA512::create()
{
  return std::unique_ptr<MessageDigestImpl>(new MessageDigestSHA512());
}

std::string MessageDigestSHA512::digest()
{
  // convert hash to string
  static const char dec2hex[16+1] = "0123456789abcdef";

  // save old hash if buffer is partially filled
  uint64_t oldHash[HASH_SIZE];
  for (int i = 0; i < HASH_SIZE; i++)
    oldHash[i] = _hash[i];

  // process remaining bytes
  processBuffer();

  // create hash string
  char hashBuffer[HASH_SIZE*8+1];
  size_t offset = 0;
  for (int i = 0; i < HASH_SIZE; i++)
  {
    hashBuffer[offset++] = dec2hex[(_hash[i] >> 60) & 15];
    hashBuffer[offset++] = dec2hex[(_hash[i] >> 56) & 15];
    hashBuffer[offset++] = dec2hex[(_hash[i] >> 52) & 15];
    hashBuffer[offset++] = dec2hex[(_hash[i] >> 48) & 15];
    hashBuffer[offset++] = dec2hex[(_hash[i] >> 44) & 15];
    hashBuffer[offset++] = dec2hex[(_hash[i] >> 40) & 15];
    hashBuffer[offset++] = dec2hex[(_hash[i] >> 36) & 15];
    hashBuffer[offset++] = dec2hex[(_hash[i] >> 32) & 15];
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

void MessageDigestSHA512::update(const void *data, const size_t offset, const size_t len)
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

void MessageDigestSHA512::processBlock(const void *data)
{
  /* Constants defined in RFC 6234 section 5.2   */
  static constexpr uint64_t K[] =    {
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
  };

  // data represented as 64-bit words
  const uint64_t* input = (uint64_t*) data;

  // message schedule of eighty 64-bit words
  uint64_t words[80];

  //Prepare the message schedule
  int i;
  for (i = 0; i < 16; i++)
    {
#if defined(__BYTE_ORDER) && (__BYTE_ORDER != 0) && (__BYTE_ORDER == __BIG_ENDIAN)
      words[i] = input[i];
#else
      words[i] = swap64(input[i]);
#endif
    }

  for (;i < 80; i++)
    {
      words[i] = words[i-16] + f3(words[i-15]) + words[i-7] + f4(words[i- 2]);
    }

  uint64_t x,y; // temporaries

  // get last hash
  uint64_t a = _hash[0];
  uint64_t b = _hash[1];
  uint64_t c = _hash[2];
  uint64_t d = _hash[3];
  uint64_t e = _hash[4];
  uint64_t f = _hash[5];
  uint64_t g = _hash[6];
  uint64_t h = _hash[7];

  i=0;
  do
    {
      x = h + f1(e,f,g) + K[i] + words[ i]; y = f2(a,b,c); d += x; h = x + y; i++;
      x = g + f1(d,e,f) + K[i] + words[ i]; y = f2(h,a,b); c += x; g = x + y; i++;
      x = f + f1(c,d,e) + K[i] + words[ i]; y = f2(g,h,a); b += x; f = x + y; i++;
      x = e + f1(b,c,d) + K[i] + words[ i]; y = f2(f,g,h); a += x; e = x + y; i++;
      x = d + f1(a,b,c) + K[i] + words[ i]; y = f2(e,f,g); h += x; d = x + y; i++;
      x = c + f1(h,a,b) + K[i] + words[ i]; y = f2(d,e,f); g += x; c = x + y; i++;
      x = b + f1(g,h,a) + K[i] + words[ i]; y = f2(c,d,e); f += x; b = x + y; i++;
      x = a + f1(f,g,h) + K[i] + words[ i]; y = f2(b,c,d); e += x; a = x + y; i++;
    }
  while(i<80);

  // update hash
  _hash[0] += a;
  _hash[1] += b;
  _hash[2] += c;
  _hash[3] += d;
  _hash[4] += e;
  _hash[5] += f;
  _hash[6] += g;
  _hash[7] += h;
}

/// process final block, less than 64 bytes
void MessageDigestSHA512::processBuffer()
{
  // the input bytes are considered as bits strings, where the first bit is the most significant bit of the byte

  // - append "1" bit to message
  // - append "0" bits until message length in bit mod 1024 is 896
  // - append length as 64 bit integer

  // number of bits
  size_t paddedLength = _bufferSize * 8;

  // plus one bit set to 1 (always appended)
  paddedLength++;

  // number of bits must be (numBits % 1024) = 896
  size_t lower11Bits = paddedLength & 1023;
  if (lower11Bits <= 896)
    paddedLength +=       896 - lower11Bits;
  else
    paddedLength += 1024 + 896 - lower11Bits;
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

  // add message length in bits as 128 bit number
  uint64_t msgBits = 8 * (_numBytes + _bufferSize);
  // find right position
  unsigned char* addLength;
  if (paddedLength < BLOCK_SIZE)
    addLength = _buffer + paddedLength + 8;
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
