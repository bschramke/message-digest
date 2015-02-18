/**
 * @file MessageDigestSHA256.cpp
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

#include "MessageDigest/MessageDigestSHA256.hpp"
#include "MessageDigest/MessageDigest.hpp"

#include <iostream>

// big endian architectures need #define __BYTE_ORDER __BIG_ENDIAN
#ifndef _MSC_VER
#include <endian.h>
#endif

static MessageDigestImplRegistrar<MessageDigestSHA256> registrar("SHA256");

namespace
{
  // mix functions for processBlock()
  inline uint32_t f1(uint32_t e, uint32_t f, uint32_t g)
  {
    uint32_t term1 = rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25);
    uint32_t term2 = (e & f) ^ (~e & g); //(g ^ (e & (f ^ g)))
    return term1 + term2;
  }

  inline uint32_t f2(uint32_t a, uint32_t b, uint32_t c)
  {
    uint32_t term1 = rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22);
    uint32_t term2 = ((a | b) & c) | (a & b); //(a & (b ^ c)) ^ (b & c);
    return term1 + term2;
  }

  inline uint32_t f3(uint32_t a)
  {
    return rotateRight(a, 7) ^ rotateRight(a, 18) ^ (a >> 3);
  }

  inline uint32_t f4(uint32_t a)
  {
    return rotateRight(a, 17) ^ rotateRight(a, 19) ^ (a >> 10);
  }
}

MessageDigestSHA256::MessageDigestSHA256()
{
  reset();
}

std::string MessageDigestSHA256::getAlgorithm() const
{
  return "SHA256";
}

void MessageDigestSHA256::reset()
{
  _numBytes   = 0;
  _bufferSize = 0;

  // according to RFC 6234 section 6.1
  _hash[0] = 0x6a09e667;
  _hash[1] = 0xbb67ae85;
  _hash[2] = 0x3c6ef372;
  _hash[3] = 0xa54ff53a;
  _hash[4] = 0x510e527f;
  _hash[5] = 0x9b05688c;
  _hash[6] = 0x1f83d9ab;
  _hash[7] = 0x5be0cd19;

}

std::unique_ptr<MessageDigestImpl> MessageDigestSHA256::create()
{
  return std::unique_ptr<MessageDigestImpl>(new MessageDigestSHA256());
}

std::string MessageDigestSHA256::digest()
{
  // convert hash to string
  static const char dec2hex[16+1] = "0123456789abcdef";

  // save old hash if buffer is partially filled
  uint32_t oldHash[HASH_SIZE];
  for (int i = 0; i < HASH_SIZE; i++)
    oldHash[i] = _hash[i];

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

void MessageDigestSHA256::update(const void *data, const size_t offset, const size_t len)
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

void MessageDigestSHA256::processBlock(const void *data)
{
  /* Constants defined in RFC 6234 section 5.1   */
  static constexpr uint32_t K[] =    {
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

  // get last hash
  uint32_t a = _hash[0];
  uint32_t b = _hash[1];
  uint32_t c = _hash[2];
  uint32_t d = _hash[3];
  uint32_t e = _hash[4];
  uint32_t f = _hash[5];
  uint32_t g = _hash[6];
  uint32_t h = _hash[7];

  // data represented as 16x 32-bit words
  const uint32_t* input = (uint32_t*) data;

  // convert to big endian
  uint32_t words[64];
  int i;
  for (i = 0; i < 16; i++)
    {
#if defined(__BYTE_ORDER) && (__BYTE_ORDER != 0) && (__BYTE_ORDER == __BIG_ENDIAN)
      words[i] = input[i];
#else
      words[i] = swap(input[i]);
#endif
    }

  uint32_t x,y; // temporaries

  // first round
  x = h + f1(e,f,g) + K[0] + words[ 0]; y = f2(a,b,c); d += x; h = x + y;
  x = g + f1(d,e,f) + K[1] + words[ 1]; y = f2(h,a,b); c += x; g = x + y;
  x = f + f1(c,d,e) + K[2] + words[ 2]; y = f2(g,h,a); b += x; f = x + y;
  x = e + f1(b,c,d) + K[3] + words[ 3]; y = f2(f,g,h); a += x; e = x + y;
  x = d + f1(a,b,c) + K[4] + words[ 4]; y = f2(e,f,g); h += x; d = x + y;
  x = c + f1(h,a,b) + K[5] + words[ 5]; y = f2(d,e,f); g += x; c = x + y;
  x = b + f1(g,h,a) + K[6] + words[ 6]; y = f2(c,d,e); f += x; b = x + y;
  x = a + f1(f,g,h) + K[7] + words[ 7]; y = f2(b,c,d); e += x; a = x + y;

  // secound round
  x = h + f1(e,f,g) + K[8] + words[ 8]; y = f2(a,b,c); d += x; h = x + y;
  x = g + f1(d,e,f) + K[9] + words[ 9]; y = f2(h,a,b); c += x; g = x + y;
  x = f + f1(c,d,e) + K[10] + words[10]; y = f2(g,h,a); b += x; f = x + y;
  x = e + f1(b,c,d) + K[11] + words[11]; y = f2(f,g,h); a += x; e = x + y;
  x = d + f1(a,b,c) + K[12] + words[12]; y = f2(e,f,g); h += x; d = x + y;
  x = c + f1(h,a,b) + K[13] + words[13]; y = f2(d,e,f); g += x; c = x + y;
  x = b + f1(g,h,a) + K[14] + words[14]; y = f2(c,d,e); f += x; b = x + y;
  x = a + f1(f,g,h) + K[15] + words[15]; y = f2(b,c,d); e += x; a = x + y;

  // extend to 24 words
  for (; i < 24; i++)
    words[i] = words[i-16] + f3(words[i-15]) + words[i-7] + f4(words[i- 2]);

  // third round
  x = h + f1(e,f,g) + K[16] + words[16]; y = f2(a,b,c); d += x; h = x + y;
  x = g + f1(d,e,f) + K[17] + words[17]; y = f2(h,a,b); c += x; g = x + y;
  x = f + f1(c,d,e) + K[18] + words[18]; y = f2(g,h,a); b += x; f = x + y;
  x = e + f1(b,c,d) + K[19] + words[19]; y = f2(f,g,h); a += x; e = x + y;
  x = d + f1(a,b,c) + K[20] + words[20]; y = f2(e,f,g); h += x; d = x + y;
  x = c + f1(h,a,b) + K[21] + words[21]; y = f2(d,e,f); g += x; c = x + y;
  x = b + f1(g,h,a) + K[22] + words[22]; y = f2(c,d,e); f += x; b = x + y;
  x = a + f1(f,g,h) + K[23] + words[23]; y = f2(b,c,d); e += x; a = x + y;

  // extend to 32 words
  for (; i < 32; i++)
    words[i] = words[i-16] + f3(words[i-15]) + words[i-7] + f4(words[i- 2]);

  // fourth round
  x = h + f1(e,f,g) + K[24] + words[24]; y = f2(a,b,c); d += x; h = x + y;
  x = g + f1(d,e,f) + K[25] + words[25]; y = f2(h,a,b); c += x; g = x + y;
  x = f + f1(c,d,e) + K[26] + words[26]; y = f2(g,h,a); b += x; f = x + y;
  x = e + f1(b,c,d) + K[27] + words[27]; y = f2(f,g,h); a += x; e = x + y;
  x = d + f1(a,b,c) + K[28] + words[28]; y = f2(e,f,g); h += x; d = x + y;
  x = c + f1(h,a,b) + K[29] + words[29]; y = f2(d,e,f); g += x; c = x + y;
  x = b + f1(g,h,a) + K[30] + words[30]; y = f2(c,d,e); f += x; b = x + y;
  x = a + f1(f,g,h) + K[31] + words[31]; y = f2(b,c,d); e += x; a = x + y;

  // extend to 40 words
  for (; i < 40; i++)
    words[i] = words[i-16] + f3(words[i-15]) + words[i-7] + f4(words[i- 2]);

  // fifth round
  x = h + f1(e,f,g) + K[32] + words[32]; y = f2(a,b,c); d += x; h = x + y;
  x = g + f1(d,e,f) + K[33] + words[33]; y = f2(h,a,b); c += x; g = x + y;
  x = f + f1(c,d,e) + K[34] + words[34]; y = f2(g,h,a); b += x; f = x + y;
  x = e + f1(b,c,d) + K[35] + words[35]; y = f2(f,g,h); a += x; e = x + y;
  x = d + f1(a,b,c) + K[36] + words[36]; y = f2(e,f,g); h += x; d = x + y;
  x = c + f1(h,a,b) + K[37] + words[37]; y = f2(d,e,f); g += x; c = x + y;
  x = b + f1(g,h,a) + K[38] + words[38]; y = f2(c,d,e); f += x; b = x + y;
  x = a + f1(f,g,h) + K[39] + words[39]; y = f2(b,c,d); e += x; a = x + y;

  // extend to 48 words
  for (; i < 48; i++)
    words[i] = words[i-16] + f3(words[i-15]) + words[i-7] + f4(words[i- 2]);

  // sixth round
  x = h + f1(e,f,g) + K[40] + words[40]; y = f2(a,b,c); d += x; h = x + y;
  x = g + f1(d,e,f) + K[41] + words[41]; y = f2(h,a,b); c += x; g = x + y;
  x = f + f1(c,d,e) + K[42] + words[42]; y = f2(g,h,a); b += x; f = x + y;
  x = e + f1(b,c,d) + K[43] + words[43]; y = f2(f,g,h); a += x; e = x + y;
  x = d + f1(a,b,c) + K[44] + words[44]; y = f2(e,f,g); h += x; d = x + y;
  x = c + f1(h,a,b) + K[45] + words[45]; y = f2(d,e,f); g += x; c = x + y;
  x = b + f1(g,h,a) + K[46] + words[46]; y = f2(c,d,e); f += x; b = x + y;
  x = a + f1(f,g,h) + K[47] + words[47]; y = f2(b,c,d); e += x; a = x + y;

  // extend to 56 words
  for (; i < 56; i++)
    words[i] = words[i-16] + f3(words[i-15]) + words[i-7] + f4(words[i- 2]);

  // seventh round
  x = h + f1(e,f,g) + K[48] + words[48]; y = f2(a,b,c); d += x; h = x + y;
  x = g + f1(d,e,f) + K[49] + words[49]; y = f2(h,a,b); c += x; g = x + y;
  x = f + f1(c,d,e) + K[50] + words[50]; y = f2(g,h,a); b += x; f = x + y;
  x = e + f1(b,c,d) + K[51] + words[51]; y = f2(f,g,h); a += x; e = x + y;
  x = d + f1(a,b,c) + K[52] + words[52]; y = f2(e,f,g); h += x; d = x + y;
  x = c + f1(h,a,b) + K[53] + words[53]; y = f2(d,e,f); g += x; c = x + y;
  x = b + f1(g,h,a) + K[54] + words[54]; y = f2(c,d,e); f += x; b = x + y;
  x = a + f1(f,g,h) + K[55] + words[55]; y = f2(b,c,d); e += x; a = x + y;

  // extend to 64 words
  for (; i < 64; i++)
    words[i] = words[i-16] + f3(words[i-15]) + words[i-7] + f4(words[i- 2]);

  // eigth round
  x = h + f1(e,f,g) + K[56] + words[56]; y = f2(a,b,c); d += x; h = x + y;
  x = g + f1(d,e,f) + K[57] + words[57]; y = f2(h,a,b); c += x; g = x + y;
  x = f + f1(c,d,e) + K[58] + words[58]; y = f2(g,h,a); b += x; f = x + y;
  x = e + f1(b,c,d) + K[59] + words[59]; y = f2(f,g,h); a += x; e = x + y;
  x = d + f1(a,b,c) + K[60] + words[60]; y = f2(e,f,g); h += x; d = x + y;
  x = c + f1(h,a,b) + K[61] + words[61]; y = f2(d,e,f); g += x; c = x + y;
  x = b + f1(g,h,a) + K[62] + words[62]; y = f2(c,d,e); f += x; b = x + y;
  x = a + f1(f,g,h) + K[63] + words[63]; y = f2(b,c,d); e += x; a = x + y;

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
void MessageDigestSHA256::processBuffer()
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
