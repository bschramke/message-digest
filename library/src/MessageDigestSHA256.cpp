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
