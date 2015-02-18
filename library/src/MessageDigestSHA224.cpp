/**
 * @file MessageDigestSHA224.cpp
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

#include "MessageDigest/MessageDigestSHA224.hpp"
#include "MessageDigest/MessageDigest.hpp"

#include <iostream>

// big endian architectures need #define __BYTE_ORDER __BIG_ENDIAN
#ifndef _MSC_VER
#include <endian.h>
#endif

static MessageDigestImplRegistrar<MessageDigestSHA224> registrar("SHA224");

MessageDigestSHA224::MessageDigestSHA224()
{
  reset();
}

std::string MessageDigestSHA224::getAlgorithm() const
{
  return "SHA224";
}

void MessageDigestSHA224::reset()
{
  _numBytes   = 0;
  _bufferSize = 0;

  // according to RFC 6234 section 6.1
  _hash[0] = 0xc1059ed8;
  _hash[1] = 0x367cd507;
  _hash[2] = 0x3070dd17;
  _hash[3] = 0xf70e5939;
  _hash[4] = 0xffc00b31;
  _hash[5] = 0x68581511;
  _hash[6] = 0x64f98fa7;
  _hash[7] = 0xbefa4fa4;

}

std::unique_ptr<MessageDigestImpl> MessageDigestSHA224::create()
{
  return std::unique_ptr<MessageDigestImpl>(new MessageDigestSHA224());
}

std::string MessageDigestSHA224::digest()
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
  char hashBuffer[7*8+1];
  size_t offset = 0;
  for (int i = 0; i < 7; i++)
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
