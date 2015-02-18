/**
 * @file MessageDigestSHA256.h
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
#ifndef MessageDigestSHA256_INCLUDED
#define MessageDigestSHA256_INCLUDED

#include "MessageDigest/MessageDigestSHA2.hpp"

#include <cstdint>
#include <string>
#include <memory>

class MessageDigestSHA256:public MessageDigestSHA2 {
public:
  MessageDigestSHA256();
  ~MessageDigestSHA256() = default;

  static std::unique_ptr<MessageDigestImpl> create();

  // MessageDigestImpl interface
public:
  std::string digest();
  std::string getAlgorithm() const;
  void reset();

};

#endif //MessageDigestSHA256_INCLUDED
