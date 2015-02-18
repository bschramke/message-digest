/**
 * @file MessageDigestSHA224.h
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
#ifndef MessageDigestSHA224_INCLUDED
#define MessageDigestSHA224_INCLUDED

#include "MessageDigest/MessageDigestSHA256.hpp"

#include <cstdint>
#include <string>
#include <memory>

class MessageDigestSHA224:public MessageDigestSHA256 {
public:
  MessageDigestSHA224();
  ~MessageDigestSHA224() = default;

  static std::unique_ptr<MessageDigestImpl> create();

  // MessageDigestImpl interface
public:
  std::string digest();
  std::string getAlgorithm() const;
  void reset();

};

#endif //MessageDigestSHA224_INCLUDED
