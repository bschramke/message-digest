/**
 * @file MessageDigestSHA1.h
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
#ifndef MessageDigestSHA1_INCLUDED
#define MessageDigestSHA1_INCLUDED

#include "MessageDigest/MessageDigestImpl.hpp"

#include <cstdint>
#include <string>
#include <memory>

class MessageDigestSHA1:public MessageDigestImpl {
public:
  MessageDigestSHA1();
  ~MessageDigestSHA1() = default;

  static std::unique_ptr<MessageDigestImpl> create();

  // MessageDigestImpl interface
public:
  std::string digest();
  std::string getAlgorithm() const;
  void update(const void *data, const size_t offset, const size_t len);
  void reset();

private:
  /// process 64 bytes
  void processBlock(const void* data);
  void processBuffer();

  static constexpr uint8_t BLOCK_SIZE = 64;
  static constexpr uint8_t HASH_SIZE = 5;

  /// size of processed data in bytes
  uint64_t _numBytes;
  /// valid bytes in _buffer
  size_t   _bufferSize;

  uint8_t  _buffer[BLOCK_SIZE];
  uint32_t _hash[HASH_SIZE];

};

#endif //MessageDigestSHA1_INCLUDED
