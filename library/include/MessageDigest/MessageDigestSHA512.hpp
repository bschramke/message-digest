/**
 * @file MessageDigestSHA512.h
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
#ifndef MessageDigestSHA512_INCLUDED
#define MessageDigestSHA512_INCLUDED

#include "MessageDigest/MessageDigestImpl.hpp"

#include <cstdint>
#include <string>
#include <memory>

class MessageDigestSHA512:public MessageDigestImpl {
public:
  MessageDigestSHA512();
  ~MessageDigestSHA512() = default;

  static std::unique_ptr<MessageDigestImpl> create();

  // MessageDigestImpl interface
public:
  virtual std::string digest();
  virtual std::string getAlgorithm() const;
  virtual void reset();

  void update(const void *data, const size_t offset, const size_t len);

protected:
  /// process 64 bytes
  virtual void processBlock(const void* data);
  virtual void processBuffer();

  static constexpr uint8_t BLOCK_SIZE = 128;
  static constexpr uint8_t HASH_SIZE = 8;

  /// size of processed data in bytes
  uint64_t _numBytes;
  /// valid bytes in _buffer
  size_t   _bufferSize;

  uint8_t  _buffer[BLOCK_SIZE];
  uint64_t _hash[HASH_SIZE];
};

#endif //MessageDigestSHA512_INCLUDED
