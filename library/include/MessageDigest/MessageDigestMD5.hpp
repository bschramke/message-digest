/**
 * @file MessageDigestMD5.h
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
#ifndef MessageDigestMD5_INCLUDED
#define MessageDigestMD5_INCLUDED

#include "MessageDigest/MessageDigestImpl.hpp"

#include <cstdint>
#include <string>
#include <memory>

class MessageDigestMD5:public MessageDigestImpl {
public:
	MessageDigestMD5();
	~MessageDigestMD5() = default;

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
        static constexpr uint8_t HASH_SIZE = 4;

        /// size of processed data in bytes
        uint64_t _numBytes;
        /// valid bytes in _buffer
        size_t   _bufferSize;

	uint8_t  _buffer[BLOCK_SIZE];
	uint32_t _hash[HASH_SIZE];

};

#endif //MessageDigestMD5_INCLUDED
