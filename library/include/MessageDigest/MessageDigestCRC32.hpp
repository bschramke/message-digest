/**
 * @file MessageDigestCRC32.h
 *
 * Copyright (c) 2014 Björn Schramke. All rights reserved.
 *
 * SPDX-License-Identifier: BSL-1.0
 *
 * based on:
 * crc32.h and crc32.cpp
 * from hash-library by Stephan Brume
 * (http://create.stephan-brumme.com/hash-library)
 *
 * Copyright (c) 2014 Stephan Brumme. All rights reserved.
 * see http://create.stephan-brumme.com/disclaimer.html
 *
 */
#ifndef MessageDigest_CRC32_INCLUDED
#define MessageDigest_CRC32_INCLUDED

#include "MessageDigest/MessageDigestImpl.hpp"

#include <cstdint>
#include <string>
#include <memory>

class MessageDigestCRC32:public MessageDigestImpl {
public:
    MessageDigestCRC32();
    ~MessageDigestCRC32() = default;

	static std::unique_ptr<MessageDigestImpl> create();

	// MessageDigestImpl interface
public:
	std::string digest();
	std::string getAlgorithm() const;
	void update(const void *data, const size_t offset, const size_t len);
	void reset();

private:
    /// hash
    uint32_t _hash;

};

#endif //MessageDigest_CRC32_INCLUDED
