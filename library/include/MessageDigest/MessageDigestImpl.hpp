/**
 * @file MessageDigestImpl.h
 *
 * Copyright (c) 2014 Björn Schramke. All rights reserved.
 *
 * SPDX-License-Identifier: BSL-1.0
 */
#ifndef MessageDigestImpl_INCLUDED
#define MessageDigestImpl_INCLUDED

#include <string>
#include <memory>

class MessageDigestImpl {
public:
	MessageDigestImpl() = default;
	~MessageDigestImpl() = default;

	virtual std::string digest() = 0;
	virtual std::string getAlgorithm() const = 0;
	virtual void update(const void* data, size_t offset, size_t len) = 0;
	virtual void reset() = 0;

	void update(const void* data, size_t len);
	void update(const std::string& data);

	std::string operator()(const void* data, size_t numBytes);
	std::string operator()(const std::string& text);

};

inline void MessageDigestImpl::update(const void *data, size_t len) { update(data,0,len); }

inline void MessageDigestImpl::update(const std::string &data)
{
  update(data.c_str(),0,data.length());
}

/// compute MD of a memory block
inline std::string MessageDigestImpl::operator()(const void *data, size_t len)
{
  reset();
  update(data,len);
  return digest();
}

/// compute MD of a string, excluding final zero
inline std::string MessageDigestImpl::operator()(const std::string &text)
{
  reset();
  update(text.c_str(),0,text.length());
  return digest();
}

namespace{

  /**
   * @brief The circular left shift operation
   */
  inline uint32_t rotateLeft(uint32_t a, uint32_t c)
  {
    return (a << c) | (a >> (32 - c));
  }

  /**
   * @brief The circular right shift operation
   */
  inline uint32_t rotateRight(uint32_t a, uint32_t c)
  {
    return (a >> c) | (a << (32 - c));
  }

  inline uint32_t swap(uint32_t x)
  {
#if defined(__GNUC__) || defined(__clang__)
    return __builtin_bswap32(x);
#endif
#ifdef MSC_VER
    return _byteswap_ulong(x);
#endif

    return (x >> 24) |
        ((x >>  8) & 0x0000FF00) |
        ((x <<  8) & 0x00FF0000) |
        (x << 24);
  }
}

#endif //MessageDigestImpl_INCLUDED
