/**
 * @file MessageDigestImpl.h
 *
 * Copyright (c) 2014 Björn Schramke. All rights reserved.
 *
 * SPDX-License-Identifier: BSL-1.0
 */
#ifndef MessageDigestImpl_INCLUDED
#define MessageDigestImpl_INCLUDED

#include "MessageDigest/MessageDigest.hpp"

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

template<class T>
class MessageDigestImplRegistrar {
public:
  MessageDigestImplRegistrar(const std::string& name){
    MessageDigest::registerAlgorithm(name,&T::create);
  }
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

#endif //MessageDigestImpl_INCLUDED

