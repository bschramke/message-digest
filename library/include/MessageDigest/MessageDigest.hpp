/**
 * @file MessageDigest.h
 *
 * Copyright (c) 2014 Björn Schramke. All rights reserved.
 *
 * SPDX-License-Identifier: BSL-1.0
 */
#ifndef MessageDigest_INCLUDED
#define MessageDigest_INCLUDED

#include <string>
#include <memory>
#include <map>
#include <functional>
#include <vector>

#include "MessageDigest/MessageDigestImpl.hpp"

typedef std::unique_ptr<MessageDigestImpl> MessageDigestImplPtr;
typedef std::function<std::unique_ptr<MessageDigestImpl>(void)> MessageDigestImplCreatorFunc;
typedef std::map<std::string,MessageDigestImplCreatorFunc> MessageDigestImplMap;

class MessageDigest {
public:
	~MessageDigest() = default;

	static std::unique_ptr<MessageDigest> createInstance(const std::string& algorithm);
	static void registerAlgorithm(const std::string& name,
				      MessageDigestImplCreatorFunc createFunc);
	static std::vector<std::string> getAlgorithms();

	std::string digest();
	std::string getAlgorithm() const;
	void update(const void* data, size_t offset, size_t len);
	void reset();

	void update(const void* data, size_t len);
	void update(const std::string& data);

protected:
	static MessageDigestImplMap &getImplementationMap();

private:
	MessageDigest() = default;
	MessageDigestImplPtr mDigestImpl;
};

template<class T>
class MessageDigestImplRegistrar {
public:
  MessageDigestImplRegistrar(const std::string& name){
    MessageDigest::registerAlgorithm(name,&T::create);
  }
};

#endif //MessageDigest_INCLUDED
