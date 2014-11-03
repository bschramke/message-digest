/**
 * @file MessageDigest.cpp
 *
 * Copyright (c) 2014 Björn Schramke. All rights reserved.
 *
 * SPDX-License-Identifier: BSL-1.0
 */
#include "MessageDigest/MessageDigest.hpp"
#include "MessageDigest/MessageDigestImpl.hpp"
#include <utility>

std::unique_ptr<MessageDigest> MessageDigest::createInstance(const std::string &algorithm)
{
  MessageDigestImplMap& implMap = getImplementationMap();
  auto it = implMap.find(algorithm);

  std::unique_ptr<MessageDigest> digestPtr;
  if(it == implMap.end()){
      digestPtr = nullptr;
  }else{
      digestPtr = std::unique_ptr<MessageDigest>(new MessageDigest());
      digestPtr->mDigestImpl = it->second();
    }

  return digestPtr;
}

void MessageDigest::registerAlgorithm(const std::string &name, MessageDigestImplCreatorFunc createFunc)
{
  MessageDigestImplMap& implMap = getImplementationMap();
  implMap.insert(std::make_pair(name,createFunc));
}

std::vector<std::string>
MessageDigest::getAlgorithms()
{
  std::vector<std::string> algorithms;
  MessageDigestImplMap& implMap = getImplementationMap();

  for(auto it = implMap.begin(); it != implMap.end(); it++ ){
      algorithms.push_back(it->first);
  }

  return algorithms;
}

MessageDigestImplMap& MessageDigest::getImplementationMap()
{
  static MessageDigestImplMap implMap;
  return implMap;
}

//**************************************************************
//* DELEGATES
//**************************************************************
std::string MessageDigest::digest()
{
  return mDigestImpl->digest();
}

std::string MessageDigest::getAlgorithm() const
{
  return mDigestImpl->getAlgorithm();
}

void MessageDigest::update(const void *data, size_t offset, size_t len)
{
  mDigestImpl->update(data,offset,len);
}

void MessageDigest::reset()
{
  mDigestImpl->reset();
}

void MessageDigest::update(const void *data, size_t len)
{
  mDigestImpl->update(data,len);
}

void MessageDigest::update(const std::string &data)
{
  mDigestImpl->update(data);
}

