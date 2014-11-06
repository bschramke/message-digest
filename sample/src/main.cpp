/**
 * @file main.cpp
 *
 * Copyright (c) 2014 Björn Schramke. All rights reserved.
 *
 * SPDX-License-Identifier: BSL-1.0
 */
#include <iostream>

#include "MessageDigest/MessageDigest.hpp"
#include "MessageDigest/MessageDigestImpl.hpp"

using namespace std;

int main()
{
  cout << "Hello World!" << endl;
  const std::string data("Dies ist ein Test");
  std::vector<string> algorithms = MessageDigest::getAlgorithms();

  std::vector<std::unique_ptr<MessageDigest>> digestVector;
  digestVector.reserve(5);
  //  digestVector.push_back(MessageDigest::createInstance("MD5"));
  for(const auto& algo: algorithms)
    {
      digestVector.push_back(MessageDigest::createInstance(algo));
    }

  cout << "input:\t" << data << endl;
  for(const auto& digest: digestVector)
    {
      digest->update(data);
      cout << digest->getAlgorithm() << ":\t";
      cout << digest->digest() << endl;
    }

  return 0;
}

