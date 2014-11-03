/**
 * @file main.cpp
 *
 * Copyright (c) 2014 Björn Schramke. All rights reserved.
 *
 * SPDX-License-Identifier: BSL-1.0
 */
#include <iostream>

#include "MessageDigest/MessageDigest.hpp"

using namespace std;

int main()
{
  cout << "Hello World!" << endl;
  const std::string data("Dies ist ein Test");
  std::vector<string> algorithms = MessageDigest::getAlgorithms();

  return 0;
}

