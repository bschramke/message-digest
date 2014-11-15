#include "MessageDigestTest.hpp"
#include "MessageDigest/MessageDigestImpl.hpp"
#include "TestConstants.h"

CPPUNIT_TEST_SUITE_REGISTRATION (MessageDigestTest);

void MessageDigestTest :: setUp (void)
{
}

void MessageDigestTest :: tearDown (void)
{
}

void MessageDigestTest::testCRC32Implementation()
{
  auto digestImpl = MessageDigest::createInstance("CRC32");
  std::string text = TEXT2;

  CPPUNIT_ASSERT_EQUAL(ALGORITHM_CRC32,digestImpl->getAlgorithm());

  digestImpl->update(TEXT1);
  CPPUNIT_ASSERT_EQUAL(TEXT1_HASH_CRC32,digestImpl->digest());

  digestImpl->reset();
  digestImpl->update(TEXT2);
  CPPUNIT_ASSERT_EQUAL(TEXT2_HASH_CRC32,digestImpl->digest());

  digestImpl->reset();
  digestImpl->update(text.c_str(),5,text.length()-5);
  CPPUNIT_ASSERT_EQUAL(TEXT1_HASH_CRC32,digestImpl->digest());
}

void MessageDigestTest :: testMD5Implementation (void)
{
  auto digestImpl = MessageDigest::createInstance("MD5");
  std::string text = TEXT2;

  CPPUNIT_ASSERT_EQUAL(ALGORITHM_MD5,digestImpl->getAlgorithm());

  digestImpl->update(TEXT1);
  CPPUNIT_ASSERT_EQUAL(TEXT1_HASH_MD5,digestImpl->digest());

  digestImpl->reset();
  digestImpl->update(TEXT2);
  CPPUNIT_ASSERT_EQUAL(TEXT2_HASH_MD5,digestImpl->digest());

  digestImpl->reset();
  digestImpl->update(text.c_str(),5,text.length()-5);
  CPPUNIT_ASSERT_EQUAL(TEXT1_HASH_MD5,digestImpl->digest());
}

void MessageDigestTest::testSHA1Implementation()
{
  auto digestImpl = MessageDigest::createInstance("SHA1");
  std::string text = TEXT2;

  CPPUNIT_ASSERT_EQUAL(ALGORITHM_SHA1,digestImpl->getAlgorithm());

  digestImpl->update(TEXT1);
  CPPUNIT_ASSERT_EQUAL(TEXT1_HASH_SHA1,digestImpl->digest());

  digestImpl->reset();
  digestImpl->update(TEXT2);
  CPPUNIT_ASSERT_EQUAL(TEXT2_HASH_SHA1,digestImpl->digest());

  digestImpl->reset();
  digestImpl->update(text.c_str(),5,text.length()-5);
  CPPUNIT_ASSERT_EQUAL(TEXT1_HASH_SHA1,digestImpl->digest());
}
