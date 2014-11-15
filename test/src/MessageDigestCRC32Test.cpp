#include "MessageDigestCRC32Test.hpp"
#include "MessageDigest/MessageDigestCRC32.hpp"
#include "TestConstants.h"

CPPUNIT_TEST_SUITE_REGISTRATION (MessageDigestCRC32Test);

void MessageDigestCRC32Test :: setUp (void)
{
}

void MessageDigestCRC32Test :: tearDown (void)
{
}

void MessageDigestCRC32Test :: testCallOperator (void)
{
  MessageDigestCRC32 digestCRC32;

  CPPUNIT_ASSERT_EQUAL(TEXT1_HASH_CRC32,digestCRC32(TEXT1));
  CPPUNIT_ASSERT_EQUAL(TEXT2_HASH_CRC32,digestCRC32(TEXT2));
  CPPUNIT_ASSERT_EQUAL(TEXT3_HASH_CRC32,digestCRC32(TEXT3));
  CPPUNIT_ASSERT_EQUAL(TEXT4_HASH_CRC32,digestCRC32(TEXT4));
}

void MessageDigestCRC32Test::testUpdate()
{
  MessageDigestCRC32 digestCRC32;
  std::string text = TEXT1;

  digestCRC32.update(text.c_str(),0,text.length());
  CPPUNIT_ASSERT_EQUAL(TEXT1_HASH_CRC32,digestCRC32.digest());
}

void MessageDigestCRC32Test :: testUpdateWithOffset (void)
{
  MessageDigestCRC32 digestCRC32;
  std::string text = TEXT2;

  digestCRC32.update(text.c_str(),5,text.length()-5);
  CPPUNIT_ASSERT_EQUAL(TEXT1_HASH_CRC32,digestCRC32.digest());
}

void MessageDigestCRC32Test::testAvalancheEffect()
{
  MessageDigestCRC32 digestCRC32;

  CPPUNIT_ASSERT_ASSERTION_FAIL( CPPUNIT_ASSERT_EQUAL( digestCRC32(TEXT3),digestCRC32(TEXT4) ) );
}
