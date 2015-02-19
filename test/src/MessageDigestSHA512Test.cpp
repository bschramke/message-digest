#include "MessageDigestSHA512Test.hpp"
#include "MessageDigest/MessageDigestSHA512.hpp"
#include "TestConstants.h"

CPPUNIT_TEST_SUITE_REGISTRATION (MessageDigestSHA512Test);

void MessageDigestSHA512Test :: setUp (void)
{
}

void MessageDigestSHA512Test :: tearDown (void)
{
}

void MessageDigestSHA512Test :: testCallOperator (void)
{
  MessageDigestSHA512 digestSHA512;

  CPPUNIT_ASSERT_EQUAL(TEXT1_HASH_SHA512,digestSHA512(TEXT1));
  CPPUNIT_ASSERT_EQUAL(TEXT2_HASH_SHA512,digestSHA512(TEXT2));
  CPPUNIT_ASSERT_EQUAL(TEXT3_HASH_SHA512,digestSHA512(TEXT3));
  CPPUNIT_ASSERT_EQUAL(TEXT4_HASH_SHA512,digestSHA512(TEXT4));
}

void MessageDigestSHA512Test :: testUpdate (void)
{
  MessageDigestSHA512 digestSHA512;
  std::string text = TEXT1;

  digestSHA512.update(text.c_str(),0,text.length());
  CPPUNIT_ASSERT_EQUAL(TEXT1_HASH_SHA512,digestSHA512.digest());
}

void MessageDigestSHA512Test :: testUpdateWithOffset (void)
{
  MessageDigestSHA512 digestSHA512;
  std::string text = TEXT2;

  digestSHA512.update(text.c_str(),5,text.length()-5);
  CPPUNIT_ASSERT_EQUAL(TEXT1_HASH_SHA512,digestSHA512.digest());
}

void MessageDigestSHA512Test::testAvalancheEffect()
{
  MessageDigestSHA512 digestSHA512;

  CPPUNIT_ASSERT_ASSERTION_FAIL( CPPUNIT_ASSERT_EQUAL( digestSHA512(TEXT3),digestSHA512(TEXT4) ) );

}
