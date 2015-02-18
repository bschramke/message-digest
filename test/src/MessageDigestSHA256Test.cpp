#include "MessageDigestSHA256Test.hpp"
#include "MessageDigest/MessageDigestSHA256.hpp"
#include "TestConstants.h"

CPPUNIT_TEST_SUITE_REGISTRATION (MessageDigestSHA256Test);

void MessageDigestSHA256Test :: setUp (void)
{
}

void MessageDigestSHA256Test :: tearDown (void)
{
}

void MessageDigestSHA256Test :: testCallOperator (void)
{
  MessageDigestSHA256 digestSHA256;

  CPPUNIT_ASSERT_EQUAL(TEXT1_HASH_SHA256,digestSHA256(TEXT1));
  CPPUNIT_ASSERT_EQUAL(TEXT2_HASH_SHA256,digestSHA256(TEXT2));
  CPPUNIT_ASSERT_EQUAL(TEXT3_HASH_SHA256,digestSHA256(TEXT3));
  CPPUNIT_ASSERT_EQUAL(TEXT4_HASH_SHA256,digestSHA256(TEXT4));
}

void MessageDigestSHA256Test :: testUpdate (void)
{
  MessageDigestSHA256 digestSHA256;
  std::string text = TEXT1;

  digestSHA256.update(text.c_str(),0,text.length());
  CPPUNIT_ASSERT_EQUAL(TEXT1_HASH_SHA256,digestSHA256.digest());
}

void MessageDigestSHA256Test :: testUpdateWithOffset (void)
{
  MessageDigestSHA256 digestSHA256;
  std::string text = TEXT2;

  digestSHA256.update(text.c_str(),5,text.length()-5);
  CPPUNIT_ASSERT_EQUAL(TEXT1_HASH_SHA256,digestSHA256.digest());
}

void MessageDigestSHA256Test::testAvalancheEffect()
{
  MessageDigestSHA256 digestSHA256;

  CPPUNIT_ASSERT_ASSERTION_FAIL( CPPUNIT_ASSERT_EQUAL( digestSHA256(TEXT3),digestSHA256(TEXT4) ) );

}
