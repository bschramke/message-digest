#include "MessageDigestSHA1Test.hpp"
#include "MessageDigest/MessageDigestSHA1.hpp"
#include "TestConstants.h"

CPPUNIT_TEST_SUITE_REGISTRATION (MessageDigestSHA1Test);

void MessageDigestSHA1Test :: setUp (void)
{
}

void MessageDigestSHA1Test :: tearDown (void)
{
}

void MessageDigestSHA1Test :: testCallOperator (void)
{
  MessageDigestSHA1 digestSHA1;

  CPPUNIT_ASSERT_EQUAL(TEXT1_HASH_SHA1,digestSHA1(TEXT1));
  CPPUNIT_ASSERT_EQUAL(TEXT2_HASH_SHA1,digestSHA1(TEXT2));
  CPPUNIT_ASSERT_EQUAL(TEXT3_HASH_SHA1,digestSHA1(TEXT3));
  CPPUNIT_ASSERT_EQUAL(TEXT4_HASH_SHA1,digestSHA1(TEXT4));
}

void MessageDigestSHA1Test :: testUpdate (void)
{
  MessageDigestSHA1 digestSHA1;
  std::string text = TEXT1;

  digestSHA1.update(text.c_str(),0,text.length());
  CPPUNIT_ASSERT_EQUAL(TEXT1_HASH_SHA1,digestSHA1.digest());
}

void MessageDigestSHA1Test :: testUpdateWithOffset (void)
{
  MessageDigestSHA1 digestSHA1;
  std::string text = TEXT2;

  digestSHA1.update(text.c_str(),5,text.length()-5);
  CPPUNIT_ASSERT_EQUAL(TEXT1_HASH_SHA1,digestSHA1.digest());
}

void MessageDigestSHA1Test::testAvalancheEffect()
{
  MessageDigestSHA1 digestSHA1;

  CPPUNIT_ASSERT_ASSERTION_FAIL( CPPUNIT_ASSERT_EQUAL( digestSHA1(TEXT3),digestSHA1(TEXT4) ) );

}
