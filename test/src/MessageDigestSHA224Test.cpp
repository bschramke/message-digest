#include "MessageDigestSHA224Test.hpp"
#include "MessageDigest/MessageDigestSHA224.hpp"
#include "TestConstants.h"

CPPUNIT_TEST_SUITE_REGISTRATION (MessageDigestSHA224Test);

void MessageDigestSHA224Test :: setUp (void)
{
}

void MessageDigestSHA224Test :: tearDown (void)
{
}

void MessageDigestSHA224Test :: testCallOperator (void)
{
  MessageDigestSHA224 digestSHA224;

  CPPUNIT_ASSERT_EQUAL(TEXT1_HASH_SHA224,digestSHA224(TEXT1));
  CPPUNIT_ASSERT_EQUAL(TEXT2_HASH_SHA224,digestSHA224(TEXT2));
  CPPUNIT_ASSERT_EQUAL(TEXT3_HASH_SHA224,digestSHA224(TEXT3));
  CPPUNIT_ASSERT_EQUAL(TEXT4_HASH_SHA224,digestSHA224(TEXT4));
}

void MessageDigestSHA224Test :: testUpdate (void)
{
  MessageDigestSHA224 digestSHA224;
  std::string text = TEXT1;

  digestSHA224.update(text.c_str(),0,text.length());
  CPPUNIT_ASSERT_EQUAL(TEXT1_HASH_SHA224,digestSHA224.digest());
}

void MessageDigestSHA224Test :: testUpdateWithOffset (void)
{
  MessageDigestSHA224 digestSHA224;
  std::string text = TEXT2;

  digestSHA224.update(text.c_str(),5,text.length()-5);
  CPPUNIT_ASSERT_EQUAL(TEXT1_HASH_SHA224,digestSHA224.digest());
}

void MessageDigestSHA224Test::testAvalancheEffect()
{
  MessageDigestSHA224 digestSHA224;

  CPPUNIT_ASSERT_ASSERTION_FAIL( CPPUNIT_ASSERT_EQUAL( digestSHA224(TEXT3),digestSHA224(TEXT4) ) );

}
