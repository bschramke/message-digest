#include "MessageDigestMD5Test.hpp"
#include "MessageDigest/MessageDigestMD5.hpp"
#include "TestConstants.h"

CPPUNIT_TEST_SUITE_REGISTRATION (MessageDigestMD5Test);

void MessageDigestMD5Test :: setUp (void)
{
}

void MessageDigestMD5Test :: tearDown (void)
{
}

void MessageDigestMD5Test :: testCallOperator (void)
{
  MessageDigestMD5 digestMD5;

  CPPUNIT_ASSERT_EQUAL(TEXT1_HASH_MD5,digestMD5(TEXT1));
  CPPUNIT_ASSERT_EQUAL(TEXT2_HASH_MD5,digestMD5(TEXT2));
  CPPUNIT_ASSERT_EQUAL(TEXT3_HASH_MD5,digestMD5(TEXT3));
  CPPUNIT_ASSERT_EQUAL(TEXT4_HASH_MD5,digestMD5(TEXT4));
}

void MessageDigestMD5Test :: testUpdate (void)
{
  MessageDigestMD5 digestMD5;
  std::string text = TEXT1;

  digestMD5.update(text.c_str(),0,text.length());
  CPPUNIT_ASSERT_EQUAL(TEXT1_HASH_MD5,digestMD5.digest());
}

void MessageDigestMD5Test :: testUpdateWithOffset (void)
{
  MessageDigestMD5 digestMD5;
  std::string text = TEXT2;

  digestMD5.reset();
  digestMD5.update(text.c_str(),5,text.length()-5);
  CPPUNIT_ASSERT_EQUAL(TEXT1_HASH_MD5,digestMD5.digest());
}

void MessageDigestMD5Test :: testAvalancheEffect ()
{
  MessageDigestMD5 digestMD5;

  CPPUNIT_ASSERT_ASSERTION_FAIL( CPPUNIT_ASSERT_EQUAL( digestMD5(TEXT3),digestMD5(TEXT4) ) );

}
