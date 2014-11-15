#ifndef MessageDigest_Test_INCLUDED
#define MessageDigest_Test_INCLUDED

#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>

class MessageDigestTest : public CPPUNIT_NS :: TestFixture
{
  CPPUNIT_TEST_SUITE (MessageDigestTest);
  CPPUNIT_TEST (testCRC32Implementation);
  CPPUNIT_TEST (testMD5Implementation);
  CPPUNIT_TEST (testSHA1Implementation);
  CPPUNIT_TEST_SUITE_END ();

public:
  void setUp (void);
  void tearDown (void);

protected:
  void testCRC32Implementation (void);
  void testMD5Implementation (void);
  void testSHA1Implementation (void);

private:
};

#endif //MessageDigest_Test_INCLUDED
