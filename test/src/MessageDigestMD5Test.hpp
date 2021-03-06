#ifndef MessageDigest_MD5Test_INCLUDED
#define MessageDigest_MD5Test_INCLUDED

#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>

class MessageDigestMD5Test : public CPPUNIT_NS :: TestFixture
{
  CPPUNIT_TEST_SUITE (MessageDigestMD5Test);
  CPPUNIT_TEST (testCallOperator);
  CPPUNIT_TEST (testUpdate);
  CPPUNIT_TEST (testUpdateWithOffset);
  CPPUNIT_TEST (testAvalancheEffect);
  CPPUNIT_TEST_SUITE_END ();

public:
  void setUp (void);
  void tearDown (void);

protected:
  void testCallOperator (void);
  void testUpdate (void);
  void testUpdateWithOffset (void);
  void testAvalancheEffect (void);

private:
};


#endif //MessageDigest_MD5Test_INCLUDED
