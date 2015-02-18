#ifndef MessageDigest_SHA256Test_INCLUDED
#define MessageDigest_SHA256Test_INCLUDED

#include <cppunit/TestFixture.h>
#include <cppunit/extensions/HelperMacros.h>

class MessageDigestSHA256Test : public CPPUNIT_NS :: TestFixture
{
  CPPUNIT_TEST_SUITE (MessageDigestSHA256Test);
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


#endif //MessageDigest_SHA256Test_INCLUDED
