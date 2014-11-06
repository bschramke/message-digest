#ifndef MessageDigest_TestConstants_INCLUDED
#define MessageDigest_TestConstants_INCLUDED

#define ALGORITHM_MD5 std::string("MD5")

#define TEXT1 std::string("Dies ist ein Test")
#define TEXT1_HASH_MD5 std::string("6cddeb6a2f0582c82dee9a38e3f035d7")

#define TEXT2 std::string("Blub Dies ist ein Test")
#define TEXT2_HASH_MD5 std::string("96f84b26452a4203b50f5620bf1e1258")

#define TEXT3 std::string("Franz jagt im komplett verwahrlosten Taxi quer durch Bayern")
#define TEXT3_HASH_MD5 std::string("a3cca2b2aa1e3b5b3b5aad99a8529074")

#define TEXT4 std::string("Granz jagt im komplett verwahrlosten Taxi quer durch Bayern")
#define TEXT4_HASH_MD5 std::string("fdf56a4d365ded5e048debb26b03848a")

#endif //MessageDigest_TestConstants_INCLUDED
