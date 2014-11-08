#ifndef MessageDigest_TestConstants_INCLUDED
#define MessageDigest_TestConstants_INCLUDED

#define ALGORITHM_MD5 std::string("MD5")
#define ALGORITHM_SHA1 std::string("SHA1")

#define TEXT1 std::string("Dies ist ein Test")
#define TEXT1_HASH_MD5 std::string("6cddeb6a2f0582c82dee9a38e3f035d7")
#define TEXT1_HASH_SHA1 std::string("46d35759feded708ecd4ac98368f9d4d0c2b61fd")

#define TEXT2 std::string("Blub Dies ist ein Test")
#define TEXT2_HASH_MD5 std::string("96f84b26452a4203b50f5620bf1e1258")
#define TEXT2_HASH_SHA1 std::string("fd67a6bb5303b3def9dacafe5f58814484c7e76b")

#define TEXT3 std::string("Franz jagt im komplett verwahrlosten Taxi quer durch Bayern")
#define TEXT3_HASH_MD5 std::string("a3cca2b2aa1e3b5b3b5aad99a8529074")
#define TEXT3_HASH_SHA1 std::string("68ac906495480a3404beee4874ed853a037a7a8f")

#define TEXT4 std::string("Granz jagt im komplett verwahrlosten Taxi quer durch Bayern")
#define TEXT4_HASH_MD5 std::string("fdf56a4d365ded5e048debb26b03848a")
#define TEXT4_HASH_SHA1 std::string("89fdde0b28373dc4f361cfb810b35342cc2c3232")

#endif //MessageDigest_TestConstants_INCLUDED
