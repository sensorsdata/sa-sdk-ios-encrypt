// regtest1.cpp - originally written and placed in the public domain by Wei Dai
//                regtest.cpp split into 3 files due to OOM kills by JW
//                in April 2017. A second split occured in July 2018.

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include "sa_cryptlib.h"
#include "sa_factory.h"
#include "sa_bench.h"
#include "sa_cpu.h"

#include "sa_crc.h"
#include "sa_adler32.h"
#include "sa_md2.h"
#include "sa_md5.h"
#include "sa_keccak.h"
#include "sa_sha3.h"
#include "sa_shake.h"
#include "sa_blake2.h"
#include "sa_sha.h"
#include "sa_sha3.h"
#include "sa_sm3.h"
#include "sa_hkdf.h"
#include "sa_tiger.h"
#include "sa_ripemd.h"
#include "sa_panama.h"
#include "sa_whrlpool.h"

#include "sa_osrng.h"
#include "sa_drbg.h"
#include "sa_darn.h"
#include "sa_mersenne.h"
#include "sa_rdrand.h"
#include "sa_padlkrng.h"

#include "sa_modes.h"
#include "sa_aes.h"

// Aggressive stack checking with VS2005 SP1 and above.
#if (_MSC_FULL_VER >= 140050727)
# pragma strict_gs_check (on)
#endif

#if CRYPTOPP_MSC_VERSION
# pragma warning(disable: 4505 4355)
#endif

USING_NAMESPACE(SA_CryptoPP)

// Unkeyed ciphers
void SA_RegisterFactories1();
// MAC ciphers
void SA_RegisterFactories2();
// Stream ciphers
void SA_RegisterFactories3();
// Block ciphers
void SA_RegisterFactories4();
// Public key ciphers
void SA_RegisterFactories5();

void RegisterFactories(SA_Test::TestClass suites)
{
	static bool s_registered = false;
	if (s_registered)
		return;

	if ((suites & SA_Test::Unkeyed) == SA_Test::Unkeyed)
		SA_RegisterFactories1();

	if ((suites & SA_Test::SharedKeyMAC) == SA_Test::SharedKeyMAC)
		SA_RegisterFactories2();

	if ((suites & SA_Test::SharedKeyStream) == SA_Test::SharedKeyStream)
		SA_RegisterFactories3();

	if ((suites & SA_Test::SharedKeyBlock) == SA_Test::SharedKeyBlock)
		SA_RegisterFactories4();

	if ((suites & SA_Test::PublicKey) == SA_Test::PublicKey)
		SA_RegisterFactories5();

	s_registered = true;
}

// Unkeyed ciphers
void SA_RegisterFactories1()
{
	RegisterDefaultFactoryFor<HashTransformation, CRC32>();
	RegisterDefaultFactoryFor<HashTransformation, CRC32C>();
	RegisterDefaultFactoryFor<HashTransformation, Adler32>();
	RegisterDefaultFactoryFor<HashTransformation, SA_Weak::MD5>();
	RegisterDefaultFactoryFor<HashTransformation, SHA1>();
	RegisterDefaultFactoryFor<HashTransformation, SHA224>();
	RegisterDefaultFactoryFor<HashTransformation, SHA256>();
	RegisterDefaultFactoryFor<HashTransformation, SHA384>();
	RegisterDefaultFactoryFor<HashTransformation, SHA512>();
	RegisterDefaultFactoryFor<HashTransformation, Whirlpool>();
	RegisterDefaultFactoryFor<HashTransformation, Tiger>();
	RegisterDefaultFactoryFor<HashTransformation, RIPEMD160>();
	RegisterDefaultFactoryFor<HashTransformation, RIPEMD320>();
	RegisterDefaultFactoryFor<HashTransformation, RIPEMD128>();
	RegisterDefaultFactoryFor<HashTransformation, RIPEMD256>();
	RegisterDefaultFactoryFor<HashTransformation, SA_Weak::PanamaHash<LittleEndian> >();
	RegisterDefaultFactoryFor<HashTransformation, SA_Weak::PanamaHash<BigEndian> >();
	RegisterDefaultFactoryFor<HashTransformation, Keccak_224>();
	RegisterDefaultFactoryFor<HashTransformation, Keccak_256>();
	RegisterDefaultFactoryFor<HashTransformation, Keccak_384>();
	RegisterDefaultFactoryFor<HashTransformation, Keccak_512>();
	RegisterDefaultFactoryFor<HashTransformation, SHA3_224>();
	RegisterDefaultFactoryFor<HashTransformation, SHA3_256>();
	RegisterDefaultFactoryFor<HashTransformation, SHA3_384>();
	RegisterDefaultFactoryFor<HashTransformation, SHA3_512>();
	RegisterDefaultFactoryFor<HashTransformation, SHAKE128>();
	RegisterDefaultFactoryFor<HashTransformation, SHAKE256>();
	RegisterDefaultFactoryFor<HashTransformation, SM3>();
	RegisterDefaultFactoryFor<HashTransformation, BLAKE2s>();
	RegisterDefaultFactoryFor<HashTransformation, BLAKE2b>();

#ifdef BLOCKING_RNG_AVAILABLE
	RegisterDefaultFactoryFor<RandomNumberGenerator, BlockingRng>();
#endif
#ifdef NONBLOCKING_RNG_AVAILABLE
	RegisterDefaultFactoryFor<RandomNumberGenerator, NonblockingRng>();
#endif
#ifdef OS_RNG_AVAILABLE
	RegisterDefaultFactoryFor<RandomNumberGenerator, AutoSeededRandomPool>();
	RegisterDefaultFactoryFor<RandomNumberGenerator, AutoSeededX917RNG<AES> >();
#endif
	RegisterDefaultFactoryFor<RandomNumberGenerator, MT19937>();
#if (CRYPTOPP_BOOL_X86)
	if (HasPadlockRNG())
		RegisterDefaultFactoryFor<RandomNumberGenerator, PadlockRNG>();
#endif
#if (CRYPTOPP_BOOL_X86 || CRYPTOPP_BOOL_X32 || CRYPTOPP_BOOL_X64)
	if (HasRDRAND())
		RegisterDefaultFactoryFor<RandomNumberGenerator, RDRAND>();
	if (HasRDSEED())
		RegisterDefaultFactoryFor<RandomNumberGenerator, RDSEED>();
#endif
#if (CRYPTOPP_BOOL_PPC32 || CRYPTOPP_BOOL_PPC64)
	if (HasDARN())
		RegisterDefaultFactoryFor<RandomNumberGenerator, DARN>();
#endif
	RegisterDefaultFactoryFor<RandomNumberGenerator, OFB_Mode<AES>::Encryption >("AES/OFB RNG");
	RegisterDefaultFactoryFor<NIST_DRBG, Hash_DRBG<SHA1> >("Hash_DRBG(SHA1)");
	RegisterDefaultFactoryFor<NIST_DRBG, Hash_DRBG<SHA256> >("Hash_DRBG(SHA256)");
	RegisterDefaultFactoryFor<NIST_DRBG, HMAC_DRBG<SHA1> >("HMAC_DRBG(SHA1)");
	RegisterDefaultFactoryFor<NIST_DRBG, HMAC_DRBG<SHA256> >("HMAC_DRBG(SHA256)");

	RegisterDefaultFactoryFor<KeyDerivationFunction, HKDF<SHA1> >();
	RegisterDefaultFactoryFor<KeyDerivationFunction, HKDF<SHA256> >();
	RegisterDefaultFactoryFor<KeyDerivationFunction, HKDF<SHA512> >();
	RegisterDefaultFactoryFor<KeyDerivationFunction, HKDF<Whirlpool> >();
}
