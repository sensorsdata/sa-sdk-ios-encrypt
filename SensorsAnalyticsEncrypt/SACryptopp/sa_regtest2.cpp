// regtest2.cpp - originally written and placed in the public domain by Wei Dai
//                regtest.cpp split into 3 files due to OOM kills by JW
//                in April 2017. A second split occured in July 2018.

#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1

#include "sa_cryptlib.h"
#include "sa_factory.h"
#include "sa_bench.h"
#include "sa_cpu.h"

// For MAC's
#include "sa_hmac.h"
#include "sa_cmac.h"
#include "sa_dmac.h"
#include "sa_vmac.h"
#include "sa_ttmac.h"

// Ciphers
#include "sa_md5.h"
#include "sa_keccak.h"
#include "sa_sha.h"
#include "sa_sha3.h"
#include "sa_blake2.h"
#include "sa_ripemd.h"
#include "sa_chacha.h"
#include "sa_poly1305.h"
#include "sa_siphash.h"
#include "sa_panama.h"

// Stream ciphers
#include "sa_arc4.h"
#include "sa_seal.h"
#include "sa_wake.h"
#include "sa_chacha.h"
#include "sa_salsa.h"
#include "sa_rabbit.h"
#include "sa_hc128.h"
#include "sa_hc256.h"
#include "sa_panama.h"
#include "sa_sosemanuk.h"

// Block for CMAC
#include "sa_aes.h"
#include "sa_des.h"

// Aggressive stack checking with VS2005 SP1 and above.
#if (_MSC_FULL_VER >= 140050727)
# pragma strict_gs_check (on)
#endif

#if CRYPTOPP_MSC_VERSION
# pragma warning(disable: 4505 4355)
#endif

USING_NAMESPACE(SA_CryptoPP)

// MAC ciphers
void SA_RegisterFactories2()
{
	RegisterDefaultFactoryFor<MessageAuthenticationCode, HMAC<SA_Weak::MD5> >();
	RegisterDefaultFactoryFor<MessageAuthenticationCode, HMAC<RIPEMD160> >();
	RegisterDefaultFactoryFor<MessageAuthenticationCode, HMAC<SHA1> >();
	RegisterDefaultFactoryFor<MessageAuthenticationCode, HMAC<SHA224> >();
	RegisterDefaultFactoryFor<MessageAuthenticationCode, HMAC<SHA256> >();
	RegisterDefaultFactoryFor<MessageAuthenticationCode, HMAC<SHA384> >();
	RegisterDefaultFactoryFor<MessageAuthenticationCode, HMAC<SHA512> >();
	RegisterDefaultFactoryFor<MessageAuthenticationCode, TTMAC>();
	RegisterDefaultFactoryFor<MessageAuthenticationCode, VMAC<AES> >();
	RegisterDefaultFactoryFor<MessageAuthenticationCode, VMAC<AES, 64> >();
	RegisterDefaultFactoryFor<MessageAuthenticationCode, SA_Weak::PanamaMAC<LittleEndian> >();
	RegisterDefaultFactoryFor<MessageAuthenticationCode, SA_Weak::PanamaMAC<BigEndian> >();
	RegisterDefaultFactoryFor<MessageAuthenticationCode, CMAC<AES> >();
	RegisterDefaultFactoryFor<MessageAuthenticationCode, DMAC<AES> >();
	RegisterDefaultFactoryFor<MessageAuthenticationCode, Poly1305<AES> >();
	RegisterDefaultFactoryFor<MessageAuthenticationCode, Poly1305TLS>();
	RegisterDefaultFactoryFor<MessageAuthenticationCode, CMAC<DES_EDE3> >();
	RegisterDefaultFactoryFor<MessageAuthenticationCode, BLAKE2s>();
	RegisterDefaultFactoryFor<MessageAuthenticationCode, BLAKE2b>();
	RegisterDefaultFactoryFor<MessageAuthenticationCode, SipHash<2,4> >();
	RegisterDefaultFactoryFor<MessageAuthenticationCode, SipHash<4,8> >();
}

// Stream ciphers
void SA_RegisterFactories3()
{
	RegisterSymmetricCipherDefaultFactories<SA_Weak::MARC4>();
	RegisterSymmetricCipherDefaultFactories<SEAL<> >();
	RegisterSymmetricCipherDefaultFactories<SEAL<LittleEndian> >();
	RegisterSymmetricCipherDefaultFactories<WAKE_OFB<LittleEndian> >();
	RegisterSymmetricCipherDefaultFactories<WAKE_OFB<BigEndian> >();
	RegisterSymmetricCipherDefaultFactories<PanamaCipher<LittleEndian> >();
	RegisterSymmetricCipherDefaultFactories<PanamaCipher<BigEndian> >();

	RegisterSymmetricCipherDefaultFactories<Salsa20>();
	RegisterSymmetricCipherDefaultFactories<XSalsa20>();
	RegisterSymmetricCipherDefaultFactories<ChaCha>();
	RegisterSymmetricCipherDefaultFactories<ChaChaTLS>();
	RegisterSymmetricCipherDefaultFactories<XChaCha20>();
	RegisterSymmetricCipherDefaultFactories<Sosemanuk>();
	RegisterSymmetricCipherDefaultFactories<Rabbit>();
	RegisterSymmetricCipherDefaultFactories<RabbitWithIV>();
	RegisterSymmetricCipherDefaultFactories<HC128>();
	RegisterSymmetricCipherDefaultFactories<HC256>();
}
