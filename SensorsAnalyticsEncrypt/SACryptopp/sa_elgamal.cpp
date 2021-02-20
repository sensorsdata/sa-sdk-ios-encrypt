// elgamal.cpp - originally written and placed in the public domain by Wei Dai

#include "sa_pch.h"
#include "sa_elgamal.h"
#include "sa_asn.h"
#include "sa_nbtheory.h"

// Squash MS LNK4221 and libtool warnings
extern const char SA_ELGAMAL_FNAME[] = __FILE__;

NAMESPACE_BEGIN(SA_CryptoPP)

#if defined(CRYPTOPP_DEBUG) && !defined(CRYPTOPP_DOXYGEN_PROCESSING)
void ElGamal_TestInstantiations()
{
	ElGamalEncryptor test1(1, 1, 1);
	ElGamalDecryptor test2(NullRNG(), 123);
	ElGamalEncryptor test3(test2);
}
#endif

NAMESPACE_END
