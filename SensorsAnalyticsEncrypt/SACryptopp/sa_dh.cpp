// dh.cpp - originally written and placed in the public domain by Wei Dai

#include "sa_pch.h"

#ifndef CRYPTOPP_IMPORTS

#include "sa_dh.h"

NAMESPACE_BEGIN(SA_CryptoPP)

#if defined(CRYPTOPP_DEBUG) && !defined(CRYPTOPP_DOXYGEN_PROCESSING)
void DH_TestInstantiations()
{
	DH dh1;
	DH dh2(NullRNG(), 10);
}
#endif

NAMESPACE_END

#endif
