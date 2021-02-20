// md2.h - originally written and placed in the public domain by Wei Dai

/// \file md2.h
/// \brief Classes for the MD2 message digest
/// \since Crypto++ 3.0

#ifndef CRYPTOPP_MD2_H
#define CRYPTOPP_MD2_H

#include "sa_cryptlib.h"
#include "sa_secblock.h"

NAMESPACE_BEGIN(SA_CryptoPP)

namespace SA_Weak1 {

/// \brief MD2 message digest
/// \sa <a href="http://www.cryptolounge.org/wiki/MD2">MD2</a>
/// \since Crypto++ 3.0
class MD2 : public HashTransformation
{
public:
	MD2();
	void Update(const byte *input, size_t length);
	void TruncatedFinal(byte *hash, size_t size);
	unsigned int DigestSize() const {return DIGESTSIZE;}
	unsigned int BlockSize() const {return BLOCKSIZE;}
	CRYPTOPP_STATIC_CONSTEXPR const char* StaticAlgorithmName() {return "MD2";}

	CRYPTOPP_CONSTANT(DIGESTSIZE = 16);
	CRYPTOPP_CONSTANT(BLOCKSIZE = 16);

private:
	void Transform();
	void Init();
	SecByteBlock m_X, m_C, m_buf;
	unsigned int m_count;
};

}
#if CRYPTOPP_ENABLE_NAMESPACE_WEAK >= 1
namespace SA_Weak {using namespace SA_Weak1;}		// import Weak1 into SA_CryptoPP::SA_Weak
#else
using namespace SA_Weak1;	// import Weak1 into CryptoPP with warning
#ifdef __GNUC__
#warning "You may be using a weak algorithm that has been retained for backwards compatibility. Please '#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1' before including this .h file and prepend the class name with 'SA_Weak::' to remove this warning."
#else
#pragma message("You may be using a weak algorithm that has been retained for backwards compatibility. Please '#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1' before including this .h file and prepend the class name with 'SA_Weak::' to remove this warning.")
#endif
#endif

NAMESPACE_END

#endif
