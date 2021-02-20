// dsa.cpp - originally written and placed in the public domain by Wei Dai

#include "sa_pch.h"

#ifndef CRYPTOPP_IMPORTS

#include "sa_dsa.h"
#include "sa_asn.h"
#include "sa_integer.h"
#include "sa_filters.h"
#include "sa_nbtheory.h"

NAMESPACE_BEGIN(SA_CryptoPP)

size_t DSAConvertSignatureFormat(byte *buffer, size_t bufferSize, DSASignatureFormat toFormat, const byte *signature, size_t signatureLen, DSASignatureFormat fromFormat)
{
	Integer r, s;
	StringStore store(signature, signatureLen);
	ArraySink sink(buffer, bufferSize);

	switch (fromFormat)
	{
	case DSA_P1363:
		r.Decode(store, signatureLen/2);
		s.Decode(store, signatureLen/2);
		break;
	case DSA_DER:
	{
		BERSequenceDecoder seq(store);
		r.BERDecode(seq);
		s.BERDecode(seq);
		seq.MessageEnd();
		break;
	}
	case DSA_OPENPGP:
		r.OpenPGPDecode(store);
		s.OpenPGPDecode(store);
		break;
	}

	switch (toFormat)
	{
	case DSA_P1363:
		r.Encode(sink, bufferSize/2);
		s.Encode(sink, bufferSize/2);
		break;
	case DSA_DER:
	{
		DERSequenceEncoder seq(sink);
		r.DEREncode(seq);
		s.DEREncode(seq);
		seq.MessageEnd();
		break;
	}
	case DSA_OPENPGP:
		r.OpenPGPEncode(sink);
		s.OpenPGPEncode(sink);
		break;
	}

	return (size_t)sink.TotalPutLength();
}

NAMESPACE_END

#endif
