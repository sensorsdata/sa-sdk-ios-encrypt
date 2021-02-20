// dll.h - originally written and placed in the public domain by Wei Dai

/// \file dll.h
/// \brief Functions and definitions required for building the FIPS-140 DLL on Windows

#ifndef CRYPTOPP_DLL_H
#define CRYPTOPP_DLL_H

#if !defined(CRYPTOPP_IMPORTS) && !defined(CRYPTOPP_EXPORTS) && !defined(CRYPTOPP_DEFAULT_NO_DLL)
#ifdef CRYPTOPP_CONFIG_H
#error To use the DLL version of Crypto++, this file must be included before any other Crypto++ header files.
#endif
#define CRYPTOPP_IMPORTS
#endif

#include "sa_aes.h"
#include "sa_cbcmac.h"
#include "sa_ccm.h"
#include "sa_cmac.h"
#include "sa_channels.h"
#include "sa_des.h"
#include "sa_dh.h"
#include "sa_dsa.h"
#include "sa_ec2n.h"
#include "sa_eccrypto.h"
#include "sa_ecp.h"
#include "sa_files.h"
#include "sa_fips140.h"
#include "sa_gcm.h"
#include "sa_hex.h"
#include "sa_hmac.h"
#include "sa_modes.h"
#include "sa_mqueue.h"
#include "sa_nbtheory.h"
#include "sa_osrng.h"
#include "sa_pkcspad.h"
#include "sa_pssr.h"
#include "sa_randpool.h"
#include "sa_rsa.h"
#include "sa_rw.h"
#include "sa_sha.h"
#include "sa_skipjack.h"

#ifdef CRYPTOPP_IMPORTS

#ifdef _DLL
// cause CRT DLL to be initialized before Crypto++ so that we can use malloc and free during DllMain()
#ifdef CRYPTOPP_DEBUG
# pragma comment(lib, "msvcrtd")
# pragma comment(lib, "cryptopp")
#else
# pragma comment(lib, "msvcrt")
# pragma comment(lib, "cryptopp")
#endif
#endif

#endif		// #ifdef CRYPTOPP_IMPORTS

#include <new>	// for new_handler

NAMESPACE_BEGIN(SA_CryptoPP)

typedef void * (CRYPTOPP_API * PNew)(size_t);
typedef void (CRYPTOPP_API * PDelete)(void *);
typedef void (CRYPTOPP_API * PGetNewAndDelete)(PNew &, PDelete &);
typedef std::new_handler (CRYPTOPP_API * PSetNewHandler)(std::new_handler);
typedef void (CRYPTOPP_API * PSetNewAndDelete)(PNew, PDelete, PSetNewHandler);

NAMESPACE_END

#endif
