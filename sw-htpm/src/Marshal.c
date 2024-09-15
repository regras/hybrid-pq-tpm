/********************************************************************************/
/*										*/
/*			  Parameter Marshaling   				*/
/*			     Written by Ken Goldman				*/
/*		       IBM Thomas J. Watson Research Center			*/
/*            $Id: Marshal.c 1262 2018-07-11 21:03:43Z kgoldman $		*/
/*										*/
/*  Licenses and Notices							*/
/*										*/
/*  1. Copyright Licenses:							*/
/*										*/
/*  - Trusted Computing Group (TCG) grants to the user of the source code in	*/
/*    this specification (the "Source Code") a worldwide, irrevocable, 		*/
/*    nonexclusive, royalty free, copyright license to reproduce, create 	*/
/*    derivative works, distribute, display and perform the Source Code and	*/
/*    derivative works thereof, and to grant others the rights granted herein.	*/
/*										*/
/*  - The TCG grants to the user of the other parts of the specification 	*/
/*    (other than the Source Code) the rights to reproduce, distribute, 	*/
/*    display, and perform the specification solely for the purpose of 		*/
/*    developing products based on such documents.				*/
/*										*/
/*  2. Source Code Distribution Conditions:					*/
/*										*/
/*  - Redistributions of Source Code must retain the above copyright licenses, 	*/
/*    this list of conditions and the following disclaimers.			*/
/*										*/
/*  - Redistributions in binary form must reproduce the above copyright 	*/
/*    licenses, this list of conditions	and the following disclaimers in the 	*/
/*    documentation and/or other materials provided with the distribution.	*/
/*										*/
/*  3. Disclaimers:								*/
/*										*/
/*  - THE COPYRIGHT LICENSES SET FORTH ABOVE DO NOT REPRESENT ANY FORM OF	*/
/*  LICENSE OR WAIVER, EXPRESS OR IMPLIED, BY ESTOPPEL OR OTHERWISE, WITH	*/
/*  RESPECT TO PATENT RIGHTS HELD BY TCG MEMBERS (OR OTHER THIRD PARTIES)	*/
/*  THAT MAY BE NECESSARY TO IMPLEMENT THIS SPECIFICATION OR OTHERWISE.		*/
/*  Contact TCG Administration (admin@trustedcomputinggroup.org) for 		*/
/*  information on specification licensing rights available through TCG 	*/
/*  membership agreements.							*/
/*										*/
/*  - THIS SPECIFICATION IS PROVIDED "AS IS" WITH NO EXPRESS OR IMPLIED 	*/
/*    WARRANTIES WHATSOEVER, INCLUDING ANY WARRANTY OF MERCHANTABILITY OR 	*/
/*    FITNESS FOR A PARTICULAR PURPOSE, ACCURACY, COMPLETENESS, OR 		*/
/*    NONINFRINGEMENT OF INTELLECTUAL PROPERTY RIGHTS, OR ANY WARRANTY 		*/
/*    OTHERWISE ARISING OUT OF ANY PROPOSAL, SPECIFICATION OR SAMPLE.		*/
/*										*/
/*  - Without limitation, TCG and its members and licensors disclaim all 	*/
/*    liability, including liability for infringement of any proprietary 	*/
/*    rights, relating to use of information in this specification and to the	*/
/*    implementation of this specification, and TCG disclaims all liability for	*/
/*    cost of procurement of substitute goods or services, lost profits, loss 	*/
/*    of use, loss of data or any incidental, consequential, direct, indirect, 	*/
/*    or special damages, whether under contract, tort, warranty or otherwise, 	*/
/*    arising in any way out of use or reliance upon this specification or any 	*/
/*    information herein.							*/
/*										*/
/*  (c) Copyright IBM Corp. and others, 2016 - 2018				*/
/*										*/
/********************************************************************************/

/* rev 136 */

#include <string.h>

#include "Tpm.h"
#include "Marshal_fp.h"

UINT32
UINT8_Marshal(UINT8 *source, BYTE **buffer, UINT32 *size)
{
    if (buffer != NULL) {
	if ((size == NULL) || ((UINT32)*size >= sizeof(UINT8))) {

	    (*buffer)[0] = *source;
	    *buffer += sizeof(UINT8);

	    if (size != NULL) {
		*size -= sizeof(UINT8);
	    }
	}
	else {
	    pAssert(FALSE);
	}
    }
    return sizeof(UINT8);
}

UINT32
INT8_Marshal(INT8 *source, BYTE **buffer, UINT32 *size)
{
    return UINT8_Marshal((UINT8 *)source, buffer, size);
}

UINT32
UINT16_Marshal(UINT16 *source, BYTE **buffer, UINT32 *size)
{
    if (buffer != NULL) {
	if ((size == NULL) || ((UINT32)*size >= sizeof(UINT16))) {

	    (*buffer)[0] = (BYTE)((*source >> 8) & 0xff);
	    (*buffer)[1] = (BYTE)((*source >> 0) & 0xff);
	    *buffer += sizeof(UINT16);

	    if (size != NULL) {
		*size -= sizeof(UINT16);
	    }
	}
	else {
	    pAssert(FALSE);
	}
    }
    return sizeof(UINT16);
}

UINT32
UINT32_Marshal(UINT32 *source, BYTE **buffer, UINT32 *size)
{
    if (buffer != NULL) {
	if ((size == NULL) || ((UINT32)*size >= sizeof(UINT32))) {

	    (*buffer)[0] = (BYTE)((*source >> 24) & 0xff);
	    (*buffer)[1] = (BYTE)((*source >> 16) & 0xff);
	    (*buffer)[2] = (BYTE)((*source >>  8) & 0xff);
	    (*buffer)[3] = (BYTE)((*source >>  0) & 0xff);
	    *buffer += sizeof(UINT32);

	    if (size != NULL) {
		*size -= sizeof(UINT32);
	    }
	}
	else {
	    pAssert(FALSE);
	}
    }
    return sizeof(UINT32);
}

UINT32
INT32_Marshal(INT32 *source, BYTE **buffer, UINT32 *size)
{
    return UINT32_Marshal((UINT32 *)source, buffer, size);
}

UINT32
UINT64_Marshal(UINT64 *source, BYTE **buffer, UINT32 *size)
{
    if (buffer != NULL) {
	if ((size == NULL) || ((UINT32)*size >= sizeof(UINT64))) {

	    (*buffer)[0] = (BYTE)((*source >> 56) & 0xff);
	    (*buffer)[1] = (BYTE)((*source >> 48) & 0xff);
	    (*buffer)[2] = (BYTE)((*source >> 40) & 0xff);
	    (*buffer)[3] = (BYTE)((*source >> 32) & 0xff);
	    (*buffer)[4] = (BYTE)((*source >> 24) & 0xff);
	    (*buffer)[5] = (BYTE)((*source >> 16) & 0xff);
	    (*buffer)[6] = (BYTE)((*source >>  8) & 0xff);
	    (*buffer)[7] = (BYTE)((*source >>  0) & 0xff);
	    *buffer += sizeof(UINT64);

	    if (size != NULL) {
		*size -= sizeof(UINT64);
	    }
	}
	else {
	    pAssert(FALSE);
	}
    }
    return sizeof(UINT64);
}

UINT32
Array_Marshal(BYTE *sourceBuffer, UINT32 sourceSize, BYTE **buffer, UINT32 *size)
{
    if (buffer != NULL) {
        if ((size == NULL) || (*size >= sourceSize)) {
            memcpy(*buffer, sourceBuffer, sourceSize);

            *buffer += sourceSize;

            if (size != NULL) {
                *size -= sourceSize;
            }
        } else {
            pAssert(FALSE);
        }
    }

    return sourceSize;
}

UINT32
TPM2B_Marshal(TPM2B *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += UINT32_Marshal(&(source->size), buffer, size);
    written += Array_Marshal(source->buffer, source->size, buffer, size);
    return written;
}

/* Table 2:5 - Definition of Types for Documentation Clarity (TypedefTable()) */

UINT32
TPM_KEY_BITS_Marshal(TPM_KEY_BITS *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += UINT16_Marshal(source, buffer, size);
    return written;
}

/* Table 2:7 - Definition of TPM_GENERATED Constants (EnumTable()) */
UINT32
TPM_GENERATED_Marshal(TPM_GENERATED *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += UINT32_Marshal(source, buffer, size);
    return written;
}

/* Table 9 - Definition of (UINT16) TPM_ALG_ID Constants <IN/OUT, S> */

UINT32
TPM_ALG_ID_Marshal(TPM_ALG_ID *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += UINT16_Marshal(source, buffer, size);
    return written;
}

/* Table 10 - Definition of (UINT16) {ECC} TPM_ECC_CURVE Constants <IN/OUT, S> */

#if ALG_ECC
UINT32
TPM_ECC_CURVE_Marshal(TPM_ECC_CURVE *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += UINT16_Marshal(source, buffer, size);
    return written;
}
#endif

/* Table 12 - Definition of TPM_CC Constants */

UINT32
TPM_CC_Marshal(TPM_CC *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += UINT32_Marshal(source, buffer, size);
    return written;
}

/* Table 2:16 - Definition of TPM_RC Constants (EnumTable()) */

UINT32
TPM_RC_Marshal(TPM_RC *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += UINT32_Marshal(source, buffer, size);
    return written;
}

/* Table 2:19 - Definition of TPM_ST Constants (EnumTable()) */

UINT32
TPM_ST_Marshal(TPM_ST *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += UINT16_Marshal(source, buffer, size);
    return written;
}

/* Table 2:22 - Definition of TPM_CAP Constants (EnumTable()) */

UINT32
TPM_CAP_Marshal(TPM_CAP *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += UINT32_Marshal(source, buffer, size);
    return written;
}

/* Table 2:23 - Definition of TPM_PT Constants (EnumTable()) */

UINT32
TPM_PT_Marshal(TPM_PT *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += UINT32_Marshal(source, buffer, size);
    return written;
}

/* Table 2:24 - Definition of TPM_PT_PCR Constants (EnumTable()) */

UINT32
TPM_PT_PCR_Marshal(TPM_PT_PCR *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += UINT32_Marshal(source, buffer, size);
    return written;
}

/* Table 2:26 - Definition of Types for Handles (TypedefTable()) */

UINT32
TPM_HANDLE_Marshal(TPM_HANDLE *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += UINT32_Marshal(source, buffer, size);
    return written;
}

/* Table 2:30 - Definition of TPMA_ALGORITHM Bits (BitsTable()) */

UINT32
TPMA_ALGORITHM_Marshal(TPMA_ALGORITHM *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += UINT32_Marshal((UINT32 *)source, buffer, size);
    return written;
}

/* Table 2:31 - Definition of TPMA_OBJECT Bits (BitsTable()) */

UINT32
TPMA_OBJECT_Marshal(TPMA_OBJECT *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += UINT32_Marshal((UINT32 *)source, buffer, size);
    return written;
}

/* Table 2:32 - Definition of TPMA_SESSION Bits (BitsTable()) */

UINT32
TPMA_SESSION_Marshal(TPMA_SESSION *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += UINT8_Marshal(source, buffer, size);
    return written;
}

/* Table 2:33 - Definition of TPMA_LOCALITY Bits (BitsTable()) */

UINT32
TPMA_LOCALITY_Marshal(TPMA_LOCALITY *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += UINT8_Marshal(source, buffer, size);
    return written;
}

/* Table 2:37 - Definition of TPMA_CC Bits (BitsTable()) */

UINT32
TPMA_CC_Marshal(TPMA_CC *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += UINT32_Marshal((UINT32 *)source, buffer, size);
    return written;
}

/* Table 2:39 - Definition of TPMI_YES_NO Type (InterfaceTable()) */

UINT32
TPMI_YES_NO_Marshal(TPMI_YES_NO *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += UINT8_Marshal(source, buffer, size);
    return written;
}

/* Table 2:48 - Definition of TPMI_DH_CONTEXT Type (InterfaceTable()) */

UINT32
TPMI_DH_CONTEXT_Marshal(TPMI_DH_CONTEXT *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPM_HANDLE_Marshal(source, buffer, size);
    return written;
}

/* Table 2:49 - Definition of TPMI_DH_SAVED Type (InterfaceTable()) */

UINT32
TPMI_DH_SAVED_Marshal(TPMI_DH_CONTEXT *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPM_HANDLE_Marshal(source, buffer, size);
    return written;
}

//* Table 2:49 - Definition of TPMI_RH_HIERARCHY Type (InterfaceTable()) */

UINT32
TPMI_RH_HIERARCHY_Marshal(TPMI_RH_HIERARCHY *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPM_HANDLE_Marshal(source, buffer, size);
    return written;
}

/* Table 2:59 - Definition of TPMI_RH_NV_INDEX Type (InterfaceTable()) */

UINT32
TPMI_RH_NV_INDEX_Marshal(TPMI_RH_NV_INDEX *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPM_HANDLE_Marshal(source, buffer, size);
    return written;
}

/* Table 2:60 - Definition of TPMI_ALG_HASH Type (InterfaceTable()) */

UINT32
TPMI_ALG_HASH_Marshal(TPMI_ALG_HASH *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPM_ALG_ID_Marshal(source, buffer, size);
    return written;
}

/* Table 2:63 - Definition of TPMI_ALG_SYM_OBJECT Type (InterfaceTable()) */

UINT32
TPMI_ALG_SYM_OBJECT_Marshal(TPMI_ALG_SYM_OBJECT *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPM_ALG_ID_Marshal(source, buffer, size);
    return written;
}

/* Table 2:64 - Definition of TPMI_ALG_SYM_MODE Type (InterfaceTable()) */

UINT32
TPMI_ALG_SYM_MODE_Marshal(TPMI_ALG_SYM_MODE *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPM_ALG_ID_Marshal(source, buffer, size);
    return written;
}

/* Table 2:65 - Definition of TPMI_ALG_KDF Type (InterfaceTable()) */

UINT32
TPMI_ALG_KDF_Marshal(TPMI_ALG_KDF *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPM_ALG_ID_Marshal(source, buffer, size);
    return written;
}

/* Table 2:66 - Definition of TPMI_ALG_SIG_SCHEME Type (InterfaceTable()) */

UINT32
TPMI_ALG_SIG_SCHEME_Marshal(TPMI_ALG_SIG_SCHEME *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPM_ALG_ID_Marshal(source, buffer, size);
    return written;
}

/* Table 2:71 - Definition of TPMU_HA Union (StructuresTable()) */

UINT32
TPMU_HA_Marshal(TPMU_HA *source, BYTE **buffer, UINT32 *size, UINT32 selector)
{
    UINT32 written = 0;

    switch (selector) {
#if ALG_SHA1
      case TPM_ALG_SHA1:
	written += Array_Marshal(&source->sha1[0], SHA1_DIGEST_SIZE, buffer, size);
	break;
#endif
#if ALG_SHA256
      case TPM_ALG_SHA256:
	written += Array_Marshal(&source->sha256[0], SHA256_DIGEST_SIZE, buffer, size);
	break;
#endif
#if ALG_SHA384
      case TPM_ALG_SHA384:
	written += Array_Marshal(&source->sha384[0], SHA384_DIGEST_SIZE, buffer, size);
	break;
#endif
#if ALG_SHA512
      case TPM_ALG_SHA512:
	written += Array_Marshal(&source->sha512[0], SHA512_DIGEST_SIZE, buffer, size);
	break;
#endif
#if ALG_SM3_256
      case TPM_ALG_SM3_256:
	written += Array_Marshal(&source->sm3_256[0], SM3_256_DIGEST_SIZE, buffer, size);
	break;
#endif
#if ALG_SHA3_256
      case TPM_ALG_SHA3_256:
	written += Array_Marshal(&source->sha3_256[0], SHA3_256_DIGEST_SIZE, buffer, size);
	break;
#endif
#if ALG_SHA3_384
      case TPM_ALG_SHA3_384:
	written += Array_Marshal(&source->sha3_384[0], SHA3_384_DIGEST_SIZE, buffer, size);
	break;
#endif
#if ALG_SHA3_512
      case TPM_ALG_SHA3_512:
	written += Array_Marshal(&source->sha3_512[0], SHA3_512_DIGEST_SIZE, buffer, size);
	break;
#endif
#if ALG_SHAKE128
      case TPM_ALG_SHAKE128:
	written += Array_Marshal(&source->shake128[0], SHAKE128_DIGEST_SIZE, buffer, size);
	break;
#endif
#if ALG_SHAKE256
      case TPM_ALG_SHAKE256:
	written += Array_Marshal(&source->shake256[0], SHAKE256_DIGEST_SIZE, buffer, size);
	break;
#endif
      case TPM_ALG_NULL:
	break;
      default:
	pAssert(FALSE);
    }
    return written;
}

/* Table 2:72 - Definition of TPMT_HA Structure (StructuresTable()) */

UINT32
TPMT_HA_Marshal(TPMT_HA *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPMI_ALG_HASH_Marshal(&source->hashAlg, buffer, size);
    written += TPMU_HA_Marshal(&source->digest, buffer, size, source->hashAlg);
    return written;
}

/* Table 2:73 - Definition of TPM2B_DIGEST Structure (StructuresTable()) */

UINT32
TPM2B_DIGEST_Marshal(TPM2B_DIGEST *source, BYTE **buffer, UINT32 *size)
{
UINT32 written = 0;
written += TPM2B_Marshal(&source->b, buffer, size);
return written;
}

/* Table 2:74 - Definition of TPM2B_DATA Structure (StructuresTable()) */

UINT32
TPM2B_DATA_Marshal(TPM2B_DATA *source, BYTE **buffer, UINT32 *size)
{
UINT32 written = 0;
written += TPM2B_Marshal(&source->b, buffer, size);
return written;
}

/* Table 2:75 - Definition of Types for TPM2B_NONCE (TypedefTable()) */

UINT32
TPM2B_NONCE_Marshal(TPM2B_NONCE *source, BYTE **buffer, UINT32 *size)
{
UINT32 written = 0;
written += TPM2B_DIGEST_Marshal(source, buffer, size);
return written;
}

/* Table 2:76 - Definition of Types for TPM2B_AUTH (TypedefTable()) */

UINT32
TPM2B_AUTH_Marshal(TPM2B_AUTH *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPM2B_DIGEST_Marshal(source, buffer, size);
    return written;
}

/* Table 2:79 - Definition of TPM2B_MAX_BUFFER Structure (StructuresTable()) */

UINT32
TPM2B_MAX_BUFFER_Marshal(TPM2B_MAX_BUFFER *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPM2B_Marshal(&source->b, buffer, size);
    return written;
}

/* Table 2:80 - Definition of TPM2B_MAX_NV_BUFFER Structure (StructuresTable()) */

UINT32
TPM2B_MAX_NV_BUFFER_Marshal(TPM2B_MAX_NV_BUFFER *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPM2B_Marshal(&source->b, buffer, size);
    return written;
}

/* Table 80 - Definition of TPM2B_TIMEOUT Structure <IN/OUT> */
UINT32
TPM2B_TIMEOUT_Marshal(TPM2B_TIMEOUT *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPM2B_Marshal(&source->b, buffer, size);
    return written;
}

/* Table 2:82 - Definition of TPM2B_IV Structure (StructuresTable()) */

UINT32
TPM2B_IV_Marshal(TPM2B_IV *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPM2B_Marshal(&source->b, buffer, size);
    return written;
}

/* Table 2:84 - Definition of TPM2B_NAME Structure (StructuresTable()) */

UINT32
TPM2B_NAME_Marshal(TPM2B_NAME *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPM2B_Marshal(&source->b, buffer, size);
    return written;
}

/* Table 2:86 - Definition of TPMS_PCR_SELECTION Structure (StructuresTable()) */

UINT32
TPMS_PCR_SELECTION_Marshal(TPMS_PCR_SELECTION *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;

    written += TPMI_ALG_HASH_Marshal(&source->hash, buffer, size);
    written += UINT8_Marshal(&source->sizeofSelect, buffer, size);
    written += Array_Marshal(&source->pcrSelect[0], source->sizeofSelect, buffer, size);
    return written;
}

/* Table 2:89 - Definition of TPMT_TK_CREATION Structure (StructuresTable()) */

UINT32
TPMT_TK_CREATION_Marshal(TPMT_TK_CREATION *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;

    written += TPM_ST_Marshal(&source->tag, buffer, size);
    written += TPMI_RH_HIERARCHY_Marshal(&source->hierarchy, buffer, size);
    written += TPM2B_DIGEST_Marshal(&source->digest, buffer, size);
    return written;
}

/* Table 2:90 - Definition of TPMT_TK_VERIFIED Structure (StructuresTable()) */

UINT32
TPMT_TK_VERIFIED_Marshal(TPMT_TK_VERIFIED *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;

    written += TPM_ST_Marshal(&source->tag, buffer, size);
    written += TPMI_RH_HIERARCHY_Marshal(&source->hierarchy, buffer, size);
    written += TPM2B_DIGEST_Marshal(&source->digest, buffer, size);
    return written;
}

/* Table 2:91 - Definition of TPMT_TK_AUTH Structure (StructuresTable()) */

UINT32
TPMT_TK_AUTH_Marshal(TPMT_TK_AUTH *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;

    written += TPM_ST_Marshal(&source->tag, buffer, size);
    written += TPMI_RH_HIERARCHY_Marshal(&source->hierarchy, buffer, size);
    written += TPM2B_DIGEST_Marshal(&source->digest, buffer, size);
    return written;
}

/* Table 2:92 - Definition of TPMT_TK_HASHCHECK Structure (StructuresTable()) */

UINT32
TPMT_TK_HASHCHECK_Marshal(TPMT_TK_HASHCHECK *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;

    written += TPM_ST_Marshal(&source->tag, buffer, size);
    written += TPMI_RH_HIERARCHY_Marshal(&source->hierarchy, buffer, size);
    written += TPM2B_DIGEST_Marshal(&source->digest, buffer, size);
    return written;
}

/* Table 2:93 - Definition of TPMS_ALG_PROPERTY Structure (StructuresTable()) */

UINT32
TPMS_ALG_PROPERTY_Marshal(TPMS_ALG_PROPERTY *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;

    written += TPM_ALG_ID_Marshal(&source->alg, buffer, size);
    written += TPMA_ALGORITHM_Marshal(&source->algProperties, buffer, size);
    return written;
}

/* Table 2:95 - Definition of TPMS_TAGGED_PCR_SELECT Structure (StructuresTable()) */

UINT32
TPMS_TAGGED_PCR_SELECT_Marshal(TPMS_TAGGED_PCR_SELECT *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;

    written += TPM_PT_PCR_Marshal(&source->tag, buffer, size);
    written += UINT8_Marshal(&source->sizeofSelect, buffer, size);
    written += Array_Marshal(&source->pcrSelect[0], source->sizeofSelect, buffer, size);
    return written;
}

/* Table 2:96 - Definition of TPMS_TAGGED_POLICY Structure (StructuresTable()) */

UINT32
TPMS_TAGGED_POLICY_Marshal(TPMS_TAGGED_POLICY *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;

    written += TPM_HANDLE_Marshal(&source->handle, buffer, size);
    written += TPMT_HA_Marshal(&source->policyHash, buffer, size);
    return written;
}

/* Table 2:94 - Definition of TPMS_TAGGED_PROPERTY Structure (StructuresTable()) */

UINT32
TPMS_TAGGED_PROPERTY_Marshal(TPMS_TAGGED_PROPERTY *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;

    written += TPM_PT_Marshal(&source->property, buffer, size);
    written += UINT32_Marshal(&source->value, buffer, size);
    return written;
}

/* Table 2:97 - Definition of TPML_CC Structure (StructuresTable()) */

UINT32
TPML_CC_Marshal(TPML_CC *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    UINT32 i;

    written += UINT32_Marshal(&source->count, buffer, size);
    for (i = 0 ; i < source->count ; i++) {
	written += TPM_CC_Marshal(&source->commandCodes[i], buffer, size);
    }
    return written;
}

/* Table 2:98 - Definition of TPML_CCA Structure (StructuresTable()) */

UINT32
TPML_CCA_Marshal(TPML_CCA *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    UINT32 i;

    written += UINT32_Marshal(&source->count, buffer, size);
    for (i = 0 ; i < source->count ; i++) {
	written += TPMA_CC_Marshal(&source->commandAttributes[i], buffer, size);
    }
    return written;
}

/* Table 2:99 - Definition of TPML_ALG Structure (StructuresTable()) */

UINT32
TPML_ALG_Marshal(TPML_ALG *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    UINT32 i;

    written += UINT32_Marshal(&source->count, buffer, size);
    for (i = 0 ; i < source->count ; i++) {
	written += TPM_ALG_ID_Marshal(&source->algorithms[i], buffer, size);
    }
    return written;
}

/* Table 2:100 - Definition of TPML_HANDLE Structure (StructuresTable()) */

UINT32
TPML_HANDLE_Marshal(TPML_HANDLE *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    UINT32 i;

    written += UINT32_Marshal(&source->count, buffer, size);
    for (i = 0 ; i < source->count ; i++) {
	written += TPM_HANDLE_Marshal(&source->handle[i], buffer, size);
    }
    return written;
}

/* Table 2:101 - Definition of TPML_DIGEST Structure (StructuresTable()) */

UINT32
TPML_DIGEST_Marshal(TPML_DIGEST *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    UINT32 i;

    written += UINT32_Marshal(&source->count, buffer, size);
    for (i = 0 ; i < source->count ; i++) {
	written += TPM2B_DIGEST_Marshal(&source->digests[i], buffer, size);
    }
    return written;
}

/* Table 2:102 - Definition of TPML_DIGEST_VALUES Structure (StructuresTable()) */

UINT32
TPML_DIGEST_VALUES_Marshal(TPML_DIGEST_VALUES *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    UINT32 i;

    written += UINT32_Marshal(&source->count, buffer, size);
    for (i = 0 ; i < source->count ; i++) {
	written += TPMT_HA_Marshal(&source->digests[i], buffer, size);
    }
    return written;
}

/* Table 2:104 - Definition of TPML_PCR_SELECTION Structure (StructuresTable()) */

UINT32
TPML_PCR_SELECTION_Marshal(TPML_PCR_SELECTION *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    UINT32 i;

    written += UINT32_Marshal(&source->count, buffer, size);
    for (i = 0 ; i < source->count ; i++) {
	written += TPMS_PCR_SELECTION_Marshal(&source->pcrSelections[i], buffer, size);
    }
    return written;
}

/* Table 2:105 - Definition of TPML_ALG_PROPERTY Structure (StructuresTable()) */


UINT32
TPML_ALG_PROPERTY_Marshal(TPML_ALG_PROPERTY *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    UINT32 i;

    written += UINT32_Marshal(&source->count, buffer, size);
    for (i = 0 ; i < source->count ; i++) {
	written += TPMS_ALG_PROPERTY_Marshal(&source->algProperties[i], buffer, size);
    }
    return written;
}

//* Table 2:106 - Definition of TPML_TAGGED_TPM_PROPERTY Structure (StructuresTable()) */

UINT32
TPML_TAGGED_TPM_PROPERTY_Marshal(TPML_TAGGED_TPM_PROPERTY *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    UINT32 i;

    written += UINT32_Marshal(&source->count, buffer, size);
    for (i = 0 ; i < source->count ; i++) {
	written += TPMS_TAGGED_PROPERTY_Marshal(&source->tpmProperty[i], buffer, size);
    }
    return written;
}

/* Table 2:107 - Definition of TPML_TAGGED_PCR_PROPERTY Structure (StructuresTable()) */

UINT32
TPML_TAGGED_PCR_PROPERTY_Marshal(TPML_TAGGED_PCR_PROPERTY *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    UINT32 i;

    written += UINT32_Marshal(&source->count, buffer, size);
    for (i = 0 ; i < source->count ; i++) {
	written += TPMS_TAGGED_PCR_SELECT_Marshal(&source->pcrProperty[i], buffer, size);
    }
    return written;
}

/* Table 2:108 - Definition of TPML_ECC_CURVE Structure (StructuresTable()) */

UINT32
TPML_ECC_CURVE_Marshal(TPML_ECC_CURVE *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;

    UINT32 i;

    written += UINT32_Marshal(&source->count, buffer, size);
    for (i = 0 ; i < source->count ; i++) {
	written += TPM_ECC_CURVE_Marshal(&source->eccCurves[i], buffer, size);
    }
    return written;
}

/* Table 2:109 - Definition of TPML_TAGGED_POLICY Structure (StructuresTable()) */

UINT32
TPML_TAGGED_POLICY_Marshal(TPML_TAGGED_POLICY *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    UINT32 i;

    written += UINT32_Marshal(&source->count, buffer, size);
    for (i = 0 ; i < source->count ; i++) {
	written += TPMS_TAGGED_POLICY_Marshal(&source->policies[i], buffer, size);
    }
    return written;
}

/* Table 2:110 - Definition of TPMU_CAPABILITIES Union (StructuresTable()) */

UINT32
TPMU_CAPABILITIES_Marshal(TPMU_CAPABILITIES *source, BYTE **buffer, UINT32 *size, UINT32 selector)
{
    UINT32 written = 0;

    switch (selector) {
      case TPM_CAP_ALGS:
        written += TPML_ALG_PROPERTY_Marshal(&source->algorithms, buffer, size);
        break;
      case TPM_CAP_HANDLES:
        written += TPML_HANDLE_Marshal(&source->handles, buffer, size);
        break;
      case TPM_CAP_COMMANDS:
        written += TPML_CCA_Marshal(&source->command, buffer, size);
        break;
      case TPM_CAP_PP_COMMANDS:
        written += TPML_CC_Marshal(&source->ppCommands, buffer, size);
        break;
      case TPM_CAP_AUDIT_COMMANDS:
        written += TPML_CC_Marshal(&source->auditCommands, buffer, size);
        break;
      case TPM_CAP_PCRS:
        written += TPML_PCR_SELECTION_Marshal(&source->assignedPCR, buffer, size);
        break;
      case TPM_CAP_TPM_PROPERTIES:
        written += TPML_TAGGED_TPM_PROPERTY_Marshal(&source->tpmProperties, buffer, size);
        break;
      case TPM_CAP_PCR_PROPERTIES:
        written += TPML_TAGGED_PCR_PROPERTY_Marshal(&source->pcrProperties, buffer, size);
        break;
      case TPM_CAP_ECC_CURVES:
        written += TPML_ECC_CURVE_Marshal(&source->eccCurves, buffer, size);
        break;
      case TPM_CAP_AUTH_POLICIES:
        written += TPML_TAGGED_POLICY_Marshal(&source->authPolicies, buffer, size);
        break;
      default:
	pAssert(FALSE);
    }
    return written;
}

/* Table 2:111 - Definition of TPMS_CAPABILITY_DATA Structure (StructuresTable()) */

UINT32
TPMS_CAPABILITY_DATA_Marshal(TPMS_CAPABILITY_DATA *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;

    written += TPM_CAP_Marshal(&source->capability, buffer, size);
    written += TPMU_CAPABILITIES_Marshal(&source->data, buffer, size, source->capability);
    return written;
}

/* Table 2:112 - Definition of TPMS_CLOCK_INFO Structure (StructuresTable()) */

UINT32
TPMS_CLOCK_INFO_Marshal(TPMS_CLOCK_INFO *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;

    written += UINT64_Marshal(&source->clock, buffer, size);
    written += UINT32_Marshal(&source->resetCount, buffer, size);
    written += UINT32_Marshal(&source->restartCount, buffer, size);
    written += TPMI_YES_NO_Marshal(&source->safe, buffer, size);
    return written;
}

/* Table 2:113 - Definition of TPMS_TIME_INFO Structure (StructuresTable()) */

UINT32
TPMS_TIME_INFO_Marshal(TPMS_TIME_INFO *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;

    written += UINT64_Marshal(&source->time, buffer, size);
    written += TPMS_CLOCK_INFO_Marshal(&source->clockInfo, buffer, size);
    return written;
}

/* Table 2:114 - Definition of TPMS_TIME_ATTEST_INFO Structure (StructuresTable()) */

UINT32
TPMS_TIME_ATTEST_INFO_Marshal(TPMS_TIME_ATTEST_INFO *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;

    written += TPMS_TIME_INFO_Marshal(&source->time, buffer, size);
    written += UINT64_Marshal(&source->firmwareVersion, buffer, size);
    return written;
}

/* Table 2:115 - Definition of TPMS_CERTIFY_INFO Structure (StructuresTable()) */

UINT32
TPMS_CERTIFY_INFO_Marshal(TPMS_CERTIFY_INFO *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;

    written += TPM2B_NAME_Marshal(&source->name, buffer, size);
    written += TPM2B_NAME_Marshal(&source->qualifiedName, buffer, size);
    return written;
}

/* Table 2:116 - Definition of TPMS_QUOTE_INFO Structure (StructuresTable()) */

UINT32
TPMS_QUOTE_INFO_Marshal(TPMS_QUOTE_INFO *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;

    written += TPML_PCR_SELECTION_Marshal(&source->pcrSelect, buffer, size);
    written += TPM2B_DIGEST_Marshal(&source->pcrDigest, buffer, size);
    return written;
}

/* Table 2:117 - Definition of TPMS_COMMAND_AUDIT_INFO Structure (StructuresTable()) */

UINT32
TPMS_COMMAND_AUDIT_INFO_Marshal(TPMS_COMMAND_AUDIT_INFO *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;

    written += UINT64_Marshal(&source->auditCounter, buffer, size);
    written += TPM_ALG_ID_Marshal(&source->digestAlg, buffer, size);
    written += TPM2B_DIGEST_Marshal(&source->auditDigest, buffer, size);
    written += TPM2B_DIGEST_Marshal(&source->commandDigest, buffer, size);
    return written;
}

/* Table 2:118 - Definition of TPMS_SESSION_AUDIT_INFO Structure (StructuresTable()) */

UINT32
TPMS_SESSION_AUDIT_INFO_Marshal(TPMS_SESSION_AUDIT_INFO *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;

    written += TPMI_YES_NO_Marshal(&source->exclusiveSession, buffer, size);
    written += TPM2B_DIGEST_Marshal(&source->sessionDigest, buffer, size);
    return written;
}

/* Table 2:119 - Definition of TPMS_CREATION_INFO Structure (StructuresTable()) */

UINT32
TPMS_CREATION_INFO_Marshal(TPMS_CREATION_INFO *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;

    written += TPM2B_NAME_Marshal(&source->objectName, buffer, size);
    written += TPM2B_DIGEST_Marshal(&source->creationHash, buffer, size);
    return written;
}

/* Table 2:120 - Definition of TPMS_NV_CERTIFY_INFO Structure (StructuresTable()) */

UINT32
TPMS_NV_CERTIFY_INFO_Marshal(TPMS_NV_CERTIFY_INFO *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;

    written += TPM2B_NAME_Marshal(&source->indexName, buffer, size);
    written += UINT16_Marshal(&source->offset, buffer, size);
    written += TPM2B_MAX_NV_BUFFER_Marshal(&source->nvContents, buffer, size);
    return written;
}

/* Table 2:121 - Definition of TPMI_ST_ATTEST Type (InterfaceTable()) */

UINT32
TPMI_ST_ATTEST_Marshal(TPMI_ST_ATTEST *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPM_ST_Marshal(source, buffer, size);
    return written;
}

/* Table 2:122 - Definition of TPMU_ATTEST Union (StructuresTable()) */

UINT32
TPMU_ATTEST_Marshal(TPMU_ATTEST  *source, BYTE **buffer, UINT32 *size, UINT32 selector)
{
    UINT32 written = 0;

    switch (selector) {
      case TPM_ST_ATTEST_CERTIFY:
	written += TPMS_CERTIFY_INFO_Marshal(&source->certify, buffer, size);
	break;
      case TPM_ST_ATTEST_CREATION:
	written += TPMS_CREATION_INFO_Marshal(&source->creation, buffer, size);
	break;
      case TPM_ST_ATTEST_QUOTE:
	written += TPMS_QUOTE_INFO_Marshal(&source->quote, buffer, size);
	break;
      case TPM_ST_ATTEST_COMMAND_AUDIT:
	written += TPMS_COMMAND_AUDIT_INFO_Marshal(&source->commandAudit, buffer, size);
	break;
      case TPM_ST_ATTEST_SESSION_AUDIT:
	written += TPMS_SESSION_AUDIT_INFO_Marshal(&source->sessionAudit, buffer, size);
	break;
      case TPM_ST_ATTEST_TIME:
	written += TPMS_TIME_ATTEST_INFO_Marshal(&source->time, buffer, size);
	break;
      case TPM_ST_ATTEST_NV:
	written += TPMS_NV_CERTIFY_INFO_Marshal(&source->nv, buffer, size);
	break;
      default:
	pAssert(FALSE);
    }
    return written;
}

/* Table 2:123 - Definition of TPMS_ATTEST Structure (StructuresTable()) */

UINT32
TPMS_ATTEST_Marshal(TPMS_ATTEST  *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;

    written += TPM_GENERATED_Marshal(&source->magic, buffer, size);
    written += TPMI_ST_ATTEST_Marshal(&source->type, buffer, size);
    written += TPM2B_NAME_Marshal(&source->qualifiedSigner, buffer, size);
    written += TPM2B_DATA_Marshal(&source->extraData, buffer, size);
    written += TPMS_CLOCK_INFO_Marshal(&source->clockInfo, buffer, size);
    written += UINT64_Marshal(&source->firmwareVersion, buffer, size);
    written += TPMU_ATTEST_Marshal(&source->attested, buffer, size,source->type);
    return written;
}

/* Table 2:124 - Definition of TPM2B_ATTEST Structure (StructuresTable()) */

UINT32
TPM2B_ATTEST_Marshal(TPM2B_ATTEST *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPM2B_Marshal(&source->b, buffer, size);
    return written;
}

/* Table 2:127 - Definition of TPMI_AES_KEY_BITS Type (InterfaceTable()) */

UINT32
TPMI_AES_KEY_BITS_Marshal(TPMI_AES_KEY_BITS *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPM_KEY_BITS_Marshal(source, buffer, size);
    return written;
}

/* Table 2:128 - Definition of TPMU_SYM_KEY_BITS Union (StructuresTable()) */

UINT32
TPMU_SYM_KEY_BITS_Marshal(TPMU_SYM_KEY_BITS *source, BYTE **buffer, UINT32 *size, UINT32 selector)
{
    UINT32 written = 0;

    switch(selector) {
#if ALG_AES
      case TPM_ALG_AES:
	written += TPMI_AES_KEY_BITS_Marshal(&source->aes, buffer, size);
	break;
#endif
#if ALG_SM4
      case TPM_ALG_SM4:
	written += TPMI_SM4_KEY_BITS_Marshal(&source->sm4, buffer, size);
	break;
#endif
#if ALG_CAMELLIA
      case TPM_ALG_CAMELLIA:
	written += TPMI_CAMELLIA_KEY_BITS_Marshal(&source->camellia, buffer, size);
	break;
#endif
#if ALG_XOR
      case TPM_ALG_XOR:
	written += TPMI_ALG_HASH_Marshal(&source->xorr, buffer, size);
	break;
#endif
      case TPM_ALG_NULL:
	break;
      default:
	pAssert(FALSE);
    }
    return written;
}

/* Table 2:129 - Definition of TPMU_SYM_MODE Union (StructuresTable()) */

UINT32
TPMU_SYM_MODE_Marshal(TPMU_SYM_MODE *source, BYTE **buffer, UINT32 *size, UINT32 selector)
{
    UINT32 written = 0;

    switch (selector) {
#if ALG_AES
      case TPM_ALG_AES:
	written += TPMI_ALG_SYM_MODE_Marshal(&source->aes, buffer, size);
	break;
#endif
#if ALG_SM4
      case TPM_ALG_SM4:
	written += TPMI_ALG_SYM_MODE_Marshal(&source->sm4, buffer, size);
	break;
#endif
#if ALG_CAMELLIA
      case TPM_ALG_CAMELLIA:
	written += TPMI_ALG_SYM_MODE_Marshal(&source->camellia, buffer, size);
	break;
#endif
#if ALG_XOR
      case TPM_ALG_XOR:
#endif
      case TPM_ALG_NULL:
	break;
      default:
	pAssert(FALSE);
    }
    return written;
}

/* Table 2:132 - Definition of TPMT_SYM_DEF_OBJECT Structure (StructuresTable()) */

UINT32
TPMT_SYM_DEF_OBJECT_Marshal(TPMT_SYM_DEF_OBJECT *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;

    written += TPMI_ALG_SYM_OBJECT_Marshal(&source->algorithm, buffer, size);
    written += TPMU_SYM_KEY_BITS_Marshal(&source->keyBits, buffer, size, source->algorithm);
    written += TPMU_SYM_MODE_Marshal(&source->mode, buffer, size, source->algorithm);
    return written;
}

/* Table 2:133 - Definition of TPM2B_SYM_KEY Structure (StructuresTable()) */

UINT32
TPM2B_SYM_KEY_Marshal(TPM2B_SYM_KEY *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPM2B_Marshal(&source->b, buffer, size);
    return written;
}

/* Table 2:134 - Definition of TPMS_SYMCIPHER_PARMS Structure (StructuresTable()) */

UINT32
TPMS_SYMCIPHER_PARMS_Marshal(TPMS_SYMCIPHER_PARMS *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;

    written += TPMT_SYM_DEF_OBJECT_Marshal(&source->sym, buffer, size);
    return written;
}

/* Table 2:139 - Definition of TPM2B_SENSITIVE_DATA Structure (StructuresTable()) */

UINT32
TPM2B_SENSITIVE_DATA_Marshal(TPM2B_SENSITIVE_DATA *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPM2B_Marshal(&source->b, buffer, size);
    return written;
}

/* Table 2:142 - Definition of TPMS_SCHEME_HASH Structure (StructuresTable()) */

UINT32
TPMS_SCHEME_HASH_Marshal(TPMS_SCHEME_HASH *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;

    written += TPMI_ALG_HASH_Marshal(&source->hashAlg, buffer, size);
    return written;
}

/* Table 2:143 - Definition of TPMS_SCHEME_ECDAA Structure (StructuresTable()) */

UINT32
TPMS_SCHEME_ECDAA_Marshal(TPMS_SCHEME_ECDAA *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;

    written += TPMI_ALG_HASH_Marshal(&source->hashAlg, buffer, size);
    written += UINT16_Marshal(&source->count, buffer, size);
    return written;
}

/* Table 2:144 - Definition of TPMI_ALG_KEYEDHASH_SCHEME Type (InterfaceTable()) */

UINT32
TPMI_ALG_KEYEDHASH_SCHEME_Marshal(TPMI_ALG_KEYEDHASH_SCHEME *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPM_ALG_ID_Marshal(source, buffer, size);
    return written;
}

/* Table 2:145 - Definition of Types for HMAC_SIG_SCHEME (TypedefTable()) */

UINT32
TPMS_SCHEME_HMAC_Marshal(TPMS_SCHEME_HMAC *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPMS_SCHEME_HASH_Marshal(source, buffer, size);
    return written;
}

/* Table 2:146 - Definition of TPMS_SCHEME_XOR Structure (StructuresTable()) */

UINT32
TPMS_SCHEME_XOR_Marshal(TPMS_SCHEME_XOR *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;

    written += TPMI_ALG_HASH_Marshal(&source->hashAlg, buffer, size);
    written += TPMI_ALG_KDF_Marshal(&source->kdf, buffer, size);
    return written;
}

/* Table 2:148 - Definition of TPMT_KEYEDHASH_SCHEME Structure (StructuresTable()) */

UINT32
TPMT_KEYEDHASH_SCHEME_Marshal(TPMT_KEYEDHASH_SCHEME *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;

    written += TPMI_ALG_KEYEDHASH_SCHEME_Marshal(&source->scheme, buffer, size);
    written += TPMU_SCHEME_KEYEDHASH_Marshal(&source->details, buffer, size, source->scheme);
    return written;
}

/*****************************************************************************/
/*                             Dilithium Mods                                */
/*****************************************************************************/
UINT32
TPMS_SIG_SCHEME_DILITHIUM_Marshal(TPMS_SIG_SCHEME_DILITHIUM *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPMS_SCHEME_HASH_Marshal(source, buffer, size);
    return written;
}
/*****************************************************************************/
/*                             Dilithium Mods                                */
/*****************************************************************************/

/* Table 2:149 - Definition of Types for RSA Signature Schemes (TypedefTable()) */

UINT32
TPMS_SIG_SCHEME_RSASSA_Marshal(TPMS_SIG_SCHEME_RSASSA *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPMS_SCHEME_HASH_Marshal(source, buffer, size);
    return written;
}

UINT32
TPMS_SIG_SCHEME_RSAPSS_Marshal(TPMS_SIG_SCHEME_RSAPSS *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPMS_SCHEME_HASH_Marshal(source, buffer, size);
    return written;
}

/* Table 2:150 - Definition of Types for ECC Signature Schemes (TypedefTable()) */

UINT32
TPMS_SIG_SCHEME_ECDSA_Marshal(TPMS_SIG_SCHEME_ECDSA *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPMS_SCHEME_HASH_Marshal(source, buffer, size);
    return written;
}
UINT32
TPMS_SIG_SCHEME_ECSCHNORR_Marshal(TPMS_SIG_SCHEME_ECSCHNORR *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPMS_SCHEME_HASH_Marshal(source, buffer, size);
    return written;
}
UINT32
TPMS_SIG_SCHEME_ECDAA_Marshal(TPMS_SIG_SCHEME_ECDAA *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPMS_SCHEME_ECDAA_Marshal(source, buffer, size);
    return written;
}

/* Table 2:153 - Definition of Types for Encryption Schemes (TypedefTable()) */

UINT32
TPMS_ENC_SCHEME_OAEP_Marshal(TPMS_ENC_SCHEME_OAEP *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPMS_SCHEME_HASH_Marshal(source, buffer, size);
    return written;
}

UINT32
TPMS_ENC_SCHEME_KYBER_Marshal(TPMS_ENC_SCHEME_KYBER *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPMS_SCHEME_HASH_Marshal(source, buffer, size);
    return written;
}

/* Table 146 - Definition of Types for {RSA} Encryption Schemes */

UINT32
TPMS_ENC_SCHEME_RSAES_Marshal(TPMS_ENC_SCHEME_RSAES *source, BYTE **buffer, UINT32 *size)
{
    source = source;
    buffer = buffer;
    size = size;
    return 0;
}

/* Table 2:147 - Definition of TPMU_SCHEME_KEYEDHASH Union (StructuresTable()) */

UINT32
TPMU_SCHEME_KEYEDHASH_Marshal(TPMU_SCHEME_KEYEDHASH *source, BYTE **buffer, UINT32 *size, UINT32 selector)
{
    UINT32 written = 0;

    switch (selector) {
#if ALG_HMAC
      case TPM_ALG_HMAC:
	written += TPMS_SCHEME_HMAC_Marshal(&source->hmac, buffer, size);
	break;
#endif
#if ALG_XOR
      case TPM_ALG_XOR:
	written += TPMS_SCHEME_XOR_Marshal(&source->xorr, buffer, size);
	break;
#endif
      case TPM_ALG_NULL:
	break;
      default:
	pAssert(FALSE);
    }
    return written;
}

/* Table 2:154 - Definition of Types for ECC Key Exchange (TypedefTable()) */

UINT32
TPMS_KEY_SCHEME_ECDH_Marshal(TPMS_KEY_SCHEME_ECDH *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPMS_SCHEME_HASH_Marshal(source, buffer, size);
    return written;
}

UINT32
TPMS_KEY_SCHEME_ECMQV_Marshal(TPMS_KEY_SCHEME_ECMQV*source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPMS_SCHEME_HASH_Marshal(source, buffer, size);
    return written;
}

/* Table 2:155 - Definition of Types for KDF Schemes (TypedefTable()) */
UINT32
TPMS_SCHEME_MGF1_Marshal(TPMS_SCHEME_MGF1 *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPMS_SCHEME_HASH_Marshal(source, buffer, size);
    return written;
}
UINT32
TPMS_SCHEME_KDF1_SP800_56A_Marshal(TPMS_SCHEME_KDF1_SP800_56A *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPMS_SCHEME_HASH_Marshal(source, buffer, size);
    return written;
}
UINT32
TPMS_SCHEME_KDF2_Marshal(TPMS_SCHEME_KDF2 *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPMS_SCHEME_HASH_Marshal(source, buffer, size);
    return written;
}
UINT32
TPMS_SCHEME_KDF1_SP800_108_Marshal(TPMS_SCHEME_KDF1_SP800_108 *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPMS_SCHEME_HASH_Marshal(source, buffer, size);
    return written;
}

/* Table 2:156 - Definition of TPMU_KDF_SCHEME Union (StructuresTable()) */

UINT32
TPMU_KDF_SCHEME_Marshal(TPMU_KDF_SCHEME *source, BYTE **buffer, UINT32 *size, UINT32 selector)
{
    UINT32 written = 0;


    switch (selector) {
#if ALG_MGF1
      case TPM_ALG_MGF1:
	written += TPMS_SCHEME_MGF1_Marshal(&source->mgf1, buffer, size);
	break;
#endif
#if ALG_KDF1_SP800_56A
      case TPM_ALG_KDF1_SP800_56A:
	written += TPMS_SCHEME_KDF1_SP800_56A_Marshal(&source->kdf1_sp800_56a, buffer, size);
	break;
#endif
#if ALG_KDF2
      case TPM_ALG_KDF2:
	written += TPMS_SCHEME_KDF2_Marshal(&source->kdf2, buffer, size);
	break;
#endif
#if ALG_KDF1_SP800_108
      case TPM_ALG_KDF1_SP800_108:
	written += TPMS_SCHEME_KDF1_SP800_108_Marshal(&source->kdf1_sp800_108, buffer, size);
	break;
#endif
      case TPM_ALG_NULL:
	break;
      default:
	pAssert(FALSE);
    }
    return written;
}

/* Table 2:157 - Definition of TPMT_KDF_SCHEME Structure (StructuresTable()) */

UINT32
TPMT_KDF_SCHEME_Marshal(TPMT_KDF_SCHEME *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;

    written += TPMI_ALG_KDF_Marshal(&source->scheme, buffer, size);
    written += TPMU_KDF_SCHEME_Marshal(&source->details, buffer, size, source->scheme);
    return written;
}

/* Table 2:159 - Definition of TPMU_ASYM_SCHEME Union (StructuresTable()) */

UINT32
TPMU_ASYM_SCHEME_Marshal(TPMU_ASYM_SCHEME  *source, BYTE **buffer, UINT32 *size, UINT32 selector)
{
    UINT32 written = 0;

    switch (selector) {
#if ALG_ECDH
      case TPM_ALG_ECDH:
        written += TPMS_KEY_SCHEME_ECDH_Marshal(&source->ecdh, buffer, size);
        break;
#endif
#if ALG_ECMQV
      case TPM_ALG_ECMQV:
        written += TPMS_KEY_SCHEME_ECMQV_Marshal(&source->ecmqv, buffer, size);
        break;
#endif
#if ALG_DILITHIUM
      case TPM_ALG_DILITHIUM:
        written += TPMS_SIG_SCHEME_DILITHIUM_Marshal(&source->dilithium, buffer, size);
        break;
#endif
#if ALG_KYBER
      case TPM_ALG_KYBER:
        written += TPMS_ENC_SCHEME_KYBER_Marshal(&source->kyber, buffer, size);
        break;
#endif
#if ALG_RSASSA
      case TPM_ALG_RSASSA:
        written += TPMS_SIG_SCHEME_RSASSA_Marshal(&source->rsassa, buffer, size);
        break;
#endif
#if ALG_RSAPSS
      case TPM_ALG_RSAPSS:
        written += TPMS_SIG_SCHEME_RSAPSS_Marshal(&source->rsapss, buffer, size);
        break;
#endif
#if ALG_ECDSA
      case TPM_ALG_ECDSA:
        written += TPMS_SIG_SCHEME_ECDSA_Marshal(&source->ecdsa, buffer, size);
        break;
#endif
#if ALG_ECDAA
      case TPM_ALG_ECDAA:
        written += TPMS_SIG_SCHEME_ECDAA_Marshal(&source->ecdaa, buffer, size);
        break;
#endif
#if ALG_SM2
      case TPM_ALG_SM2:
        written += TPMS_SIG_SCHEME_SM2_Marshal(&source->sm2, buffer, size);
        break;
#endif
#if ALG_ECSCHNORR
      case TPM_ALG_ECSCHNORR:
        written += TPMS_SIG_SCHEME_ECSCHNORR_Marshal(&source->ecschnorr, buffer, size);
        break;
#endif
#if ALG_RSAES
      case TPM_ALG_RSAES:
        written += TPMS_ENC_SCHEME_RSAES_Marshal(&source->rsaes, buffer, size);
        break;
#endif
#if ALG_OAEP
      case TPM_ALG_OAEP:
        written += TPMS_ENC_SCHEME_OAEP_Marshal(&source->oaep, buffer, size);
        break;
#endif
      case TPM_ALG_NULL:
        break;
      default:
        pAssert(FALSE);
    }
    return written;
}

/* Table 2:161 - Definition of TPMI_ALG_RSA_SCHEME Type (InterfaceTable()) */

UINT32
TPMI_ALG_RSA_SCHEME_Marshal(TPMI_ALG_RSA_SCHEME *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPM_ALG_ID_Marshal(source, buffer, size);
    return written;
}

/*****************************************************************************/
/*                             Dilithium Mods                                */
/*****************************************************************************/
UINT32
TPMI_ALG_DILITHIUM_SCHEME_Marshal(TPMI_ALG_DILITHIUM_SCHEME *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPM_ALG_ID_Marshal(source, buffer, size);
    return written;
}
/*****************************************************************************/
/*                             Dilithium Mods                                */
/*****************************************************************************/

/*****************************************************************************/
/*                                Kyber Mods                                 */
/*****************************************************************************/
UINT32
TPMI_ALG_KYBER_SCHEME_Marshal(TPMI_ALG_KYBER_SCHEME *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPM_ALG_ID_Marshal(source, buffer, size);
    return written;
}
/*****************************************************************************/
/*                                Kyber Mods                                 */
/*****************************************************************************/

/* Table 2:162 - Definition of TPMT_RSA_SCHEME Structure (StructuresTable()) */

UINT32
TPMT_RSA_SCHEME_Marshal(TPMT_RSA_SCHEME *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;

    written += TPMI_ALG_RSA_SCHEME_Marshal(&source->scheme, buffer, size);
    written += TPMU_ASYM_SCHEME_Marshal(&source->details, buffer, size, source->scheme);
    return written;
}

/*****************************************************************************/
/*                             Dilithium Mods                                */
/*****************************************************************************/
UINT32
TPMT_DILITHIUM_SCHEME_Marshal(TPMT_DILITHIUM_SCHEME *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;

    written += TPMI_ALG_DILITHIUM_SCHEME_Marshal(&source->scheme, buffer, size);
    written += TPMU_ASYM_SCHEME_Marshal(&source->details, buffer, size, source->scheme);
    return written;
}
/*****************************************************************************/
/*                             Dilithium Mods                                */
/*****************************************************************************/

/*****************************************************************************/
/*                                Kyber Mods                                 */
/*****************************************************************************/
UINT32
TPMT_KYBER_SCHEME_Marshal(TPMT_KYBER_SCHEME *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;

    written += TPMI_ALG_KYBER_SCHEME_Marshal(&source->scheme, buffer, size);
    written += TPMU_ASYM_SCHEME_Marshal(&source->details, buffer, size, source->scheme);
    return written;
}
/*****************************************************************************/
/*                                Kyber Mods                                 */
/*****************************************************************************/

/* Table 2:165 - Definition of TPM2B_PUBLIC_KEY_RSA Structure (StructuresTable()) */

UINT32
TPM2B_PUBLIC_KEY_RSA_Marshal(TPM2B_PUBLIC_KEY_RSA *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPM2B_Marshal(&source->b, buffer, size);
    return written;
}

/* Table 2:166 - Definition of TPMI_RSA_KEY_BITS Type (InterfaceTable()) */

UINT32
TPMI_RSA_KEY_BITS_Marshal(TPMI_RSA_KEY_BITS *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPM_KEY_BITS_Marshal(source, buffer, size);
    return written;
}

/* Table 2:167 - Definition of TPM2B_PRIVATE_KEY_RSA Structure (StructuresTable()) */

UINT32
TPM2B_PRIVATE_KEY_RSA_Marshal(TPM2B_PRIVATE_KEY_RSA *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPM2B_Marshal(&source->b, buffer, size);
    return written;
}

/* Table 2:168 - Definition of TPM2B_ECC_PARAMETER Structure (StructuresTable()) */

UINT32
TPM2B_ECC_PARAMETER_Marshal(TPM2B_ECC_PARAMETER *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPM2B_Marshal(&source->b, buffer, size);
    return written;
}

/* Table 2:169 - Definition of TPMS_ECC_POINT Structure (StructuresTable()) */

UINT32
TPMS_ECC_POINT_Marshal(TPMS_ECC_POINT *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;

    written += TPM2B_ECC_PARAMETER_Marshal(&source->x, buffer, size);
    written += TPM2B_ECC_PARAMETER_Marshal(&source->y, buffer, size);
    return written;
}

/* Table 2:170 - Definition of TPM2B_ECC_POINT Structure (StructuresTable()) */

UINT32
TPM2B_ECC_POINT_Marshal(TPM2B_ECC_POINT *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    BYTE *sizePtr;

    if (buffer != NULL) {
	sizePtr = *buffer;
    	*buffer += sizeof(UINT32);
    }
    written += TPMS_ECC_POINT_Marshal(&source->point, buffer, size);
    if (buffer != NULL) {
	written += UINT32_Marshal(&written, &sizePtr, size);
    }
    else {
	written += sizeof(UINT32);
    }
    return written;
}

/* Table 2:171 - Definition of TPMI_ALG_ECC_SCHEME Type (InterfaceTable()) */

UINT32
TPMI_ALG_ECC_SCHEME_Marshal(TPMI_ALG_ECC_SCHEME *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPM_ALG_ID_Marshal(source, buffer, size);
    return written;
}

/* Table 2:172 - Definition of TPMI_ECC_CURVE Type (InterfaceTable()) */

UINT32
TPMI_ECC_CURVE_Marshal(TPMI_ECC_CURVE *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPM_ECC_CURVE_Marshal(source, buffer, size);
    return written;
}

/* Table 2:173 - Definition of TPMT_ECC_SCHEME Structure (StructuresTable()) */

UINT32
TPMT_ECC_SCHEME_Marshal(TPMT_ECC_SCHEME *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;

    written += TPMI_ALG_ECC_SCHEME_Marshal(&source->scheme, buffer, size);
    written += TPMU_ASYM_SCHEME_Marshal(&source->details, buffer, size, source->scheme);
    return written;
}

/* Table 2:174 - Definition of TPMS_ALGORITHM_DETAIL_ECC Structure (StructuresTable()) */

UINT32
TPMS_ALGORITHM_DETAIL_ECC_Marshal(TPMS_ALGORITHM_DETAIL_ECC *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;

    written += TPM_ECC_CURVE_Marshal(&source->curveID, buffer, size);
    written += UINT16_Marshal(&source->keySize, buffer, size);
    written += TPMT_KDF_SCHEME_Marshal(&source->kdf, buffer, size);
    written += TPMT_ECC_SCHEME_Marshal(&source->sign, buffer, size);
    written += TPM2B_ECC_PARAMETER_Marshal(&source->p, buffer, size);
    written += TPM2B_ECC_PARAMETER_Marshal(&source->a, buffer, size);
    written += TPM2B_ECC_PARAMETER_Marshal(&source->b, buffer, size);
    written += TPM2B_ECC_PARAMETER_Marshal(&source->gX, buffer, size);
    written += TPM2B_ECC_PARAMETER_Marshal(&source->gY, buffer, size);
    written += TPM2B_ECC_PARAMETER_Marshal(&source->n, buffer, size);
    written += TPM2B_ECC_PARAMETER_Marshal(&source->h, buffer, size);
    return written;
}

/* Table 2:175 - Definition of TPMS_SIGNATURE_RSA Structure (StructuresTable()) */

UINT32
TPMS_SIGNATURE_RSA_Marshal(TPMS_SIGNATURE_RSA *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;

    written += TPMI_ALG_HASH_Marshal(&source->hash, buffer, size);
    written += TPM2B_PUBLIC_KEY_RSA_Marshal(&source->sig, buffer, size);
    return written;
}

/* Table 2:176 - Definition of Types for Signature (TypedefTable()) */
UINT32
TPMS_SIGNATURE_RSASSA_Marshal(TPMS_SIGNATURE_RSASSA *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPMS_SIGNATURE_RSA_Marshal(source, buffer, size);
    return written;
}
UINT32
TPMS_SIGNATURE_RSAPSS_Marshal(TPMS_SIGNATURE_RSAPSS *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPMS_SIGNATURE_RSA_Marshal(source, buffer, size);
    return written;
}

/* Table 2:177 - Definition of TPMS_SIGNATURE_ECC Structure (StructuresTable()) */

UINT32
TPMS_SIGNATURE_ECC_Marshal(TPMS_SIGNATURE_ECC *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;

    written += TPMI_ALG_HASH_Marshal(&source->hash, buffer, size);
    written += TPM2B_ECC_PARAMETER_Marshal(&source->signatureR, buffer, size);
    written += TPM2B_ECC_PARAMETER_Marshal(&source->signatureS, buffer, size);
    return written;
}

/* Table 2:178 - Definition of Types for TPMS_SIGNATURE_ECC (TypedefTable()) */

UINT32
TPMS_SIGNATURE_ECDSA_Marshal(TPMS_SIGNATURE_ECDSA *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPMS_SIGNATURE_ECC_Marshal(source, buffer, size);
    return written;
}

UINT32
TPMS_SIGNATURE_ECDAA_Marshal(TPMS_SIGNATURE_ECDAA *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPMS_SIGNATURE_ECC_Marshal(source, buffer, size);
    return written;
}

UINT32
TPMS_SIGNATURE_ECSCHNORR_Marshal(TPMS_SIGNATURE_ECSCHNORR *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPMS_SIGNATURE_ECC_Marshal(source, buffer, size);
    return written;
}

/*****************************************************************************/
/*                             Dilithium Mods                                */
/*****************************************************************************/
UINT32
TPMS_SIGNATURE_DILITHIUM_Marshal(TPMS_SIGNATURE_DILITHIUM *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;

    written += TPMI_ALG_HASH_Marshal(&source->hash, buffer, size);
    written += TPM2B_DILITHIUM_SIGNED_MESSAGE_Marshal(&source->sig, buffer, size);
    written += UINT8_Marshal(&source->mode, buffer, size);
    return written;
}
/*****************************************************************************/
/*                             Dilithium Mods                                */
/*****************************************************************************/

/* Table 2:179 - Definition of TPMU_SIGNATURE Union (StructuresTable()) */
UINT32
TPMU_SIGNATURE_Marshal(TPMU_SIGNATURE *source, BYTE **buffer, UINT32 *size, UINT32 selector)
{
    UINT32 written = 0;

    switch (selector) {
#if ALG_DILITHIUM
      case TPM_ALG_DILITHIUM:
        written += TPMS_SIGNATURE_DILITHIUM_Marshal(&source->dilithium, buffer, size);
        break;
#endif
#if ALG_RSASSA
      case TPM_ALG_RSASSA:
        written += TPMS_SIGNATURE_RSASSA_Marshal(&source->rsassa, buffer, size);
        break;
#endif
#if ALG_RSAPSS
      case TPM_ALG_RSAPSS:
        written += TPMS_SIGNATURE_RSAPSS_Marshal(&source->rsapss, buffer, size);
        break;
#endif
#if ALG_ECDSA
      case TPM_ALG_ECDSA:
        written += TPMS_SIGNATURE_ECDSA_Marshal(&source->ecdsa, buffer, size);
        break;
#endif
#if ALG_ECDAA
      case TPM_ALG_ECDAA:
        written += TPMS_SIGNATURE_ECDAA_Marshal(&source->ecdaa, buffer, size);
        break;
#endif
#if ALG_SM2
      case TPM_ALG_SM2:
        written += TPMS_SIGNATURE_SM2_Marshal(&source->sm2, buffer, size);
        break;
#endif
#if ALG_ECSCHNORR
      case TPM_ALG_ECSCHNORR:
        written += TPMS_SIGNATURE_ECSCHNORR_Marshal(&source->ecschnorr, buffer, size);
        break;
#endif
#if ALG_HMAC
      case TPM_ALG_HMAC:
        written += TPMT_HA_Marshal(&source->hmac, buffer, size);
        break;
#endif
      case TPM_ALG_NULL:
        break;
      default:
        pAssert(FALSE);
    }
    return written;
}

/* Table 2:180 - Definition of TPMT_SIGNATURE Structure (StructuresTable()) */

UINT32
TPMT_SIGNATURE_Marshal(TPMT_SIGNATURE *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;

    written += TPMI_ALG_SIG_SCHEME_Marshal(&source->sigAlg, buffer, size);
    written += TPMU_SIGNATURE_Marshal(&source->signature, buffer, size, source->sigAlg);
    return written;
}

/* Table 2:182 - Definition of TPM2B_ENCRYPTED_SECRET Structure (StructuresTable()) */

UINT32
TPM2B_ENCRYPTED_SECRET_Marshal(TPM2B_ENCRYPTED_SECRET *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPM2B_Marshal(&source->b, buffer, size);
    return written;
}

/* Table 2:183 - Definition of TPMI_ALG_PUBLIC Type (InterfaceTable()) */


UINT32
TPMI_ALG_PUBLIC_Marshal(TPMI_ALG_PUBLIC *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPM_ALG_ID_Marshal(source, buffer, size);
    return written;
}

/* Table 2:184 - Definition of TPMU_PUBLIC_ID Union (StructuresTable()) */
UINT32
TPMU_PUBLIC_ID_Marshal(TPMU_PUBLIC_ID *source, BYTE **buffer, UINT32 *size, UINT32 selector)
{
    UINT32 written = 0;

    switch (selector) {
#if ALG_KEYEDHASH
      case TPM_ALG_KEYEDHASH:
        written += TPM2B_DIGEST_Marshal(&source->keyedHash, buffer, size);
        break;
#endif
#if ALG_SYMCIPHER
      case TPM_ALG_SYMCIPHER:
        written += TPM2B_DIGEST_Marshal(&source->sym, buffer, size);
        break;
#endif
#if ALG_RSA
      case TPM_ALG_RSA:
        written += TPM2B_PUBLIC_KEY_RSA_Marshal(&source->rsa, buffer, size);
        break;
#endif
#if ALG_DILITHIUM
      case TPM_ALG_DILITHIUM:
        written += TPM2B_DILITHIUM_PUBLIC_KEY_Marshal(&source->dilithium, buffer, size);
        break;
#endif
#if ALG_KYBER
      case TPM_ALG_KYBER:
        written += TPM2B_KYBER_PUBLIC_KEY_Marshal(&source->kyber, buffer, size);
        break;
#endif
#if ALG_ECC
      case TPM_ALG_ECC:
        written += TPMS_ECC_POINT_Marshal(&source->ecc, buffer, size);
        break;
#endif
      default:
        pAssert(FALSE);
    }
    return written;
}

/* Table 2:185 - Definition of TPMS_KEYEDHASH_PARMS Structure (StructuresTable()) */

UINT32
TPMS_KEYEDHASH_PARMS_Marshal(TPMS_KEYEDHASH_PARMS *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPMT_KEYEDHASH_SCHEME_Marshal(&source->scheme, buffer, size);
    return written;
}

/* Table 2:187 - Definition of TPMS_RSA_PARMS Structure (StructuresTable()) */

UINT32
TPMS_RSA_PARMS_Marshal(TPMS_RSA_PARMS *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;

    written += TPMT_SYM_DEF_OBJECT_Marshal(&source->symmetric, buffer, size);
    written += TPMT_RSA_SCHEME_Marshal(&source->scheme, buffer, size);
    written += TPMI_RSA_KEY_BITS_Marshal(&source->keyBits, buffer, size);
    written += UINT32_Marshal(&source->exponent, buffer, size);
    return written;
}

/* Table 2:188 - Definition of TPMS_ECC_PARMS Structure (StructuresTable()) */

UINT32
TPMS_ECC_PARMS_Marshal(TPMS_ECC_PARMS *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;

    written += TPMT_SYM_DEF_OBJECT_Marshal(&source->symmetric, buffer, size);
    written += TPMT_ECC_SCHEME_Marshal(&source->scheme, buffer, size);
    written += TPMI_ECC_CURVE_Marshal(&source->curveID, buffer, size);
    written += TPMT_KDF_SCHEME_Marshal(&source->kdf, buffer, size);
    return written;
}

/*****************************************************************************/
/*                             Dilithium Mods                                */
/*****************************************************************************/
UINT32
TPMS_DILITHIUM_PARMS_Marshal(TPMS_DILITHIUM_PARMS *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;

    written += TPMT_SYM_DEF_OBJECT_Marshal(&source->symmetric, buffer, size);
    written += TPMT_DILITHIUM_SCHEME_Marshal(&source->scheme, buffer, size);
    written += UINT8_Marshal(&source->mode, buffer, size);
    return written;
}
/*****************************************************************************/
/*                             Dilithium Mods                                */
/*****************************************************************************/

/*****************************************************************************/
/*                                Kyber Mods                                 */
/*****************************************************************************/
UINT32
TPMS_KYBER_PARMS_Marshal(TPMS_KYBER_PARMS *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;

    written += TPMT_SYM_DEF_OBJECT_Marshal(&source->symmetric, buffer, size);
    written += TPMT_KYBER_SCHEME_Marshal(&source->scheme, buffer, size);
    written += UINT8_Marshal(&source->security, buffer, size);
    return written;
}
/*****************************************************************************/
/*                                Kyber Mods                                 */
/*****************************************************************************/

/* Table 2:189 - Definition of TPMU_PUBLIC_PARMS Union (StructuresTable()) */

UINT32
TPMU_PUBLIC_PARMS_Marshal(TPMU_PUBLIC_PARMS *source, BYTE **buffer, UINT32 *size, UINT32 selector)
{
    UINT32 written = 0;

    switch (selector) {
#if ALG_KEYEDHASH
      case TPM_ALG_KEYEDHASH:
        written += TPMS_KEYEDHASH_PARMS_Marshal(&source->keyedHashDetail, buffer, size);
        break;
#endif
#if ALG_SYMCIPHER
      case TPM_ALG_SYMCIPHER:
        written += TPMS_SYMCIPHER_PARMS_Marshal(&source->symDetail, buffer, size);
        break;
#endif
#if ALG_RSA
      case TPM_ALG_RSA:
        written += TPMS_RSA_PARMS_Marshal(&source->rsaDetail, buffer, size);
        break;
#endif
#if ALG_DILITHIUM
      case TPM_ALG_DILITHIUM:
        written += TPMS_DILITHIUM_PARMS_Marshal(&source->dilithiumDetail, buffer, size);
        break;
#endif
#if ALG_KYBER
      case TPM_ALG_KYBER:
        written += TPMS_KYBER_PARMS_Marshal(&source->kyberDetail, buffer, size);
        break;
#endif
#if ALG_ECC
      case TPM_ALG_ECC:
        written += TPMS_ECC_PARMS_Marshal(&source->eccDetail, buffer, size);
        break;
#endif
      default:
        pAssert(FALSE);
    }
    return written;
}

/* Table 2:190 - Definition of TPMT_PUBLIC_PARMS Structure (StructuresTable()) */

UINT32
TPMT_PUBLIC_PARMS_Marshal(TPMT_PUBLIC_PARMS *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPMI_ALG_PUBLIC_Marshal(&source->type, buffer, size);
    written += TPMU_PUBLIC_PARMS_Marshal(&source->parameters, buffer, size, source->type);
    return written;
}

/* Table 2:191 - Definition of TPMT_PUBLIC Structure (StructuresTable()) */

UINT32
TPMT_PUBLIC_Marshal(TPMT_PUBLIC *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPMI_ALG_PUBLIC_Marshal(&source->type, buffer, size);
    written += TPMI_ALG_HASH_Marshal(&source->nameAlg, buffer, size);
    written += TPMA_OBJECT_Marshal(&source->objectAttributes, buffer, size);
    written += TPM2B_DIGEST_Marshal(&source->authPolicy, buffer, size);
    written += TPMU_PUBLIC_PARMS_Marshal(&source->parameters, buffer, size, source->type);
    written += TPMU_PUBLIC_ID_Marshal(&source->unique, buffer, size, source->type);
    return written;
}

/* Table 2:192 - Definition of TPM2B_PUBLIC Structure (StructuresTable()) */

UINT32
TPM2B_PUBLIC_Marshal(TPM2B_PUBLIC *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    BYTE *sizePtr;

    if (buffer != NULL) {
	sizePtr = *buffer;
   	*buffer += sizeof(UINT32);
    }
    written += TPMT_PUBLIC_Marshal(&source->publicArea, buffer, size);
    if (buffer != NULL) {
        written += UINT32_Marshal(&written, &sizePtr, size);
    }
    else {
	written += sizeof(UINT32);
    }
    return written;
}

/* Table 2:195 - Definition of TPMU_SENSITIVE_COMPOSITE Union (StructuresTable()) */

UINT32
TPMU_SENSITIVE_COMPOSITE_Marshal(TPMU_SENSITIVE_COMPOSITE *source, BYTE **buffer, UINT32 *size, UINT32 selector)
{
    UINT32 written = 0;

    switch (selector) {
#if ALG_DILITHIUM
      case TPM_ALG_DILITHIUM:
        written += TPM2B_DILITHIUM_SECRET_KEY_Marshal(&source->dilithium, buffer, size);
        break;
#endif
#if ALG_RSA
      case TPM_ALG_RSA:
        written += TPM2B_PRIVATE_KEY_RSA_Marshal(&source->rsa, buffer, size);
        break;
#endif
#if ALG_ECC
      case TPM_ALG_ECC:
        written += TPM2B_ECC_PARAMETER_Marshal(&source->ecc, buffer, size);
        break;
#endif
#if ALG_KEYEDHASH
      case TPM_ALG_KEYEDHASH:
        written += TPM2B_SENSITIVE_DATA_Marshal(&source->bits, buffer, size);
        break;
#endif
#if ALG_SYMCIPHER
      case TPM_ALG_SYMCIPHER:
        written += TPM2B_SYM_KEY_Marshal(&source->sym, buffer, size);
        break;
#endif
#if ALG_KYBER
      case TPM_ALG_KYBER:
        written += TPM2B_KYBER_SECRET_KEY_Marshal(&source->kyber, buffer, size);
        break;
#endif
      default:
        pAssert(FALSE);
    }
    return written;
}

/* Table 2:196 - Definition of TPMT_SENSITIVE Structure (StructuresTable()) */

UINT32
TPMT_SENSITIVE_Marshal(TPMT_SENSITIVE *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;

    written += TPMI_ALG_PUBLIC_Marshal(&source->sensitiveType, buffer, size);
    written += TPM2B_AUTH_Marshal(&source->authValue, buffer, size);
    written += TPM2B_DIGEST_Marshal(&source->seedValue, buffer, size);
    written += TPMU_SENSITIVE_COMPOSITE_Marshal(&source->sensitive, buffer, size, source->sensitiveType);
    return written;
}

/* Table 2:199 - Definition of TPM2B_PRIVATE Structure (StructuresTable()) */

UINT32
TPM2B_PRIVATE_Marshal(TPM2B_PRIVATE *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPM2B_Marshal(&source->b, buffer, size);
    return written;
}

/* Table 2:201 - Definition of TPM2B_ID_OBJECT Structure (StructuresTable()) */

UINT32
TPM2B_ID_OBJECT_Marshal(TPM2B_ID_OBJECT *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPM2B_Marshal(&source->b, buffer, size);
    return written;
}

/* Table 2:205 - Definition of TPMA_NV Bits (BitsTable()) */

UINT32
TPMA_NV_Marshal(TPMA_NV *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += UINT32_Marshal(source, buffer, size);
    return written;
}

/* Table 2:206 - Definition of TPMS_NV_PUBLIC Structure (StructuresTable()) */

UINT32
TPMS_NV_PUBLIC_Marshal(TPMS_NV_PUBLIC *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;

    written += TPMI_RH_NV_INDEX_Marshal(&source->nvIndex, buffer, size);
    written += TPMI_ALG_HASH_Marshal(&source->nameAlg, buffer, size);
    written += TPMA_NV_Marshal(&source->attributes, buffer, size);
    written += TPM2B_DIGEST_Marshal(&source->authPolicy, buffer, size);
    written += UINT32_Marshal(&source->dataSize, buffer, size);
    return written;
}

/* Table 2:207 - Definition of TPM2B_NV_PUBLIC Structure (StructuresTable()) */

UINT32
TPM2B_NV_PUBLIC_Marshal(TPM2B_NV_PUBLIC *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    BYTE *sizePtr;

    if (buffer != NULL) {
	sizePtr = *buffer;
    	*buffer += sizeof(UINT32);
    }
    written += TPMS_NV_PUBLIC_Marshal(&source->nvPublic, buffer, size);
    if (buffer != NULL) {
	written += UINT32_Marshal(&written, &sizePtr, size);
    }
    else {
	written += sizeof(UINT32);
    }
    return written;
}

/* Table 2:210 - Definition of TPM2B_CONTEXT_DATA Structure (StructuresTable()) */

UINT32
TPM2B_CONTEXT_DATA_Marshal(TPM2B_CONTEXT_DATA  *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPM2B_Marshal(&source->b, buffer, size);
    return written;
}

/* Table 2:211 - Definition of TPMS_CONTEXT Structure (StructuresTable()) */

UINT32
TPMS_CONTEXT_Marshal(TPMS_CONTEXT *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;

    written += UINT64_Marshal(&source->sequence, buffer, size);
    written += TPMI_DH_SAVED_Marshal(&source->savedHandle, buffer, size);
    written += TPMI_RH_HIERARCHY_Marshal(&source->hierarchy, buffer, size);
    written += TPM2B_CONTEXT_DATA_Marshal(&source->contextBlob, buffer, size);
    return written;
}

/* Table 2:213 - Definition of TPMS_CREATION_DATA Structure (StructuresTable()) */

UINT32
TPMS_CREATION_DATA_Marshal(TPMS_CREATION_DATA *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;

    written += TPML_PCR_SELECTION_Marshal(&source->pcrSelect, buffer, size);
    written += TPM2B_DIGEST_Marshal(&source->pcrDigest, buffer, size);
    written += TPMA_LOCALITY_Marshal(&source->locality, buffer, size);
    written += TPM_ALG_ID_Marshal(&source->parentNameAlg, buffer, size);
    written += TPM2B_NAME_Marshal(&source->parentName, buffer, size);
    written += TPM2B_NAME_Marshal(&source->parentQualifiedName, buffer, size);
    written += TPM2B_DATA_Marshal(&source->outsideInfo, buffer, size);
    return written;
}

/* Table 2:214 - Definition of TPM2B_CREATION_DATA Structure (StructuresTable()) */

UINT32
TPM2B_CREATION_DATA_Marshal(TPM2B_CREATION_DATA *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    BYTE *sizePtr;

    if (buffer != NULL) {
	sizePtr = *buffer;
    	*buffer += sizeof(UINT32);
    }
    written += TPMS_CREATION_DATA_Marshal(&source->creationData, buffer, size);
    if (buffer != NULL) {
	written += UINT32_Marshal(&written, &sizePtr, size);
    }
    else {
	written += sizeof(UINT32);
    }
    return written;
}

/*****************************************************************************/
/*                                Kyber Mods                                 */
/*****************************************************************************/
UINT32
TPM2B_KYBER_PUBLIC_KEY_Marshal(TPM2B_KYBER_PUBLIC_KEY *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPM2B_Marshal(&source->b, buffer, size);
    return written;
}

UINT32
TPM2B_KYBER_SECRET_KEY_Marshal(TPM2B_KYBER_SECRET_KEY *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPM2B_Marshal(&source->b, buffer, size);
    return written;
}

UINT32
TPM2B_KYBER_SHARED_KEY_Marshal(TPM2B_KYBER_SHARED_KEY *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPM2B_Marshal(&source->b, buffer, size);
    return written;
}

UINT32
TPM2B_KYBER_CIPHER_TEXT_Marshal(TPM2B_KYBER_CIPHER_TEXT *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPM2B_Marshal(&source->b, buffer, size);
    return written;
}

UINT32
TPM2B_KYBER_ENCRYPT_Marshal(TPM2B_KYBER_ENCRYPT *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPM2B_Marshal(&source->b, buffer, size);
    return written;
}
/*****************************************************************************/
/*                                Kyber Mods                                 */
/*****************************************************************************/

/*****************************************************************************/
/*                             Dilithium Mods                                */
/*****************************************************************************/
UINT32
TPM2B_DILITHIUM_PUBLIC_KEY_Marshal(TPM2B_DILITHIUM_PUBLIC_KEY *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPM2B_Marshal(&source->b, buffer, size);
    return written;
}

UINT32
TPM2B_DILITHIUM_SECRET_KEY_Marshal(TPM2B_DILITHIUM_SECRET_KEY *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPM2B_Marshal(&source->b, buffer, size);
    return written;
}

UINT32
TPM2B_DILITHIUM_SIGNED_MESSAGE_Marshal(TPM2B_DILITHIUM_SIGNED_MESSAGE *source, BYTE **buffer, UINT32 *size)
{
    UINT32 written = 0;
    written += TPM2B_Marshal(&source->b, buffer, size);
    return written;
}
/*****************************************************************************/
/*                             Dilithium Mods                                */
/*****************************************************************************/
