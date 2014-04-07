//----------------------------------------------------------------------
// See CoolkeyRSAKeyGenResult.h
//----------------------------------------------------------------------

#include "CoolkeyRSAKeyGenResult.h"

//----------------------------------------------------------------------

#include "Endianness.h"

#include <cstdint>
#include <string>
#include <sstream>
#include <iomanip>
#include <iterator>  // std::back_inserter

#include <openssl/evp.h>
#include <openssl/rsa.h>

//----------------------------------------------------------------------
// PUBLIC
// constructor does parsing work
//   throws std::runtime_error if unable to parse
//   does NOT verify the signature on the key - call CoolkeyRSAKeyChallenge::verifySignature() to do that
CoolkeyRSAKeyGenResult::CoolkeyRSAKeyGenResult(const std::vector<byte>& data, const bool extraDataOkay){
    // check that sufficient data is present for keyblob length and proof length
    if (data.size() < (2 + 2)){
        throw std::runtime_error("Invalid RSA Key Gen Result - Insufficient data for key blob length and proof length.");
    }

    size_t bytesConsumed = 0;  // how many bytes we've parsed out of the data vector

    // parse out key length
    uint16_t keyLength_short = *(reinterpret_cast<const uint16_t*>(&data.at(0)));  // get at(0 to 1) as short
    keyLength_short = Endianness::ntohs(keyLength_short);                          // fix endianness
    size_t keyLength_sizet = keyLength_short;                                      // widen to word size of machine
    bytesConsumed += 2;

    // sanity check key length
    size_t remainingData = data.size() - bytesConsumed;
    // subtract 2 for proof length
    if ((remainingData - 2) < keyLength_sizet){
        std::ostringstream errsstr;
        errsstr << "Invalid RSA Key Gen Result - Insufficient data for key blob."
                << "  Blob length was: " << keyLength_sizet
                << "  Remaining data was: " << (remainingData - 2);
        throw std::runtime_error(errsstr.str());
    }

    // copy key blob data
    std::vector<byte> keyBlobData(data.begin() + bytesConsumed, data.begin() + bytesConsumed + keyLength_sizet);
    bytesConsumed += keyLength_sizet;

    // parse key blob data into object - may throw std::runtime_error but this is okay
    std::unique_ptr<CoolkeyRSAKeyBlob> keyBlobPtr(new CoolkeyRSAKeyBlob(keyBlobData));
    this->m_pKeyBlob = std::move(keyBlobPtr);


    // parse out proof length
    uint16_t proofLength_short = *(reinterpret_cast<const uint16_t*>(&data.at(bytesConsumed)));  // get at(bytesConsumed to bytesConsumed+1) as short
    proofLength_short = Endianness::ntohs(proofLength_short);                                    // fix endianness
    size_t proofLength_sizet = proofLength_short;                                                // widen to word size of machine
    bytesConsumed += 2;

    // sanity check proof length
    remainingData = data.size() - bytesConsumed;
    if ((remainingData) < proofLength_sizet){
        std::ostringstream errsstr;
        errsstr << "Invalid RSA Key Gen Result - Insufficient data for proof."
                << "  Proof length was: " << proofLength_sizet
                << "  Remaining data was: " << (remainingData);
        throw std::runtime_error(errsstr.str());
    }

    // parse out proof data (copy subset of blobData to this->m_keyProofData)
    std::copy(data.begin() + bytesConsumed,
              data.begin() + bytesConsumed + proofLength_sizet,
              std::back_inserter(this->m_keyProofData));
    bytesConsumed += proofLength_sizet;


    // check if extra data was present.  If so --> if configuration parameter was that extra data isn't okay, throw exception.
    if (extraDataOkay == false){
        if (bytesConsumed != data.size()){
            std::ostringstream errsstr;
            errsstr << "Invalid RSA Key Gen Result - Extra data was present after parsing completed."
                    << "  Parsed result length was: " << bytesConsumed
                    << "  Total result length was: " << data.size();
            throw std::runtime_error(errsstr.str());
        }
    }
}

//----------------------------------------------------------------------
// PUBLIC
// destructor - nothing to do at present
CoolkeyRSAKeyGenResult::~CoolkeyRSAKeyGenResult(){

}

//----------------------------------------------------------------------
// verify method verifies the RSA signature on the blob with the specified challenge key
//   throws std::runtime_error if signature has a problem
void CoolkeyRSAKeyGenResult::verifySignature(const std::vector<byte>& challengeKeyData) const {
    const RSA* rsaKey = this->m_pKeyBlob.get()->getOpensslRSAKey();

    // create new EVP Key object
    EVP_PKEY* evpRsaKey = EVP_PKEY_new();
    if (evpRsaKey == nullptr){
        throw std::runtime_error("Unable to create EVP_PKEY object.");
    }
    try{
        // wrap RSAkey inside EVP key object.  
        // Using the "set1" function adds a reference count to the RSA key so freeing the EVP key will not free the RSA key (what we want).
        int result = EVP_PKEY_set1_RSA(evpRsaKey, const_cast<RSA*>(rsaKey));
        if (result != 1){
            throw std::runtime_error("Unable to assign RSA public key to EVP_PKEY object.");
        }

        // create cipher context
        EVP_MD_CTX ctx;
        EVP_MD_CTX_init(&ctx);

        try{
            // initialize cipher context for verification with sha1
            if (EVP_VerifyInit_ex(&ctx, EVP_sha1(), nullptr) != 1){
                throw std::runtime_error("Unable to initialize EVP_MD_CTX for verify operation.");
            }


            // calculate sha1 digest of (key blob + challenge key)
            if (EVP_VerifyUpdate(&ctx, &this->m_pKeyBlob.get()->getBlobData().at(0), this->m_pKeyBlob.get()->getBlobSize()) != 1){
                throw std::runtime_error("Unable to compute digest of original message (part 1 of 2).");
            }
            if (EVP_VerifyUpdate(&ctx, &challengeKeyData.at(0), challengeKeyData.size()) != 1){
                throw std::runtime_error("Unable to compute digest of original message (part 2 of 2).");
            }


            // decrypt proof data and compare digests
            int verifyResult = EVP_VerifyFinal(&ctx, &this->m_keyProofData.at(0), this->m_keyProofData.size(), evpRsaKey);
            // result == 1 indicates success, 0 verify failure and < 0 for some other error.
                
            if (verifyResult == 1){
                // do nothing
            }else if (verifyResult == 0){
                throw std::runtime_error("OpenSSL computation successful; however, verification of proof/signature data failed.");
            }else{
                throw std::runtime_error("Unable to perform data validation; internal error decrypting encrypted digest.");
            }


            // clean up
            EVP_MD_CTX_cleanup(&ctx);
        }catch (...){
            // clean up
            EVP_MD_CTX_cleanup(&ctx);

            throw;
        }

        
        // AC: Old code that doesn't work right.  It doesn't appear to have OpenSSL 
        //     calculate the digest of the data prior to comparison:
        
        
        //// create cipher context with public RSA (EVP) key
        //EVP_PKEY_CTX* ctx = nullptr;
        //ctx = EVP_PKEY_CTX_new(evpRsaKey, nullptr);
        //if (ctx == nullptr){
        //    throw std::runtime_error("Unable to create EVP_PKEY_CTX.");
        //}
        //
        //try{
        //    // try to initialize cipher context for a verify operation
        //    if (EVP_PKEY_verify_init(ctx) != 1){
        //        throw std::runtime_error("Unable to initialize EVP_PKEY_CTX for verify operation.");
        //    }

        //    // configure to use SHA1 digest algorithm
        //    int digestResult = EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha1());
        //    if (digestResult <= 0){
        //        throw std::runtime_error("Unable to set message digest algorithm of EVP_PKEY_CTX to sha1.");
        //    }

        //    // try to set padding
        //    int paddingResult = EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING);
        //    if (paddingResult <= 0){
        //        throw std::runtime_error("Unable to set RSA padding mode for EVP_PKEY_CTX.");
        //    }

        //    // build "original data" for hashing
        //    std::vector<byte> dataToVerify(this->m_pKeyBlob.get()->getBlobData()); // copy key blob data
        //    dataToVerify.reserve(dataToVerify.size() + challengeKeyData.size());    
        //    std::copy(challengeKeyData.begin(), challengeKeyData.end(), std::back_inserter(dataToVerify)); // append challenge key data

        //    // Performs three things:
        //    // 1. Calculates hash of original message.
        //    // 2. Decrypts encrypted RSA blob, which yields original hash.
        //    // 3. Compares the two hashes.
        //    int    result = EVP_PKEY_verify(ctx,
        //                                    &this->m_keyProofData.at(0),
        //                                    this->m_keyProofData.size(),
        //                                    &dataToVerify.at(0),
        //                                    dataToVerify.size());
        //    // result == 1 indicates success, 0 verify failure and < 0 for some other error.
        //    
        //    if (result == 1){
        //        // do nothing
        //    }else if (result == 0){
        //        throw std::runtime_error("OpenSSL computation successful; however, verification of proof/signature data failed.");
        //    }else{
        //        throw std::runtime_error("Unable to perform data validation; internal error.");
        //    }

        //    // clean up
        //    EVP_PKEY_CTX_free(ctx);
        //}catch (...){
        //    // clean up
        //    EVP_PKEY_CTX_free(ctx);
        //    throw;
        //}

        // clean up
        EVP_PKEY_free(evpRsaKey);
    }catch (...){
        // clean up
        EVP_PKEY_free(evpRsaKey);
        throw;
    }
}

//----------------------------------------------------------------------
