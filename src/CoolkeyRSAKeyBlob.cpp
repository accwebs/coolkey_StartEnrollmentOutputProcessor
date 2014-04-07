//----------------------------------------------------------------------
// See CoolkeyRSAKeyBlob.h
//----------------------------------------------------------------------

#include "CoolkeyRSAKeyBlob.h"

//----------------------------------------------------------------------

#include "Endianness.h"

#include <cstdint>
#include <string>
#include <sstream>
#include <iomanip>
#include <iterator>  // std::back_inserter

#include <openssl/bn.h>
#include <openssl/engine.h>

//----------------------------------------------------------------------
// PUBLIC
// constructor does parsing work
//   throws std::runtime_error if unable to parse
CoolkeyRSAKeyBlob::CoolkeyRSAKeyBlob(const std::vector<byte>& blobData, const bool extraDataOkay) : m_rsaKey(nullptr){
    // check that sufficient data is present for encoding, key type, key length, and modulus length
    if (blobData.size() < (1 + 1 + 2 + 2)){
        throw std::runtime_error("Invalid RSA Key Blob data - Insufficient data for blob header.");
    }

    size_t bytesConsumed = 0;  // how many bytes we've parsed out of the blobData vector

    // parse out encoding byte
    this->m_encoding = blobData.at(0);
    ++bytesConsumed;

    // parse out key type byte
    this->m_keyType = blobData.at(1);
    ++bytesConsumed;

    // parse out key length in bits
    uint16_t keyLengthBitsShort = *(reinterpret_cast<const uint16_t*>(&blobData.at(2)));  // get at(2 to 3) as short
    keyLengthBitsShort = Endianness::ntohs(keyLengthBitsShort);                           // fix endianness
    this->m_keyLengthBits = keyLengthBitsShort;                                           // widen to word size of machine
    bytesConsumed += 2;

    // parse out modulus length
    uint16_t modulusLengthShort = *(reinterpret_cast<const uint16_t*>(&blobData.at(4)));  // get at(4 to 5) as short
    modulusLengthShort = Endianness::ntohs(modulusLengthShort);                           // fix endianness
    this->m_modulusLength = modulusLengthShort;                                           // widen to word size of machine
    bytesConsumed += 2;

    // sanity check parsed out values thus far
    if (this->m_encoding != KEYENCODING_PLAINTEXT){
        std::ostringstream errsstr;
        int m_encoding_int = this->m_encoding;
        errsstr << "Invalid RSA Key Blob data - Unsupported key encoding 0x"
                << std::setw(2) << std::setfill('0') << std::hex << m_encoding_int;
        throw std::runtime_error(errsstr.str());
    }
    if (this->m_keyType != KEYTYPE_RSA_PUBLIC){
        std::ostringstream errsstr;
        int m_keyType_int = this->m_keyType;
        errsstr << "Invalid RSA Key Blob data - Unsupported key type 0x"
                << std::setw(2) << std::setfill('0') << std::hex << m_keyType_int;
        throw std::runtime_error(errsstr.str());
    }

    // sanity check modulus length
    size_t remainingData = blobData.size() - bytesConsumed;
    // subtract 2 for exponent length
    if ((remainingData - 2) < this->m_modulusLength){
        std::ostringstream errsstr;
        errsstr << "Invalid RSA Key Blob data - Insufficient data for key modulus."
                << "  Modulus length was: " << this->m_modulusLength
                << "  Remaining data was: " << (remainingData - 2);
        throw std::runtime_error(errsstr.str());
    }

    // parse out modulus data (copy subset of blobData to this->m_modulusData)
    std::copy(blobData.begin() + bytesConsumed, 
              blobData.begin() + bytesConsumed + this->m_modulusLength,
              std::back_inserter(this->m_modulusData));
    bytesConsumed += this->m_modulusLength;

    // parse out exponent length
    uint16_t exponentLengthShort = *(reinterpret_cast<const uint16_t*>(&blobData.at(bytesConsumed)));  // get at(bytesConsumed to bytesConsumed+1) as short
    exponentLengthShort = Endianness::ntohs(exponentLengthShort);                                      // fix endianness
    this->m_exponentLength = exponentLengthShort;                                                      // widen to word size of machine
    bytesConsumed += 2;

    // sanity check exponent length
    remainingData = blobData.size() - bytesConsumed;
    if ((remainingData) < this->m_exponentLength){
        std::ostringstream errsstr;
        errsstr << "Invalid RSA Key Blob data - Insufficient data for key exponent."
                << "  Exponent length was: " << this->m_exponentLength
                << "  Remaining data was: " << (remainingData);
        throw std::runtime_error(errsstr.str());
    }

    // parse out exponent data (copy subset of blobData to this->m_exponentData)
    std::copy(blobData.begin() + bytesConsumed,
              blobData.begin() + bytesConsumed + this->m_exponentLength,
              std::back_inserter(this->m_exponentData));
    bytesConsumed += this->m_exponentLength;

    // check if extra data was present.  If so --> if configuration parameter was that extra data isn't okay, throw exception.
    if (extraDataOkay == false){
        if (bytesConsumed != blobData.size()){
            std::ostringstream errsstr;
            errsstr << "Invalid RSA Key Blob data - Extra data was present after parsing completed."
                    << "  Parsed blob length was: " << bytesConsumed
                    << "  Total blob length was: " << blobData.size();
            throw std::runtime_error(errsstr.str());
        }
    }

    // copy blob data bytes to this->m_blobData
    std::copy(blobData.begin(),
              blobData.begin() + bytesConsumed,
              std::back_inserter(this->m_blobData));



    // pointers to openssl BIGNUM versions of m_modulusData and m_exponentData
    BIGNUM* bnModulus = nullptr;
    BIGNUM* bnExponent = nullptr;
    try{
        // create openssl BIGNUM structures based on modulus and exponent data
        bnExponent = BN_bin2bn(&this->m_exponentData.at(0), this->m_exponentData.size(), nullptr);
        if (bnExponent == nullptr){
            throw std::runtime_error("Unable to finalize RSA Key Blob data parsing - Could not create openssl BIGNUM structure for exponent data.");
        }
        bnModulus = BN_bin2bn(&this->m_modulusData.at(0), this->m_modulusData.size(), nullptr);
        if (bnModulus == nullptr){
            throw std::runtime_error("Unable to finalize RSA Key Blob data parsing - Could not create openssl BIGNUM structure for modulus data.");
        }

        // create openssl RSA structure
        this->m_rsaKey = RSA_new();
        if (this->m_rsaKey == nullptr){
            throw std::runtime_error("Unable to finalize RSA Key Blob data parsing - Could not create openssl RSA key structure.");
        }

    }catch (...){
        // free openssl BIGNUM structures we may have allocated
        if (bnExponent != nullptr){
            BN_free(bnExponent);
            bnExponent = nullptr;
        }
        if (bnModulus != nullptr){
            BN_free(bnModulus);
            bnModulus = nullptr;
        }
        // free RSA structure we may have allocated
        if (this->m_rsaKey != nullptr){
            RSA_free(this->m_rsaKey);
            this->m_rsaKey = nullptr;
        }
    }

    // assign ownership of bnExponent and bnModulus to this->m_rsaKey
    //   this means that when we free this->m_rsaKey, we will free the BIGNUMs as well
    this->m_rsaKey->e = bnExponent;
    this->m_rsaKey->n = bnModulus;
}

//----------------------------------------------------------------------
// PUBLIC
// destructor - cleans up OpenSSL objects
CoolkeyRSAKeyBlob::~CoolkeyRSAKeyBlob(){
    // free RSA structure we may have allocated
    if (this->m_rsaKey != nullptr){
        RSA_free(this->m_rsaKey);
        this->m_rsaKey = nullptr;
    }
}

//----------------------------------------------------------------------
