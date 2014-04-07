//----------------------------------------------------------------------
// CoolkeyRSAKeyGenResult - Handles parsing and verification of Coolkey 
//                          RSA Key generation result blobs into into 
//                          machine-retrievable fields.
//----------------------------------------------------------------------

#ifndef CoolkeyRSAKeyGenResultH_Included
#define CoolkeyRSAKeyGenResultH_Included

//----------------------------------------------------------------------

class CoolkeyRSAKeyGenResult;

//----------------------------------------------------------------------

#include <vector>
#include <stdexcept>
#include <memory> // unique_ptr

typedef unsigned char byte;
typedef unsigned char BYTE;

#include "CoolkeyRSAKeyBlob.h"

//----------------------------------------------------------------------

class CoolkeyRSAKeyGenResult{
    public:

    private:
        // prevent copying and assignment
        CoolkeyRSAKeyGenResult(const CoolkeyRSAKeyGenResult& src);
        CoolkeyRSAKeyGenResult operator=(const CoolkeyRSAKeyGenResult& rhs);

    protected:
        std::unique_ptr<CoolkeyRSAKeyBlob> m_pKeyBlob;   // key blob object (RSA key)      - parsed out in constructor
        std::vector<byte> m_keyProofData;                // raw key proof data (signature) - parsed out in constructor

    public:
        // constructor does parsing work
        //   throws std::runtime_error if unable to parse
        //   does NOT verify the signature on the key - call CoolkeyRSAKeyGenResult::verifySignature() to do that
        CoolkeyRSAKeyGenResult(const std::vector<byte>& data, const bool extraDataOkay = false);

        // destructor
        virtual ~CoolkeyRSAKeyGenResult();


        // getters for parsed out blob data
        size_t getBlobSize() const { return this->m_pKeyBlob.get()->getBlobSize(); }
        const CoolkeyRSAKeyBlob& getBlob() const { return *(this->m_pKeyBlob.get()); }

        // getters for raw proof data
        size_t getProofSize() const { return this->m_keyProofData.size(); }
        const std::vector<byte>& getProofData() const { return this->m_keyProofData; }


        // verify method verifies the RSA signature on the blob with the specified challenge key
        //   throws std::runtime_error if signature has a problem
        void verifySignature(const std::vector<byte>& challengeKeyData) const;
};

//----------------------------------------------------------------------

#endif 
