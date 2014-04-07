//----------------------------------------------------------------------
// CoolkeyRSAKeyBlob - Handles parsing of Coolkey RSA Key Blob objects 
//                     into machine-retrievable fields.
//----------------------------------------------------------------------

#ifndef CoolkeyRSAKeyBlobH_Included
#define CoolkeyRSAKeyBlobH_Included

//----------------------------------------------------------------------

class CoolkeyRSAKeyBlob;

//----------------------------------------------------------------------

#include <vector>
#include <stdexcept>

typedef unsigned char byte;
typedef unsigned char BYTE;

#include <openssl/rsa.h>

//----------------------------------------------------------------------

class CoolkeyRSAKeyBlob{
    public:
        // supported key blob types
        const static byte KEYTYPE_RSA_PUBLIC = 0x01;
        
        // supported key encoding types
        const static byte KEYENCODING_PLAINTEXT = 0x00;

    private:
        // prevent copying and assignment
        CoolkeyRSAKeyBlob(const CoolkeyRSAKeyBlob& src);
        CoolkeyRSAKeyBlob operator=(const CoolkeyRSAKeyBlob& rhs);

    protected:
        std::vector<byte> m_blobData;         // raw key blob data
        
        byte m_encoding;                      // key encoding field of blob     - parsed out in constructor
        byte m_keyType;                       // key type field of blob         - parsed out in constructor
        size_t m_keyLengthBits;               // length of RSA key in bits      - parsed out in constructor
        
        size_t m_modulusLength;               // byte length of modulus field   - parsed out in constructor
        std::vector<byte> m_modulusData;      // modulus data                   - parsed out in constructor
        size_t m_exponentLength;              // byte length of exponent length - parsed out in constructor
        std::vector<byte> m_exponentData;     // exponent data                  - parsed out in constructor


        // pointer to openssl RSA (public key) structure
        RSA* m_rsaKey;                        // initialized in constructor with parsed out key data

    public:
        // constructor does parsing work
        //   throws std::runtime_error if unable to parse
        CoolkeyRSAKeyBlob(const std::vector<byte>& blobData, const bool extraDataOkay = false);

        // destructor
        virtual ~CoolkeyRSAKeyBlob();


        // getters for raw blob data
        size_t getBlobSize() const { return this->m_blobData.size(); }
        const std::vector<byte>& getBlobData() const { return this->m_blobData; }

        // getters for key blob fields
        const byte getKeyEncoding() const { return this->m_encoding; }
        const byte getKeyType() const { return this->m_keyType; }
        const size_t getKeyLengthBits() const { return this->m_keyLengthBits; }
        const std::vector<byte>& getModulusData() const { return this->m_modulusData; }
        const std::vector<byte>& getExponentData() const { return this->m_exponentData; }


        // getter for openssl RSA key object
        //   rules: 
        //   1. valid for the lifetime of this
        //   2. don't free (will be automatically freed by this)
        //   3. guaranteed to not be NULL (provided complete construction of the object occurs)
        const RSA* getOpensslRSAKey() const{ return this->m_rsaKey; }
};

//----------------------------------------------------------------------

#endif 
