//----------------------------------------------------------------------
// Defines helper functions for machine endianness.
//----------------------------------------------------------------------

#ifndef EndiannessH_Included
#define EndiannessH_Included

//----------------------------------------------------------------------

class Endianness;

//----------------------------------------------------------------------

#include <cstdint>

//----------------------------------------------------------------------

class Endianness{
    public:
        // returns true if this is a big endian compiler
        static bool is_big_endian();
        // converts a 32-bit integer from network to host byte order
        static uint32_t ntohl(uint32_t l);
        // converts a 32-bit integer from host to network byte order
        static uint32_t htonl(uint32_t l);
        // converts a 16-bit integer from network to host byte order
        static uint16_t ntohs(uint16_t s);
        // converts a 16-bit integer from host to network byte order
        static uint16_t htons(uint16_t l);

    private:
        // prevent copying and assignment
        Endianness(const Endianness& src);
        Endianness operator=(const Endianness& rhs);

        // prevent construction
        Endianness();
};

//----------------------------------------------------------------------

#endif 
