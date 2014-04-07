//----------------------------------------------------------------------
// See Endianness.h
//----------------------------------------------------------------------

#include "Endianness.h"

//----------------------------------------------------------------------
// PUBLIC STATIC
//   returns true if this is a big endian compiler
bool Endianness::is_big_endian(){
    union{
        uint32_t i;
        char c[4];
    } bint = {0x01020304};
    return bint.c[0] == 1;
}

//----------------------------------------------------------------------
// PUBLIC STATIC
//   converts a 32-bit integer from network to host byte order
uint32_t Endianness::ntohl(uint32_t l){
    if (is_big_endian() == true){
        return l;
    }else{
        return ((l>>24)&0x000000FF) | ((l>>8)&0x0000FF00) | ((l<<8)&0x00FF0000) | ((l<<24)&0xFF000000);
    }
}

//----------------------------------------------------------------------
// PUBLIC STATIC
//   converts a 32-bit integer from host to network byte order
uint32_t Endianness::htonl(uint32_t l){
    return ntohl(l);
}

//----------------------------------------------------------------------
// PUBLIC STATIC
//   converts a 16-bit integer from network to host byte order
uint16_t Endianness::ntohs(uint16_t s){
    if (is_big_endian() == true){
        return s;
    }else{
        return ((s>>8)&0x00FF) | ((s<<8)&0xFF00);
    }
}

//----------------------------------------------------------------------
// PUBLIC STATIC
//   converts a 16-bit integer from host to network byte order
uint16_t Endianness::htons(uint16_t l){
    return ntohs(l);
}

//----------------------------------------------------------------------
