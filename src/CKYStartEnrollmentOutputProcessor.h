/*
 * CKYStartEnrollmentOutputProcessor - A simple utility tool that performs processing
 *              and validation of the result of Coolkey's SecureStartEnrollment() 
 *              command.  Parses and retrieves the public key; verifies that the
 *              proof-of-location field (signature) is as expected.
 *
 * Written by Aaron Curley
 */

//----------------------------------------------------------------------

#ifndef CKYStartEnrollmentOutputProcessor_H_Included
#define CKYStartEnrollmentOutputProcessor_H_Included

//----------------------------------------------------------------------

#include <vector>
#include <string>

typedef unsigned char BYTE;
typedef unsigned char byte;

//----------------------------------------------------------------------
// PUBLIC STATIC
// program constants
const std::string PROGRAM_NAME("CKYStartEnrollmentOutputProcessor");
const std::string PROGRAM_EXECUTABLE("CKYStartEnrollmentOutputProcessor.exe");
const std::string PROGRAM_VERSION("1.0");
const std::string PROGRAM_DESCRIPTION(std::string("A simple utility tool that performs processing and validation of the\n") +
                                                  "result of Coolkey's SecureStartEnrollment() command.  Parses and\n" + 
                                                  "retrieves the public key; verifies that the proof-of-location field\n" + 
                                                  "(signature) is as expected.");

//----------------------------------------------------------------------
// PROTOTYPES
std::string Bytes_To_String(const std::vector<byte>& v);
std::vector<byte> Convert_ASCIIHex_To_Byte(std::string str);
void StringReplaceAll(std::string& str, const std::string& from, const std::string& to);
int main(int argc, const char** const argv);

//----------------------------------------------------------------------

#endif

//----------------------------------------------------------------------
