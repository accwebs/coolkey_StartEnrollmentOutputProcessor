/*
 * CKYStartEnrollmentOutputProcessor - A simple utility tool that performs processing
 *              and validation of the result of Coolkey's SecureStartEnrollment() 
 *              command.  Parses and retrieves the public key; verifies that the
 *              proof-of-location field (signature) is as expected.
 *
 * Written by Aaron Curley
 */

//----------------------------------------------------------------------

#include "CKYStartEnrollmentOutputProcessor.h"

#include <stdexcept>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <fstream>

#include "CoolkeyRSAKeyBlob.h"
#include "CoolkeyRSAKeyGenResult.h"

//----------------------------------------------------------------------
// converts a byte vector to a hexadecimal string in the form of AA:BB:CC:etc
std::string Bytes_To_String(const std::vector<byte>& v){
    std::stringstream ss;
    for(std::vector<byte>::const_iterator it = v.begin(); it != v.end(); it++){
        int thisNum = *it;
        ss << std::setfill('0') << std::setw(2) << std::hex << thisNum << ":";
    }

    std::string result = ss.str();
    if (result.size() > 0){
        result.erase(result.length() - 1);
    }
    return result;
}

//----------------------------------------------------------------------
// Converts a string of ASCII-encoded hex to a byte array.
std::vector<byte> Convert_ASCIIHex_To_Byte(std::string str){
    // strip out any separator characters from this string
    StringReplaceAll(str, ":", "");
    StringReplaceAll(str, " ", "");

    std::vector<byte> result;

    std::stringstream converter;
    size_t pos = 1;
    while (pos < str.length()){
        // get two characters from string
        std::string twoChars(str.substr(pos - 1, 2));

        // convert two characters to int
        converter.clear();
        converter << std::hex << twoChars;
        int temp;
        converter >> temp;

        // save result
        result.push_back(static_cast<byte>(temp));
        
        // skip forward two characters
        pos += 2; 
    }

    return result;
}

//----------------------------------------------------------------------
// replaces all instances of a string with a new string
void StringReplaceAll(std::string& str, const std::string& from, const std::string& to){
    if (from.empty() == true){
        return;
    }
    size_t start_pos = 0;
    while((start_pos = str.find(from, start_pos)) != std::string::npos){
        str.replace(start_pos, from.length(), to);
        start_pos += to.length();
    }
}

//----------------------------------------------------------------------
// entry point of this program
int main(int argc, const char** const argv){
    int retcode;

    if (argc != 3){
        std::cout << PROGRAM_NAME << "  -  " << PROGRAM_VERSION << std::endl;
        std::cout << PROGRAM_DESCRIPTION << std::endl;
        std::cout << std::endl;
        std::cout << "Usage:  " << PROGRAM_EXECUTABLE << " <resulting iobuf file> <wrappedkey file>" << std::endl;
        std::cout << "  Files should both contain data in ASCII-hex format on a single line." << std::endl;
        std::cout << std::endl;
        retcode = 1;
    }else{
        // print program name and version
        std::cout << PROGRAM_NAME << "  -  " << PROGRAM_VERSION << "\n" << std::endl;

        // convert iobuf filename to std::string
        const std::string iobuf_filepath(argv[1]);

        // convert wrappedkey filename to std::string
        const std::string wrappedkey_filepath(argv[2]);
        
        try{
            // open input files
            std::ifstream iobuf_file(iobuf_filepath);
            if (iobuf_file.good() == false){
                throw std::runtime_error("Unable to open iobuf file.");
            }
            std::ifstream wrappedKey_file(wrappedkey_filepath);
            if (wrappedKey_file.good() == false){
                throw std::runtime_error("Unable to open wrappedKey file.");
            }
            
            // read in one line of text from each file
            std::string iobuf_data_str;
            std::getline(iobuf_file, iobuf_data_str);
            std::string wrappedkey_data_str;
            std::getline(wrappedKey_file, wrappedkey_data_str);

            // convert from ASCII-hex to byte array
            std::vector<byte> iobuf_data(Convert_ASCIIHex_To_Byte(iobuf_data_str));
            std::vector<byte> wrappedkey_data(Convert_ASCIIHex_To_Byte(wrappedkey_data_str));

            try{
                // try to parse RSA key gen result blob
                CoolkeyRSAKeyGenResult coolkeyRSAKeyGenResult(iobuf_data);

                // if we made it here, parsing was successful so print out what we've parsed

                // get reference to internal (parsed) key blob object
                const CoolkeyRSAKeyBlob& coolkeyRSAKeyBlob = coolkeyRSAKeyGenResult.getBlob();

                // print out what we've parsed thus far
                std::cout << "Key blob data:\n"
                          << "0x" << Bytes_To_String(coolkeyRSAKeyBlob.getBlobData()) << "\n"
                          << "  Length (of blob): " << std::dec << coolkeyRSAKeyBlob.getBlobSize() << "\n"
                          << "  Key Encoding:     0x" << std::setw(2) << std::setfill('0') << std::hex << static_cast<size_t>(coolkeyRSAKeyBlob.getKeyEncoding()) << "\n"
                          << "  Key Type:         0x" << std::setw(2) << std::setfill('0') << std::hex << static_cast<size_t>(coolkeyRSAKeyBlob.getKeyType()) << "\n"
                          << "  Key Length (bits):" << std::dec << coolkeyRSAKeyBlob.getKeyLengthBits() << "\n"
                          << "  Pub Key Exponent: 0x" << Bytes_To_String(coolkeyRSAKeyBlob.getExponentData()) << "\n"
                          << "  Pub Key Modulus:  0x" << Bytes_To_String(coolkeyRSAKeyBlob.getModulusData()) << "\n"
                          << "\n"
                          << "Key proof data:\n"
                          << "0x" << Bytes_To_String(coolkeyRSAKeyGenResult.getProofData()) << "\n"
                          << "  Length (of proof):" << std::dec << coolkeyRSAKeyGenResult.getProofSize() << "\n\n";

                try{
                    // try to verify RSA key gen result blob
                    coolkeyRSAKeyGenResult.verifySignature(wrappedkey_data);
                    
                    // if we made it here, validation was successful
                    std::cout << "Successfully validated RSA key gen result!" << std::endl;
                    retcode = 0;

                }catch (std::runtime_error& ex){
                    std::cout << "Exception thrown while validating RSA key gen result: " << ((ex.what() == nullptr) ? "<null>" : ex.what());
                    std::cout << std::endl;

                    retcode = 30;
                }catch (...){
                    std::cout << "Unknown exception thrown while validating RSA key gen result.";
                    std::cout << std::endl;

                    retcode = 30;
                }

            }catch (std::runtime_error& ex){
                std::cout << "Exception thrown while parsing RSA key gen result: " << ((ex.what() == nullptr) ? "<null>" : ex.what());
                std::cout << std::endl;

                retcode = 20;
            }catch (...){
                std::cout << "Unknown exception thrown while parsing RSA key gen result.";
                std::cout << std::endl;

                retcode = 20;
            }

        }catch(std::runtime_error& ex){
            std::cout << "Exception thrown: " << ((ex.what() == nullptr) ? "<null>" : ex.what());
            std::cout << std::endl;

            retcode = 10;
        }catch(...){
            std::cout << "Unknown exception thrown.";
            std::cout << std::endl;

            retcode = 10;
        } 
        
    } // endif arguments are correct

    return retcode;
}

//----------------------------------------------------------------------
