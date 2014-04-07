find_package(OpenSSL REQUIRED)



SET(header_files  CKYStartEnrollmentOutputProcessor.h
                  CoolkeyRSAKeyBlob.h
                  CoolkeyRSAKeyGenResult.h
                  Endianness.h)

SET(SOURCES       CKYStartEnrollmentOutputProcessor.cpp
                  CoolkeyRSAKeyBlob.cpp
                  CoolkeyRSAKeyGenResult.cpp
                  Endianness.cpp
                  ${header_files})

source_group("Headers" FILES ${header_files})



INCLUDE_DIRECTORIES(${OPENSSL_INCLUDE_DIR})



ADD_EXECUTABLE(CKYStartEnrollmentOutputProcessor ${SOURCES})



TARGET_LINK_LIBRARIES(CKYStartEnrollmentOutputProcessor ${OPENSSL_LIBRARIES})



INSTALL(TARGETS CKYStartEnrollmentOutputProcessor DESTINATION bin)
