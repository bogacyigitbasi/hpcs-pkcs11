#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <dlfcn.h>
#include "sample.h"

CK_FUNCTION_LIST *funcs;
CK_SESSION_HANDLE session;
CK_OBJECT_HANDLE privateKey;

// Helper function to find an object (private key) in the keystore
CK_RV findPrivateKey(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE *privateKey)
{
    CK_ATTRIBUTE searchTemplate[] = {
        {CKA_CLASS, &(CK_OBJECT_CLASS){CKO_PRIVATE_KEY}, sizeof(CK_OBJECT_CLASS)},
        {CKA_LABEL, "KEY_STORE_PAIR", strlen("KEY_STORE_PAIR")} // name of
    };
    /* CK_BYTE_PTR keyID ="876f";
     CK_ULONG keyIDLen = strlen(keyID);
     CK_ATTRIBUTE searchTemplate[] = {
         {CKA_CLASS, &(CK_OBJECT_CLASS){CKO_PRIVATE_KEY}, sizeof(CK_OBJECT_CLASS)},
         {CKA_ID, keyID, keyIDLen} // Search by key ID
     };*/
    CK_ULONG objectCount;

    CK_RV rc = funcs->C_FindObjectsInit(session, searchTemplate, sizeof(searchTemplate) / sizeof(CK_ATTRIBUTE));
    if (rc != CKR_OK)
    {
        printf("error C_FindObjectsInit: rc=0x%04lx\n", rc);
        return rc;
    }

    rc = funcs->C_FindObjects(session, privateKey, 1, &objectCount);
    if (rc != CKR_OK || objectCount == 0)
    {
        printf("Private key not found. error C_FindObjects: rc=0x%04lx\n", rc);
        funcs->C_FindObjectsFinal(session);
        return rc == CKR_OK ? CKR_KEY_HANDLE_INVALID : rc;
    }

    rc = funcs->C_FindObjectsFinal(session);
    if (rc != CKR_OK)
    {
        printf("error C_FindObjectsFinal: rc=0x%04lx\n", rc);
        return rc;
    }

    return CKR_OK;
}

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <dlfcn.h>
#include <sys/timeb.h>
#include "sample.h"

CK_FUNCTION_LIST *funcs;
CK_BYTE tokenNameBuf[32];
const char tokenName[] = "testToken";

int main(int argc, char **argv)
{
    CK_C_INITIALIZE_ARGS initArgs;
    CK_RV rc;
    CK_FLAGS flags = 0;
    CK_SESSION_HANDLE session;
    // CK_MECHANISM            mech;
    CK_OBJECT_HANDLE publicKey, privateKey, aesKey;
    static CK_BBOOL isTrue = TRUE;

    CK_RV(*pFunc)
    ();
    void *pkcs11Lib;
    CK_UTF8CHAR_PTR soPin = (unsigned char *)"";
    CK_UTF8CHAR_PTR userPin = (unsigned char *)"";
    char pkcs11LibName[] = "pkcs11-grep11-amd64.so.2.6.7";

    printf("Opening the PKCS11 library...\n");
    pkcs11Lib = dlopen(pkcs11LibName, RTLD_NOW);
    if (pkcs11Lib == NULL)
    {
        printf("%s not found. Ensure that the PKCS11 library is in the system library path or LD_LIBRARY_PATH\n", pkcs11LibName);
        return !CKR_OK;
    }

    printf("Getting the PKCS11 function list...\n");
    pFunc = (CK_RV(*)())dlsym(pkcs11Lib, "C_GetFunctionList");
    // CK_RV (*pFunc) (CK_FUNCTION_LIST_PTR_PTR);
    // pFunc = (CK_RV (*) (CK_FUNCTION_LIST_PTR_PTR)) dlsym(pkcs11Lib, "C_GetFunctionList");

    if (pFunc == NULL)
    {
        printf("C_GetFunctionList() not found in module %s\n", pkcs11LibName);
        return !CKR_OK;
    }
    rc = pFunc(&funcs);
    if (rc != CKR_OK)
    {
        printf("error C_GetFunctionList: rc=0x%04lx\n", rc);
        return !CKR_OK;
    }

    printf("Initializing the PKCS11 environment...\n");
    memset(&initArgs, 0x0, sizeof(initArgs));
    rc = funcs->C_Initialize(&initArgs);
    if (rc != CKR_OK)
    {
        printf("error C_Initialize: rc=0x%04lx\n", rc);
        return !CKR_OK;
    }

    printf("Initializing the token... \n");
    memset(tokenNameBuf, ' ', sizeof(tokenNameBuf)); /* Token name is left justified, padded with blanks */
    memcpy(tokenNameBuf, tokenName, strlen(tokenName));

    /* C_InitToken cleans up private and public keystore thus only needs to be done once.
     * Subsequent C_InitToken calls will delete any existing keys within the keystores
     */
    rc = funcs->C_InitToken(0, soPin, strlen((const char *)soPin), tokenNameBuf);
    if (rc != CKR_OK)
    {
        printf("error C_InitToken: rc=0x%04lx\n", rc);
        funcs->C_Finalize(NULL);
        return !CKR_OK;
    }

    flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    printf("Opening a session... \n");
    rc = funcs->C_OpenSession(0, flags, (CK_VOID_PTR)NULL, NULL, &session);
    if (rc != CKR_OK)
    {
        printf("error C_OpenSession: rc=0x%04lx\n", rc);
        funcs->C_Finalize(NULL);
        return !CKR_OK;
    }

    printf("Logging in as normal user... \n");
    rc = funcs->C_Login(session, CKU_USER, userPin, strlen((const char *)userPin));
    if (rc != CKR_OK)
    {
        printf("error C_Login: rc=0x%04lx\n", rc);
        funcs->C_Finalize(NULL);
        return !CKR_OK;
    }

    CK_MECHANISM mech = {CKM_ECDSA, NULL, 0};

    // Assuming the session and PKCS#11 library initialization have been done.
    // Find the private key
    rc = findPrivateKey(session, &privateKey);
    if (rc != CKR_OK)
    {
        printf("Failed to find private key: rc=0x%04lx\n", rc);
        funcs->C_Finalize(NULL);
        return rc;
    }

    // Prepare the message for signing
    CK_BYTE dataToBeSigned[] = "This is data to be signed using the existing private key";
    CK_ULONG dataToBeSignedLen = sizeof(dataToBeSigned) - 1;
    CK_BYTE signature[64];
    CK_ULONG signatureLen = sizeof(signature);

    // Initialize signing operation
    printf("Initializing signing operation...\n");
    rc = funcs->C_SignInit(session, &mech, privateKey);
    if (rc != CKR_OK)
    {
        printf("error C_SignInit: rc=0x%04lx\n", rc);
        funcs->C_Finalize(NULL);
        return rc;
    }

    // Sign the data
    printf("Signing the message...\n");
    rc = funcs->C_Sign(session, dataToBeSigned, dataToBeSignedLen, signature, &signatureLen);
    if (rc != CKR_OK)
    {
        printf("error C_Sign: rc=0x%04lx\n", rc);
        funcs->C_Finalize(NULL);
        return rc;
    }

    printf("Signature generated successfully. Signature length: %lu bytes\n", signatureLen);

    // Print the signature (optional, for debugging purposes)
    printf("Signature: ");
    for (CK_ULONG i = 0; i < signatureLen; i++)
    {
        printf("%02x", signature[i]);
    }
    printf("\n");

    // Clean up
    printf("Finalizing...\n");
    rc = funcs->C_Finalize(NULL);
    if (rc != CKR_OK)
    {
        printf("error C_Finalize: rc=0x%04lx\n", rc);
        return rc;
    }

    printf("Operation completed successfully.\n");

    /*  printf("Verifying with ECDSA public key... \n");
      rc = funcs->C_VerifyInit(session, &mech, publicKey);
      if (rc != CKR_OK) {
          printf("error C_VerifyInit: rc=0x%04lx\n", rc );
          funcs->C_Finalize( NULL );
          return !CKR_OK;
      }

      rc = funcs->C_Verify(session, dataToBeSigned, dataToBeSignedLen, signature, signatureLen);
      if (rc != CKR_OK) {
          printf("error C_Verify: rc=0x%04lx\n", rc );
          funcs->C_Finalize( NULL );
          return !CKR_OK;
      }
  */
    printf("Logging out... \n");
    rc = funcs->C_Logout(session);
    if (rc != CKR_OK)
    {
        printf("error C_Logout: rc=0x%04lx\n", rc);
        funcs->C_Finalize(NULL);
        return !CKR_OK;
    }

    printf("Closing the session... \n");
    rc = funcs->C_CloseSession(session);
    if (rc != CKR_OK)
    {
        printf("error C_CloseSession: rc=0x%04lx\n", rc);
        return !CKR_OK;
    }

    printf("Finalizing... \n");
    rc = funcs->C_Finalize(NULL);
    if (rc != CKR_OK)
    {
        printf("error C_Finalize: rc=0x%04lx\n", rc);
        return !CKR_OK;
    }
    printf("Sample completed successfully!\n");
    return 0;
}
