#pragma once
#ifdef _WIN32
#define DLL_EXPORT __declspec(dllexport)
#else
#define DLL_EXPORT
#endif
#include"Elleptical_curve.h"
#include"key.h"
struct Pair{
    char * first;
    char * second;
};
extern "C"{
    DLL_EXPORT Pair GeneratePublicKey(char * );
    DLL_EXPORT Pair Challange(char *,char*);
    DLL_EXPORT Pair GenerateSignature(char*,char*);
    DLL_EXPORT bool Verify_Signature(char * ,char* , char*, char* , char*);
    DLL_EXPORT void Free_keys(char* c){
        delete []c;
    }
    DLL_EXPORT char* HS256(char * ,char *);
    DLL_EXPORT char * checksum(char *,char*);
    DLL_EXPORT char * Response(char *, char* ,char *);
}