#include"ECC.h"

extern "C"{
    Elliptical_curve obj;
    DLL_EXPORT Pair GeneratePublicKey(char * Private_key){
        Pair sub;
        auto public_key=obj.Public_key(Private_key);
        sub.first=new char[strlen(public_key.first)+1];
        sub.second=new char[strlen(public_key.second)+1];
        strcpy(sub.first,public_key.first);
        strcpy(sub.second,public_key.second);
        OPENSSL_free(public_key.first);
        OPENSSL_free(public_key.second);
        return sub;
    }
    DLL_EXPORT Pair Challange(char *PUa,char*PUb) //return s the point in first and the value which is secret to second
    {
        auto question=obj.challange(PUa,PUb);
        Pair sub;
        sub.first=new char[strlen(question.first.first)*2+1]; //its the bulk of point which len is 64 per a single x-cord 
        char * secret=unkeyed_Hash(toByte(string(question.second)),SHA256); //sha256 of the value to get secret
        sub.second=new char[strlen(secret)+1];
        strcpy(sub.second,secret);
        OPENSSL_free(secret);
        OPENSSL_free(question.second);
        string temp=question.first.first;
        temp=temp+question.first.second;
        strcpy(sub.first,temp.data());
        OPENSSL_free(question.first.first);OPENSSL_free(question.first.second);
        return sub;       
    }
    DLL_EXPORT Pair GenerateSignature(char*PR,char*hash){
        auto sig=obj.Signature_Generate(PR,hash,ECDSA);
        Pair sub;
        sub.first=new char[strlen(sig.first)+1];
        sub.second=new char[strlen(sig.second)+1];
        strcpy(sub.first,sig.first);
        strcpy(sub.second,sig.second);
        OPENSSL_free(sig.first);OPENSSL_free(sig.second);
        return sub;
    }

    DLL_EXPORT bool Verify_Signature(char *PUa ,char*PUb , char* hash, char*s , char*r)
    {
        return obj.verify_signature(PUa,PUb,hash,s,r,ECDSA);
    }

    DLL_EXPORT char* HS256(char *data ,char *key){
        return Keyed_Hash(toByte(string(key)),toByte(string(data)),SHA256);
    }

    DLL_EXPORT char* checksum(char * PUa,char*  PUb){
         string temp=PUa;
        temp=temp+PUb;
        char * hash=unkeyed_Hash(toByte(temp),SHA256);
        temp=hash+32;//last 128 bit
        OPENSSL_free(hash);
        hash=nullptr;
        hash=unkeyed_Hash(toByte(temp),SHA256);
        for(int i=0;i<8;i++) temp.push_back(hash[i]);
        OPENSSL_free(hash);
        char * output=new char[temp.length()+1];
        strcpy(output,temp.data());
        return output;
    }
     DLL_EXPORT char * Response(char *PUa, char* PUb,char *PR)
    {
        return obj.response(PUa,PUb,PR); //compute the secret value.
    }

}