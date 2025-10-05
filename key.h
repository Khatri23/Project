#pragma once
#ifndef MESSAGEDIGEST
#include<iostream>
#include<vector>
#include<string.h>
#include<openssl/evp.h>
#include<openssl/hmac.h>
#include<stdint.h>
using std::string;
//function to use :support sha256 and sha512 which are in common and expandable.
enum Message_Digest{
    SHA256, SHA512
};
string toByte(string  data)
{
    string result;
    if(data.length() &1 ) data="0"+data;
    for(int i=0;i<data.length();i+=2){
        char c=char( std::stoul(data.substr(i,2),nullptr,16));
        result.push_back(c);
    }
    return result;
}
char * unkeyed_Hash(string data, enum Message_Digest hash)//return hex encoded of the given input, for hex convert to byte
{
    EVP_MD_CTX * ctx=EVP_MD_CTX_new();
    if(!ctx){
        std::cerr<<"Unable to initialize";
        EVP_MD_CTX_free(ctx);
        exit(1);
    }
    const EVP_MD * md=nullptr;
    switch (hash)
    {
        case SHA256 :md=EVP_sha256(); break;
        case SHA512: md=EVP_sha512(); break;
    }
    if(EVP_DigestInit_ex(ctx,md,nullptr) !=1){
        std::cerr<<"Unable to initialize the hash!";
        EVP_MD_CTX_free(ctx);
         exit(1);
    }
    if(EVP_DigestUpdate(ctx,data.data(),data.length())!=1){
        std::cerr<<"Unable to updata the data!";
        EVP_MD_CTX_free(ctx);
        exit(1);
    }
    unsigned size;
    unsigned char h[EVP_MAX_MD_SIZE];
    EVP_DigestFinal(ctx,h,&size);
    char *result=new char[size*2+1];//given result is in byte and output is in hex.
    for(int i=0;i<size;i++)
    {
        sprintf(result+i*2,"%02x",h[i]);
    }
    result[size*2]='\0';
    EVP_MD_CTX_free(ctx);
    return result;
}
char * Keyed_Hash(string key,string data,enum Message_Digest hash)//outputs the hex
{
    unsigned len;
    const EVP_MD * md=nullptr;
    switch (hash)
    {
        case SHA256 :md=EVP_sha256(); break;
        case SHA512: md=EVP_sha512(); break;
    }    
    unsigned char *h= HMAC(md,key.data(),key.length(),reinterpret_cast<unsigned char*>(data.data()),data.length(),nullptr,&len);    
     char * result=new char[len*2+1];
    for(int i=0;i<len;i++)
    {
        sprintf(result+i*2,"%02x",h[i]);
    }
    result[len*2]='\0';   
    return result; 
    return result;
}

std::vector<unsigned char> hex_to_bytes(const std::string& hex) {
    std::vector<unsigned char> bytes;
    if (hex.size() % 2 != 0)
        throw std::invalid_argument("Hex string must have even length");

    for (size_t i = 0; i < hex.length(); i += 2) {
        unsigned int byte;
        std::stringstream ss;
        ss << std::hex << hex.substr(i, 2);
        ss >> byte;
        bytes.push_back(static_cast<unsigned char>(byte));
    }
    return bytes;
}
std::string bytes_to_hex(const std::vector<unsigned char>& bytes) {
    std::ostringstream oss;
    for (unsigned char byte : bytes)
        oss << std::hex << (byte >> 4) << (byte & 0xF);
    return oss.str();
}
#endif