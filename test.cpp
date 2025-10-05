#include"Elleptical_curve.h"
#include"key.h"
#include<fstream>
//secp256k1 curve 256 bit of information

struct DataContext{
string seed;
string master_private_key;
string master_public_key_hash;
}Context;
bool verify_checksum(string data,string checksum){
    char * hash=unkeyed_Hash(toByte(data),SHA256);
    string c;
    for(int i=0;i<8;i++) c.push_back(hash[i]);
    delete[]hash;
    if(c==checksum){
        return true;
    }
    return false;
}
bool verify_SEED(string seed)
{
    string data,checksum;
    data=seed.substr(0,32);
    checksum=seed.substr(32);
    return verify_checksum(data,checksum);
}

void SaveToFile(string public_key_hash,char * private_key,char * seed){
    std::vector<unsigned char>data=hex_to_bytes(std::string(seed));
    std::ofstream file;
    file.open("SInformation.dat",std::ios::out|std::ios::binary);
    file.write(reinterpret_cast<char*>(&data[0]),data.size());
    data=hex_to_bytes(public_key_hash);
    file.write(reinterpret_cast<char*>(&data[0]),data.size());
    std::vector<unsigned char>PR=hex_to_bytes(std::string(private_key));
    file.write(reinterpret_cast<char*>(&PR[0]),PR.size());
    file.close();
}
void ReadFromFile(){
    std::ifstream file;
    file.open("SInformation.dat",std::ios::in| std::ios::binary);
    std::vector<unsigned char>data(20);
    file.read(reinterpret_cast<char*>(&data[0]),20);
    Context.seed=bytes_to_hex(data);
    file.read(reinterpret_cast<char*>(&data[0]),20);
    Context.master_public_key_hash=bytes_to_hex(data);
    std::vector<unsigned char>PR(32);
    file.read(reinterpret_cast<char*>(&PR[0]),32);
    Context.master_private_key=bytes_to_hex(PR);
    file.close();
}

void Register()
{
    Elliptical_curve obj;
    char * seed=obj.seed(128);
    char * checksum=unkeyed_Hash(toByte(std::string(seed)),SHA256); //need first 32 bit of the result.
    char * SEED=new char[41];
    int i=0;
    while(seed[i]!='\0'){
        SEED[i]=seed[i];
        i++;
    }
    SEED[i]=checksum[0],SEED[i+1]=checksum[1],SEED[i+2]=checksum[2],SEED[i+3]=checksum[3],SEED[i+4]=checksum[4],SEED[i+5]=checksum[5];
    SEED[i+6]=checksum[6],SEED[i+7]=checksum[7],SEED[40]='\0';
    OPENSSL_free(seed),OPENSSL_free(checksum);
    std::cout<<"Seed= "<<SEED<<std::endl;
    char * private_key=Keyed_Hash(toByte(string(SEED)),"Anjul",SHA256);
    std::cout<<"Private_key= "<<private_key<<std::endl;
    auto public_key=obj.Public_key(private_key);
    std::cout<<"Publickey= "<<public_key.first<< " , "<<public_key.second<<std::endl;
    string temp=public_key.first;
    temp=temp+public_key.second;
    char * hash=unkeyed_Hash(toByte(temp),SHA256);
    temp=hash+32;//last 128 bit
    OPENSSL_free(hash);
    hash=nullptr;
    hash=unkeyed_Hash(toByte(temp),SHA256);
    for(i=0;i<8;i++) temp.push_back(hash[i]);
    OPENSSL_free(hash);
    std::cout<<"Public key hash= "<<temp<<std::endl;
    SaveToFile(temp,private_key,SEED);
}
char *  signIN(char * private_key,std::pair<char*,char*>& public_key,Elliptical_curve& ep)
{
    std::cout<<"Master_Private key: " <<Context.master_private_key<<std::endl;
    std::cout<<"Master publickey hash: " <<Context.master_public_key_hash<<std::endl;
    std::cout<<"-------------------------------------------------------------------\n";
    std::cout<<"Session private key: "<<private_key<<std::endl;
    std::cout<<"Publickey X: "<<public_key.first<<std::endl;
    std::cout<<"Publickey Y: "<<public_key.second<<std::endl;
    string msg=Context.master_public_key_hash;
    msg=msg+public_key.first;
    msg=msg+public_key.second;
    char * hash=unkeyed_Hash(toByte(msg),SHA256);
    auto sig=ep.Signature_Generate(private_key,hash,ECDSA);
    std::cout<<"signature s: "<<sig.first<<" , "<<"r: "<<sig.second<<std::endl;
    std::cout<<"msg= "<<hash<<std::endl;
    return private_key;
}
void key_block(char * secret,string label,char *seed)
{
    //using the same PRF of TLS assuming AES 256 so we need three rounds to have 96 bytes of secret information
    string A[4];
    string SEED=label+seed;
    A[0]=SEED;
    string key=toByte(string(secret));
    for(int i=1;i<=3;i++){
        A[i]=Keyed_Hash(key,toByte(A[i-1]),SHA256);
    }
    char * Session_secret=Keyed_Hash(key,toByte(A[1]+SEED),SHA256);
    char * MAC_secret=Keyed_Hash(key,toByte(A[2]+SEED),SHA256);
    char * IV=Keyed_Hash(key,toByte(A[3]+SEED),SHA256);
    std::cout<<"Session_secret : "<<Session_secret<<std::endl;
    std::cout<<"MAC_Secret : "<<MAC_secret<<std::endl;
    std::cout<<"IV: "<<IV<<std::endl;
    OPENSSL_free(Session_secret);
    OPENSSL_free(MAC_secret);
    OPENSSL_free(IV);
}
int main()
{
    int choice;
    std::cout<<"Enter 1. Register and 2. signIn\n";
    std::cin>>choice;
    if(choice==1){
        Register();
    }
    else if(choice==2){
        ReadFromFile();
        Elliptical_curve ep;
        char * private_key=ep.seed(160);
        auto session_public_key=ep.Public_key(private_key);
        signIN(private_key,session_public_key,ep); //session private key.
        std::cout<<"Phase-2 challange- response \n";
        std::cout<<"..................Server's signature verification................\n";
        std::pair<const char*,const char*>public_key={"1EEEB755192165A3751F1CF00BD5FB302E456C0AF9771E49B242D647DA31AD4C",
            "7BEF17D62A82C94D758C8167C0EF4C10C2A426275C82602F1B3AE98A47FFFB9C"};
        std::cout<<"Servers publickey_x: "<<public_key.first<<std::endl;
        std::cout<<"Servers publickey_y: "<<public_key.second<<std::endl;
        char * n1=ep.response(public_key.first,public_key.second,private_key); //secret value to prepare nonce
        std::pair<string,string>hint;
        std::cout<<"Hint1: ";
        std::cin>>hint.first;
        std::cout<<"Hint2: ";
        std::cin>>hint.second;
        std::pair<string,string>signature;
        std::cout<<"Signature s: ";
        std::cin>>signature.first;
        std::cout<<"Signature r: ";
        std::cin>>signature.second;
        string hash=Context.master_public_key_hash+hint.first+hint.second+session_public_key.first+session_public_key.second;
        if(!ep.verify_signature(public_key.first,public_key.second,unkeyed_Hash(toByte(hash),SHA256),signature.first.data(),signature.second.data(),ECDSA)){
            std::cout<<"Signature is not valid!";
            exit(1);
        }else{
            std::cout<<"Signature is valid!\n";
        }
        //response is the proof of layer ownership 
        //calculate the nonce. //without the corresponding sessoin private key against the publickey sent to the server it is not possible to derive nonce.
        char * secret=unkeyed_Hash (toByte(string(ep.response(hint.first.data(),hint.second.data(),private_key))),SHA256);
        char * h=Keyed_Hash(toByte(string(secret)),toByte(Context.master_public_key_hash),SHA256);
        char * nonce=Keyed_Hash(toByte(string(n1)),toByte(string(h)),SHA256);//nonce =hmac(n1,hmac(secret,public_key_hash))
        char * msg=unkeyed_Hash(toByte(Context.master_public_key_hash+string(nonce)),SHA256);
        auto sig=ep.Signature_Generate(Context.master_private_key.data(),msg,ECDSA);
        std::cout<<"Signature from master privatekey\n";
        std::cout<<"s: "<<sig.first<<std::endl;
        std::cout<<"r: "<<sig.second<<std::endl;
        std::cout<<"========================================================================\nnonce= "<<nonce<<std::endl;
        std::cout<<"Secret for nonce: "<<n1<<std::endl;
        std::cout<<"pre shared Secret: "<<secret<<std::endl;
        key_block(secret,"4b65792045786368616e6765",nonce);
        OPENSSL_free(private_key);
        OPENSSL_free(secret);
        OPENSSL_free(nonce);
        OPENSSL_free(n1);
        OPENSSL_free(h);

    }
    return 0;
}