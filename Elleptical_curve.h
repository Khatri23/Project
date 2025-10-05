#ifndef ELLIPTICAL_CURVE
#include<iostream>
#include<openssl/bn.h>
#include<openssl/rand.h>
#include<unordered_map>
#include<openssl/keccak.h>
//elliptical curve defined on secp256k k means Koblitz curve E(0,7) prime is 256 bits long .. y^2=x^3+7.
using std::string;
std::unordered_map<char,string>hextobin={
    {'0',"0000"},
    {'1',"0001"},
    {'2',"0010"},
    {'3',"0011"},
    {'4',"0100"},
    {'5',"0101"},
    {'6',"0110"},
    {'7',"0111"},
    {'8',"1000"},
    {'9',"1001"},
    {'A',"1010"},
    {'B',"1011"},
    {'C',"1100"},
    {'D',"1101"},
    {'E',"1110"},
    {'F',"1111"},
    {'a',"1010"},
    {'b',"1011"},
    {'c',"1100"},
    {'d',"1101"},
    {'e',"1110"},
    {'f',"1111"}
};
enum Signature_flag{
    ECDSA,SCHNORR
};

class Elliptical_curve{
private:
    BIGNUM *prime;
    BIGNUM * n;//multiplicative order
    BIGNUM *a,*b;//coefficient.
    BIGNUM **G;
    BN_CTX *ctx;//for cleanup
public:
    Elliptical_curve();
    ~Elliptical_curve(){
        BN_free(prime);
        BN_free(n);
        BN_free(a),BN_free(b);
        BN_free(G[0]),BN_free(G[1]);
        BN_CTX_free(ctx);
        delete []G;
    }
 
    char * seed(int bits)
    {
        BIGNUM *rnd=BN_new();
        //private key should be less than that n 
       BN_rand(rnd,bits,0,0);
        char * str=BN_bn2hex(rnd);
        BN_free(rnd);
        return str;
    }
    std::pair<char *,char*> Public_key(const char * PR) //uncompressed
    {
        //PUBLIC_KEY= PR*G(x,y). we will use point doubling technique. algorithm called doubling and addition.
        string bin;
        int i=0;
        while(PR[i]!='\0'){
            bin=bin+hextobin[PR[i++]];
        }
        auto key= CALCULATE(bin,G);
        char * first=BN_bn2hex(key.first);
        char * second=BN_bn2hex(key.second);
        BN_free(key.first),BN_free(key.second);
        return {first,second};
    }
    std::pair<std::pair<char *,char*>,char*> challange(char*,char *);// this is send by the server to challange the client.
    char * response(const char *,const char*,const char *);
    char* find_next(const char * PUa)//y-cordinate is calculated.
    {
        string temp(PUa);
        char even=temp[1];
        temp=temp.substr(2);//remove the compressed prefix
        BIGNUM * x=BN_new();
        BN_hex2bn(&x,temp.c_str());
        BIGNUM * xcube=BN_new();
        BN_mod_exp(xcube,x,a,prime,ctx);
        x=BN_new();
        BN_add(x,xcube,b);
        BIGNUM * y=BN_new();
        BN_mod_sqrt(y,x,prime,ctx);
        bool stat=BN_is_odd(y);
        if((stat && even=='2') || (!stat && even =='3') ){
            BN_sub(y,prime,y);
        }
        temp=BN_bn2hex(y);
        BN_free(xcube),BN_free(x),BN_free(y);
       char * output=new char[temp.length()+1];
        strcpy(output,temp.c_str());
        return output;
    }
    //for signing what algorithm to use{s,r}
    std::pair<char*,char*> Signature_Generate(const char * PR,const char * hash,enum Signature_flag flag){
        if(flag==ECDSA) return sign_ECDSA(PR,hash);
        return sign_schnorr(PR,hash);
    }
    //based on signining what verification should be used
    bool verify_signature(const char *PUa, const char * PUb,const char *msg ,const char *s,const char * r,enum Signature_flag flag){
        bool result;
        if(flag==ECDSA) result=verify_signature_ECDSA(std::string(PUa),std::string(PUb),msg,s,r);
        else result=verify_signature_schnorr(std::string(PUa),std::string(PUb),msg,s,r);
        return result;
    }
    private:
    std::pair<BIGNUM*,BIGNUM*> CALCULATE(string& ,BIGNUM **);
    std::pair<BIGNUM*,BIGNUM*>Double(BIGNUM*,BIGNUM *);
    std::pair<BIGNUM *,BIGNUM*>Formula(BIGNUM*,BIGNUM*,BIGNUM**,BIGNUM*);
    std::pair<BIGNUM *, BIGNUM*>Addition(BIGNUM*,BIGNUM*,BIGNUM**);
    std::pair<char*,char*> sign_ECDSA(const char *,const char *);
    //Digital signature.
    std::pair<char*,char*> sign_schnorr(const char *, const char * );
    bool verify_signature_ECDSA(std::string,std::string,const char *,const char * ,const char *);
    bool verify_signature_schnorr(std::string,std::string,const char *,const char * ,const char *);


};
std::pair<std::pair<char *,char*>,char*> Elliptical_curve::challange(char *PUa,char * PUb){ //return the hint to client and save the value to server.
    //sends the hit KG. k is 128 bit to make it fast
    char * K=seed(128);
    //actually it behaves as the private key so same publickey algorithm can be used.
    auto hint= Public_key(K);
    //similarly server will compute K.PU to get x-cord which is the mathematical answer which should be solved with the private key.
    BIGNUM ** co=new BIGNUM*[2];
    co[0]=co[1]=nullptr;
    BN_hex2bn(&co[0],PUa); BN_hex2bn(&co[1],PUb);
    string bin;
    int i=0;
    while(K[i]!='\0'){
        bin=bin+hextobin[K[i++]];
    }
    auto temp=CALCULATE(bin,co);
   char * value=BN_bn2hex(temp.first);
   BN_free(temp.first),BN_free(temp.second);
    OPENSSL_free(K);
    BN_free(co[0]),BN_free(co[1]);
    return {hint,value};
}

char * Elliptical_curve::response(const char * PUa,const char* PUb,const char * PR){ 
    //PR*KG
    BIGNUM * co[2];
    co[0]=co[1]=nullptr;
    BN_hex2bn(&co[0],PUa);BN_hex2bn(&co[1],PUb);
    string bin;
    int i=0;
    while(PR[i]!='\0'){
        bin=bin+hextobin[PR[i++]];
    }
    auto temp=CALCULATE(bin,co);
   char * value=BN_bn2hex(temp.first);
   BN_free(temp.first),BN_free(temp.second);
   BN_free(co[0]),BN_free(co[1]);
   return value;
}

bool Elliptical_curve::verify_signature_schnorr(std::string PUa,std::string PUb,const char*msg,const char*y,const char * e)
{
    BIGNUM ** public_key=new BIGNUM*[2];
    public_key[0]=BN_new();public_key[1]=BN_new();
    BN_hex2bn(&public_key[0],PUa.c_str());
    BN_hex2bn(&public_key[1],PUb.c_str());
    string bin;
    int i=0;
    while(y[i]!='\0'){
        bin=bin+hextobin[y[i++]];
    }
    auto Y=CALCULATE(bin,G); //y.G
    bin.clear();

    //msg+e to get msg+e.
    std::string temp=e;
    temp=msg+temp;
    temp=keccak_Hash(256,SHA3_FLAGS_KECCAK,temp,32);//using keccak sha-3 for hashing.
     i=0;
    while(i < temp.length()){
        bin=bin+hextobin[temp[i++]];
    }
    auto R=CALCULATE(bin,public_key); //e.PU = e.PR.G
    BN_free(public_key[0]);BN_free(public_key[1]);
    public_key[0]=public_key[1]=nullptr;
    public_key[0]=R.first;
    public_key[1]=BN_new();
    BN_sub(public_key[1],prime,R.second);//formula y.G - e.PU
    BIGNUM * E=BN_new();
    BIGNUM*v=Addition(Y.first,Y.second,public_key).first;
    BN_mod(v,v,n,ctx);
   // std::cout<<BN_bn2hex(v)<<std::endl;
    
    BN_hex2bn(&E,e);
    bool result=BN_cmp(E,v)==0;
    BN_free(R.first);BN_free(R.second); BN_free(v);
    BN_free(E);BN_free(Y.first);BN_free(Y.second);
    return result;
}

std::pair<char*,char*>Elliptical_curve::sign_schnorr(const char * PR,const char * msg) //{y, e}
{
    char * k=seed(256); //random value generate. < n and there is very less change to be greater 0.01%.
    string bin;
    int i=0;
    while(k[i]!='\0'){
        bin=bin+hextobin[k[i++]];
    }
    BIGNUM* x_cord=CALCULATE(bin,G).first;
    BN_mod(x_cord,x_cord,n,ctx);
    char* r=BN_bn2hex(x_cord);
    string e=msg; //forming H(msg||r)
    e=e+(string)r;
    e=keccak_Hash(256,SHA3_FLAGS_KECCAK,e,32);//using keccak sha-3 for hashing.
    BN_free(x_cord);
    x_cord=nullptr;
    BN_hex2bn(&x_cord,k); 
    //y=k+pr.e
    BIGNUM * PR_e=BN_new();
    BN_hex2bn(&PR_e,e.c_str());
    BIGNUM * private_key=BN_new();
    BN_hex2bn(&private_key,PR);
    BN_mod_mul(PR_e,private_key,PR_e,n,ctx);
    
    BIGNUM * y=BN_new();
    BN_mod_add(y,x_cord,PR_e,n,ctx);
    char * Y=BN_bn2hex(y);
    BN_free(x_cord);BN_free(y);BN_free(PR_e);BN_free(private_key);
    OPENSSL_free(k);
    return {Y,r};
}

bool Elliptical_curve::verify_signature_ECDSA(std::string PUa,std::string PUb,const char * hash,const char * s,const char * r)
{
    BIGNUM * s_inv=BN_new();
    BN_hex2bn(&s_inv,s);
    s_inv=BN_mod_inverse(nullptr,s_inv,n,ctx);
    BIGNUM * u1=BN_new();
    BN_hex2bn(&u1,hash);
    BN_mod_mul(u1,u1,s_inv,n,ctx);
    BIGNUM * u2=BN_new();
    BN_hex2bn(&u2,r);
    BN_mod_mul(u2,u2,s_inv,n,ctx);

    BIGNUM ** public_key=new BIGNUM*[2];
    public_key[0]=BN_new();public_key[1]=BN_new();
    BN_hex2bn(&public_key[0],PUa.c_str());
    BN_hex2bn(&public_key[1],PUb.c_str());
    string bin;
    int i=0;
    char * PR1=BN_bn2hex(u1);
    while(PR1[i]!='\0'){
        bin=bin+hextobin[PR1[i++]];
    }
    auto UU1=CALCULATE(bin,G); 
    bin.clear();
    i=0;
    char *PR2=BN_bn2hex(u2);
     while(PR2[i]!='\0'){
        bin=bin+hextobin[PR2[i++]];
    }
    auto UU2=CALCULATE(bin,public_key);
    BN_free(public_key[0]);BN_free(public_key[1]);
    public_key[0]=UU2.first;
    public_key[1]=UU2.second;
    
    auto v=Addition(UU1.first,UU1.second,public_key).first;
    BN_mod(v,v,n,ctx);
    u1=BN_new();
    BN_hex2bn(&u1,r);
    //std::cout<<BN_bn2hex(v)<<std::endl;
    bool result=BN_cmp(v,u1)==0;
    BN_free(public_key[0]);BN_free(public_key[1]);
    BN_free(UU1.first);BN_free(UU1.second);
    BN_free(s_inv);BN_free(u1);BN_free(u2);BN_free(v);
    OPENSSL_free(PR1);OPENSSL_free(PR2);
    return result;
    
}

std::pair<char*,char*> Elliptical_curve::sign_ECDSA(const char * PR,const char * hash)
{
    char * k=seed(256); //random value generate. < n and there is very less change to be greater 0.01%.
    string bin;
    int i=0;
    while(k[i]!='\0'){
        bin=bin+hextobin[k[i++]];
    }
    BIGNUM* x_cord=CALCULATE(bin,G).first;
    BN_mod(x_cord,x_cord,n,ctx);
    
    
    BIGNUM * K=BN_new();
    BN_hex2bn(&K,k);
    BIGNUM * k_inv=BN_mod_inverse(nullptr,K,n,ctx);
    
    K=nullptr;
    BN_hex2bn(&K,PR);
    BIGNUM* mul_r_PR= BN_new();
    BN_mul(mul_r_PR,K,x_cord,ctx);
    
    k=nullptr;
    BN_hex2bn(&K,hash);
    BIGNUM * temp=BN_new();
    BN_add(temp,mul_r_PR,K);

    K=nullptr;
    K=BN_new(); //it will save s=k_inv(h + r*PR) mod n.
    BN_mod_mul(K,k_inv,temp,n,ctx);
    char * s=BN_bn2hex(K);
    char* r=BN_bn2hex(x_cord);
    OPENSSL_free(k);
    BN_free(K);BN_free(k_inv);BN_free(temp);BN_free(x_cord);
    return {s,r};
}

Elliptical_curve::Elliptical_curve():prime(nullptr),n(nullptr){ //setup for processing public information.
    ctx=BN_CTX_new();
    a=BN_new();b=BN_new();
    BN_set_word(a,3),BN_set_word(b,7); //actual a is 0 but for internal operation i use 3
    BN_hex2bn(&prime,"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
    BN_hex2bn(&n,"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    G= new BIGNUM*[2];
    G[0]=G[1]=nullptr;
    //base point.
    BN_hex2bn(&G[0],"79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"); //x-coordinate
    BN_hex2bn(&G[1],"483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");//y-coordinate

}

std::pair<BIGNUM*,BIGNUM*> Elliptical_curve::CALCULATE(string& bin,BIGNUM** co)
{
    int i=0; //using double and add algorithm
    while(bin[i]=='0')i++; //skip MSB's 0's and a 1.
    i++;
    std::pair<BIGNUM*,BIGNUM*>temp={co[0],co[1]};
    while(i < bin.length())
    {
        temp=Double(temp.first,temp.second);
        if(bin[i]=='1'){
            temp=Addition(temp.first,temp.second,co);
        }
        i++;
    }
    return temp;
}

std::pair<BIGNUM*,BIGNUM*>Elliptical_curve::Formula(BIGNUM*x1,BIGNUM* x2,BIGNUM**slope,BIGNUM*y1){
/*
        x.new=s^2-x1-x2 % p
        y.new=s(x1-x.new)-y1 %p
    */
   BIGNUM *s=BN_new();
   if(BN_mul(s,*slope,*slope,ctx)==0){
    std::cerr<<"Failed";
    exit(1);
   }
   BIGNUM * add=BN_new();
   if(BN_add(add,x1,x2)==0){
    std::cerr<<"failed";
    exit(1);
   }
   BIGNUM * newx=BN_new();
   if(BN_mod_sub(newx,s,add,prime,ctx)==0){
    std::cerr<<"Failed";
    exit(1);
   }
   BN_free(s);
   s=BN_new();
   if(BN_mod_sub(s,x1,newx,prime,ctx)==0){
    std::cerr<<"Failed";
    exit(1);
   }
   BIGNUM *t=BN_new();
   if(BN_mul(t,*slope,s,ctx)==0){
    std::cerr<<"failed";
    exit(1);
   }
   BIGNUM*newy=BN_new();
   if(BN_mod_sub(newy,t,y1,prime,ctx)==0){
    std::cerr<<"failed";
    exit(1);
   }
   BN_free(s);
   BN_free(add);
   BN_free(t);
   return{newx,newy};
}

std::pair<BIGNUM*,BIGNUM*>Elliptical_curve::Double(BIGNUM*x,BIGNUM*y){
    //slope of tangent. %prime.
    BIGNUM *num=BN_new();//3x^2+a/2*y mod p
    if(BN_mul(num,x,x,ctx)==0){
        std::cerr<<"Failed";
        exit(1);
    }
    if(BN_mul(num,a,num,ctx)==0){
        std::cerr<<"Failed";
        exit(1);
    }
    BIGNUM * den=BN_new();
    BN_set_word(den,2);
    if(BN_mul(den,den,y,ctx)==0){
        std::cerr<<"Failed";
        exit(1);
    }
    BIGNUM * inv=BN_new();
    if(BN_mod_inverse(inv,den,prime,ctx)==0){
        std::cerr<<"falied";
        exit(1);
    }
    BIGNUM * slope=BN_new();
    if(BN_mod_mul(slope,num,inv,prime,ctx)==0){
        std::cerr<<"failed";
        exit(1);
    }
    
    BN_free(num);
    BN_free(den);
    BN_free(inv);
    return Formula(x,x,&slope,y);
}

std::pair<BIGNUM*,BIGNUM*>Elliptical_curve::Addition(BIGNUM* x1,BIGNUM*y1,BIGNUM**co)
{
    //slope=y2-y1/x2-x1 mod p
    BIGNUM *Y=BN_new();
    if(BN_mod_sub(Y,co[1],y1,prime,ctx)==0){
        std::cerr<<"failed";
        exit(1);
    }
    BIGNUM *X=BN_new();
    if(BN_mod_sub(X,co[0],x1,prime,ctx)==0){
        std::cerr<<"failed";
        exit(1);
    }
    BIGNUM * inv=BN_new();
    if(BN_mod_inverse(inv,X,prime,ctx)==0){
        std::cerr<<"failed";
        exit(1);
    }
    BIGNUM* slope=BN_new();
    if(BN_mod_mul(slope,Y,inv,prime,ctx)==0){
        std::cerr<<"failed";
        exit(1);
    }
    BN_free(Y);
    BN_free(inv);
    BN_free(X);
    return Formula(x1,co[0],&slope,y1);
}



#endif