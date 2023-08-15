#include <stdio.h>
#include <openssl/bn.h>
typedef struct _b12rsa_st {
    BIGNUM *e;
    BIGNUM *d;
    BIGNUM *n;
}BOB12_RSA;

// RSA 구조체를 생성하여 포인터를 리턴하는 함수
BOB12_RSA *BOB12_RSA_new();

// RSA 구조체 포인터를 해제하는 함수
int BOB12_RSA_free(BOB12_RSA *b12rsa);

// RSA 키 생성 함수
// 입력 : nBits (RSA modulus bit size)
// 출력 : b12rsa (구조체에 n, e, d 가  생성돼 있어야 함)
// p=C485F491D12EA7E6FEB95794E9FE0A819168AAC9D545C9E2AE0C561622F265FEB965754C875E049B19F3F945F2574D57FA6A2FC0A0B99A2328F107DD16ADA2A7
// q=F9A91C5F20FBBCCC4114FEBABFE9D6806A52AECDF5C9BAC9E72A07B0AE162B4540C62C52DF8A8181ABCC1A9E982DEB84DE500B27E902CD8FDED6B545C067CE4F
int BOB12_RSA_KeyGen(BOB12_RSA *b12rsa, int nBits);

// RSA 암호화 함수
// 입력 : 공개키를 포함한 b12rsa, 메시지 m
// 출력 : 암호문 c
int BOB12_RSA_Enc(BIGNUM *c, BIGNUM *m, BOB12_RSA *b12rsa);

// RSA 복호화 함수
//입력 : 공개키를 포함한 b12rsa, 암호문 c
//출력 : 평문 m
int BOB12_RSA_Dec(BIGNUM *m,BIGNUM *c, BOB12_RSA *b12rsa);

void PrintUsage()
{
    printf("usage: rsa [-k|-e e n plaintext|-d d n ciphertext]\n");
}

int main (int argc, char *argv[])
{
    BOB12_RSA *b12rsa = BOB12_RSA_new();
    BIGNUM *in = BN_new();
    BIGNUM *out = BN_new();

    if(argc == 2){
        if(strncmp(argv[1],"-k",2)){
            PrintUsage();
            return -1;
        }
        BOB12_RSA_KeyGen(b12rsa,1024);
        BN_print_fp(stdout,b12rsa->n);
        printf(" ");
        BN_print_fp(stdout,b12rsa->e);
        printf(" ");
        BN_print_fp(stdout,b12rsa->d);
    }else if(argc == 5){
        if(strncmp(argv[1],"-e",2) && strncmp(argv[1],"-d",2)){
            PrintUsage();
            return -1;
        }
        BN_hex2bn(&b12rsa->n, argv[3]);
        BN_hex2bn(&in, argv[4]);
        if(!strncmp(argv[1],"-e",2)){
            BN_hex2bn(&b12rsa->e, argv[2]);
            BOB12_RSA_Enc(out,in, b12rsa);
        }else if(!strncmp(argv[1],"-d",2)){
            BN_hex2bn(&b12rsa->d, argv[2]);
            BOB12_RSA_Dec(out,in, b12rsa);
        }else{
            PrintUsage();
            return -1;
        }
        BN_print_fp(stdout,out);
    }else{
        PrintUsage();
        return -1;
    }

    if(in != NULL) BN_free(in);
    if(out != NULL) BN_free(out);
    if(b12rsa!= NULL) BOB12_RSA_free(b12rsa);

    return 0;
}