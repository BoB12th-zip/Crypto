/*
작성할 함수 프로토타입: 

int ExpMod(BIGNUM *r, const BIGNUM *a, const BIGNUM *e, BIGNUM *m)

입력 : a, e, m
출력 : r = a**e mod m (a를 e승 (mod m)한 결과)


다음과 같이 테스트 main 함수를 포함시켜 오류 없이 실행되도록 작성하시오.
*/
#include <stdio.h>
#include <openssl/bn.h>



void printBN(char *msg, BIGNUM * a)
{
        char * number_str = BN_bn2dec(a);
        printf("%s %s\n", msg, number_str);
        OPENSSL_free(number_str);
}

int ExpMod(BIGNUM *r, const BIGNUM *a, const BIGNUM *e, BIGNUM *m)
{
    BIGNUM *one = BN_new();
    BN_one(one);

    // Initialize the result r to 1
    BN_copy(r, one);

    BIGNUM *temp_a = BN_new();
    BN_copy(temp_a, a);

    // Create a non-const temporary BIGNUM to hold the value of e
    BIGNUM *temp_e = BN_new();
    BN_copy(temp_e, e);

    while (!BN_is_zero(temp_e)) {
        // If temp_e is odd, multiply r with a and take the modulo m
        if (BN_is_odd(temp_e)) {
            if (!BN_mod_mul(r, r, temp_a, m, BN_CTX_new())) {
                BN_free(one);
                BN_free(temp_a);
                BN_free(temp_e);
                return 0;
            }
        }

        // Square a and take the modulo m
        if (!BN_mod_mul(temp_a, temp_a, temp_a, m, BN_CTX_new())) {
            BN_free(one);
            BN_free(temp_a);
            BN_free(temp_e);
            return 0;
        }

        // Right-shift temp_e by 1 (equivalent to integer division by 2)
        if (!BN_rshift1(temp_e, temp_e)) {
            BN_free(one);
            BN_free(temp_a);
            BN_free(temp_e);
            return 0;
        }
    }

    // Free the temporary BIGNUMs
    BN_free(one);
    BN_free(temp_a);
    BN_free(temp_e);
    return 1;
}

int main (int argc, char *argv[])
{
        BIGNUM *a = BN_new();
        BIGNUM *e = BN_new();
        BIGNUM *m = BN_new();
        BIGNUM *res = BN_new();

        if(argc != 4){
                printf("usage: exp base exponent modulus\n");
                printf("%d\n",argc);
                return -1;
        }

        BN_dec2bn(&a, argv[1]);
        BN_dec2bn(&e, argv[2]);
        BN_dec2bn(&m, argv[3]);
        printBN("a = ", a);
        printBN("e = ", e);
        printBN("m = ", m);

        ExpMod(res,a,e,m);

        printBN("a**e mod m = ", res);

        if(a != NULL) BN_free(a);
        if(e != NULL) BN_free(e);
        if(m != NULL) BN_free(m);
        if(res != NULL) BN_free(res);

        return 0;
}
