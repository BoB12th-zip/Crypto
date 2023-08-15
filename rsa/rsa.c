#include <stdio.h>
#include <openssl/bn.h>
#include <string.h>

typedef struct _b12rsa_st
{
    BIGNUM *e;
    BIGNUM *d;
    BIGNUM *n;
} BOB12_RSA;

// assignment #1
BIGNUM *XEuclid(BIGNUM *x, BIGNUM *y, const BIGNUM *a, const BIGNUM *b)
{
    BIGNUM *gcd = BN_new();
    BIGNUM *x1 = BN_new();
    BIGNUM *y1 = BN_new();
    BIGNUM *q = BN_new();
    BIGNUM *r = BN_new();
    BIGNUM *temp = BN_new();

    if (BN_is_zero(b))
    {
        BN_one(x);
        BN_zero(y);
        BN_copy(gcd, a);
    }
    else
    {
        BN_div(q, r, a, b, BN_CTX_new());

        BIGNUM *recursive_gcd = XEuclid(x1, y1, b, r);

        BN_copy(x, y1);
        BN_mul(temp, q, y1, BN_CTX_new());
        BN_sub(y, x1, temp);

        BN_copy(gcd, recursive_gcd);
    }

    BN_free(temp);
    BN_free(x1);
    BN_free(y1);
    BN_free(q);
    BN_free(r);

    return gcd;
}

// assignment #2
int myExpMod(BIGNUM *r, const BIGNUM *a, const BIGNUM *e, BIGNUM *m)
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

    while (!BN_is_zero(temp_e))
    {
        // If temp_e is odd, multiply r with a and take the modulo m
        if (BN_is_odd(temp_e))
        {
            if (!BN_mod_mul(r, r, temp_a, m, BN_CTX_new()))
            {
                BN_free(one);
                BN_free(temp_a);
                BN_free(temp_e);
                return 0;
            }
        }

        // Square a and take the modulo m
        if (!BN_mod_mul(temp_a, temp_a, temp_a, m, BN_CTX_new()))
        {
            BN_free(one);
            BN_free(temp_a);
            BN_free(temp_e);
            return 0;
        }

        // Right-shift temp_e by 1 (equivalent to integer division by 2)
        if (!BN_rshift1(temp_e, temp_e))
        {
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

// RSA 구조체를 생성하여 포인터를 리턴하는 함수
BOB12_RSA *BOB12_RSA_new()
{
    BOB12_RSA *rsa = (BOB12_RSA *)malloc(sizeof(BOB12_RSA));

    rsa->e = BN_new();
    rsa->d = BN_new();
    rsa->n = BN_new();
    return rsa;
}

// RSA 구조체 포인터를 해제하는 함수
int BOB12_RSA_free(BOB12_RSA *b12rsa)
{
    BN_free(b12rsa->e);
    BN_free(b12rsa->d);
    BN_free(b12rsa->n);

    free(b12rsa);

    return 0;
}

// RSA 키 생성 함수
// 입력 : nBits (RSA modulus bit size)
// 출력 : b12rsa (구조체에 n, e, d 가  생성돼 있어야 함)
// p=C485F491D12EA7E6FEB95794E9FE0A819168AAC9D545C9E2AE0C561622F265FEB965754C875E049B19F3F945F2574D57FA6A2FC0A0B99A2328F107DD16ADA2A7
// q=F9A91C5F20FBBCCC4114FEBABFE9D6806A52AECDF5C9BAC9E72A07B0AE162B4540C62C52DF8A8181ABCC1A9E982DEB84DE500B27E902CD8FDED6B545C067CE4F
int BOB12_RSA_KeyGen(BOB12_RSA *b12rsa, int nBits)
{
    // Given p and q in hexadecimal form
    const char *p_hex = "C485F491D12EA7E6FEB95794E9FE0A819168AAC9D545C9E2AE0C561622F265FEB965754C875E049B19F3F945F2574D57FA6A2FC0A0B99A2328F107DD16ADA2A7";
    const char *q_hex = "F9A91C5F20FBBCCC4114FEBABFE9D6806A52AECDF5C9BAC9E72A07B0AE162B4540C62C52DF8A8181ABCC1A9E982DEB84DE500B27E902CD8FDED6B545C067CE4F";

    // Convert p and q from hexadecimal to BIGNUM format
    BIGNUM *p = BN_new();
    BIGNUM *q = BN_new();
    BN_hex2bn(&p, p_hex);
    BN_hex2bn(&q, q_hex);

    // Calculate n = p * q
    BN_mul(b12rsa->n, p, q, BN_CTX_new());

    // Set e to a common value (65537)
    BN_set_word(b12rsa->e, 65537);

    // Calculate phi(n) = (p - 1) * (q - 1)
    BIGNUM *phi_n = BN_new();
    BIGNUM *p_minus_1 = BN_new();
    BIGNUM *q_minus_1 = BN_new();
    BN_sub(p_minus_1, p, BN_value_one());
    BN_sub(q_minus_1, q, BN_value_one());
    BN_mul(phi_n, p_minus_1, q_minus_1, BN_CTX_new());

    // Calculate d = e^(-1) mod phi(n)
    BN_mod_inverse(b12rsa->d, b12rsa->e, phi_n, BN_CTX_new());

    // Free temporary BIGNUMs
    BN_free(p);
    BN_free(q);
    BN_free(phi_n);
    BN_free(p_minus_1);
    BN_free(q_minus_1);

    return 1;
}

// RSA 암호화 함수
// 입력 : 공개키를 포함한 b12rsa, 메시지 m
// 출력 : 암호문 c
int BOB12_RSA_Enc(BIGNUM *c, BIGNUM *m, BOB12_RSA *b12rsa)
{
    myExpMod(c, m, b12rsa->e, b12rsa->n);
    // BN_mod_exp(c, m, b12rsa->e,
    //            b12rsa->n, BN_CTX_new());
    return 1;
}

// RSA 복호화 함수
// 입력 : 공개키를 포함한 b12rsa, 암호문 c
// 출력 : 평문 m
int BOB12_RSA_Dec(BIGNUM *m, BIGNUM *c, BOB12_RSA *b12rsa)
{
    myExpMod(m, c, b12rsa->d, b12rsa->n);
    // BN_mod_exp(m, c, b12rsa->d,
    //            b12rsa->n, BN_CTX_new());
    return 1;
}
void PrintUsage()
{
    printf("usage: rsa [-k|-e e n plaintext|-d d n ciphertext]\n");
}

int main(int argc, char *argv[])
{
    BOB12_RSA *b12rsa = BOB12_RSA_new();
    BIGNUM *in = BN_new();
    BIGNUM *out = BN_new();

    if (argc == 2)
    {
        if (strncmp(argv[1], "-k", 2))
        {
            PrintUsage();
            return -1;
        }
        BOB12_RSA_KeyGen(b12rsa, 1024);
        printf("n : ");
        BN_print_fp(stdout, b12rsa->n);
        printf("\n");
        printf("e : ");
        BN_print_fp(stdout, b12rsa->e);
        printf("\n");
        printf("d : ");
        BN_print_fp(stdout, b12rsa->d);
        printf("\n");
    }
    else if (argc == 5)
    {
        if (strncmp(argv[1], "-e", 2) && strncmp(argv[1], "-d", 2))
        {
            PrintUsage();
            return -1;
        }
        BN_hex2bn(&b12rsa->n, argv[3]);
        BN_hex2bn(&in, argv[4]);
        if (!strncmp(argv[1], "-e", 2))
        {
            BN_hex2bn(&b12rsa->e, argv[2]);
            printf("enc : ");
            BOB12_RSA_Enc(out, in, b12rsa);
        }
        else if (!strncmp(argv[1], "-d", 2))
        {
            BN_hex2bn(&b12rsa->d, argv[2]);
            printf("dec : ");
            BOB12_RSA_Dec(out, in, b12rsa);
        }
        else
        {
            PrintUsage();
            return -1;
        }
        BN_print_fp(stdout, out);
        printf("\n");
    }
    else
    {
        PrintUsage();
        return -1;
    }

    if (in != NULL)
        BN_free(in);
    if (out != NULL)
        BN_free(out);
    if (b12rsa != NULL)
        BOB12_RSA_free(b12rsa);

    return 0;
}