#include "rsa.h"


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