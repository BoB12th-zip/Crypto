#include "xeuclid.h"



int main(int argc, char *argv[])
{
    BIGNUM *a = BN_new();
    BIGNUM *b = BN_new();
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    BIGNUM *gcd;

    if (argc != 3)
    {
        printf("usage: xeuclid num1 num2");
        return -1;
    }
    BN_dec2bn(&a, argv[1]);
    BN_dec2bn(&b, argv[2]);
    gcd = XEuclid(x, y, a, b);

    printBN("(a,b) = ", gcd);
    printBN("a = ", a);
    printBN("b = ", b);
    printBN("x = ", x);
    printBN("y = ", y);
    printf("%s*(%s) + %s*(%s) = %s\n", BN_bn2dec(a), BN_bn2dec(x), BN_bn2dec(b), BN_bn2dec(y), BN_bn2dec(gcd));

    if (a != NULL)
        BN_free(a);
    if (b != NULL)
        BN_free(b);
    if (x != NULL)
        BN_free(x);
    if (y != NULL)
        BN_free(y);
    if (gcd != NULL)
        BN_free(gcd);

    return 0;
}