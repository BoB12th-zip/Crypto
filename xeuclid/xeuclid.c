#include "xeuclid.h"

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

void printBN(const char *msg, const BIGNUM *a)
{
    char *number_str = BN_bn2dec(a);
    printf("%s%s\n", msg, number_str);
    OPENSSL_free(number_str);
}

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