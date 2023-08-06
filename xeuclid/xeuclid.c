#include "xeuclid.h"
BIGNUM *XEuclid(BIGNUM *x, BIGNUM *y, const BIGNUM *a, const BIGNUM *b)
{
    BIGNUM *zero = BN_new();
    BIGNUM *one = BN_new();
    BIGNUM *temp1 = BN_new();
    BIGNUM *temp2 = BN_new();
    BIGNUM *quotient = BN_new();
    BIGNUM *remainder = BN_new();

    BN_zero(zero);
    BN_one(one);

    BN_copy(x, zero);
    BN_copy(y, one);

    BIGNUM *aa = BN_dup(a);
    BIGNUM *bb = BN_dup(b);

    while (!BN_is_zero(bb))
    {
        BN_div(quotient, remainder, aa, bb, BN_CTX_new());
        BN_copy(aa, bb);
        BN_copy(bb, remainder);

        BN_copy(temp1, x);
        BN_copy(x, y);

        BN_mul(temp2, quotient, y, BN_CTX_new());
        BN_sub(y, temp1, temp2);
    }

    BN_free(zero);
    BN_free(one);
    BN_free(bb);
    BN_free(temp1);
    BN_free(temp2);
    BN_free(quotient);
    BN_free(remainder);

    return aa;
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