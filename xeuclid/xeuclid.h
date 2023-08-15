#include <stdio.h>
#include <openssl/bn.h>
/*
OpenSSL에 내장된 gcd, extended euclidean 함수 등을 사용하지 말고
BN_add, BN_div, BN_mod 등의 하위 함수들만을 사용하여 작성하시오.

평가 기준
1. 임의의 입력에 대해 오류 없이 맞는 출력값을 출력하는가.
2. 실행 성능
3. 코드가 군더더기 없이 잘 작성되었는가.

입력 : a, b
출력 : gcd  &  정수들 x, y satisfying a*x+b*y=gcd

주의사항 : 다음과 같이 openssl 하위 디렉토리에서 바로 컴파일 하여 실행될 수 있도록 xeuclid.c 를 제출하시오.

$gcc xeuclid.c -L.. -lcrypto  -I../include/crypto -o xeuclid
$./xeuclid 123123123111 1293109238019381121

*/

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