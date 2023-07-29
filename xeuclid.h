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