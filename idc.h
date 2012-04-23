#ifndef IDC_H
#define IDC_H

#include "image.h"

#include <openssl/pkcs7.h>

int IDC_set(PKCS7 *p7, PKCS7_SIGNER_INFO *si, struct image *image);

#endif /* IDC_H */

