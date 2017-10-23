#ifndef OATH_TOKEN_H
#define OATH_TOKEN_H

#include <stdint.h>
#include <time.h>

int oath_totp_generate(const char *secret, const int len, const uint32_t interval, unsigned int digits, char *ret);

#endif
