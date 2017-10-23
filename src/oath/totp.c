#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "hmac.h"
#include "base32.h"

uint32_t code_trunc(uint8_t *md, size_t dlen, int digits){
	int i;
	uint32_t base = 1;
	uint32_t off = md[dlen-1]&0xf;
	uint32_t t;

	for(i=0;i<digits;i++)
		base *= 10;

	t = (md[off+0]&0x7f) << 24;
	t |= (md[off+1]) << 16;
	t |= (md[off+2]) << 8;
	t |= (md[off+3]);

	return t % base;
}

int otp(uint8_t *key, int keylen, unsigned int digits, uint64_t counter, uint32_t *code)
{
	uint8_t *md;
	size_t dlen;

#ifdef __LITTLE_ENDIAN__
	counter = (((uint64_t)htonl(counter))<<32) + htonl(counter>>32);
#endif

	if (hmac(key,keylen,&counter,sizeof(counter),&md,&dlen))
		return 1;

	*code = code_trunc(md,dlen,digits);

	free(md);

	return 0;
}

int oath_totp_generate(const char *secret, const int len, const uint32_t interval, unsigned int digits, char *ret){
	char fmt[14];
	time_t now;
	uint32_t num;
	int decseclen = (len*5/8)+2;
	uint8_t *decsec;

	if (interval==0 || (now=time(NULL))==(time_t)-1)
		return 1;

	now /= interval;

	if((decsec=malloc(decseclen))==NULL)
		return 1;

	decseclen = base32_decode((const char*)secret,decsec,decseclen);

	snprintf(fmt, sizeof(fmt), "%%0%ud", digits);

	if (otp(decsec,decseclen,digits,now,&num))
		return 1;

	snprintf(ret, digits+1, fmt, num);

	free(decsec);

	return 0;
}
