#ifndef IO_DATA_H
#define IO_DATA_H

#include "io_common.h"

#define ENC_FUNCTION EVP_aes_256_cbc()
#define ENC_BLOCK_SIZE 16
#define ENC_IV_SIZE 16
#define ENC_KEY_SIZE 32

unsigned char* get_password(struct pwitem *item,const char *pw);
void set_password(struct pwitem *item,const char *pw);
void init_data(struct yamlpwdata *data, FILE *infd, FILE *outfd);
void append_data_item(struct yamlpwdata *data, struct pwitem *item, char *pw);
void write_data(struct yamlpwdata *data);
void cleanup_data(struct yamlpwdata *data);

#endif
