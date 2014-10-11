#ifndef DATA_H
#define DATA_H

#include "io/io_common.h"

void add_password(struct yamlpwdata *data, struct pwitem *item);
void print_password(struct yamlpwdata *data, struct pwitem *item, int print_user);
void copy_password(struct yamlpwdata *data, struct pwitem *item);
void print_entries(struct yamlpwdata *data);
void print_info(struct yamlpwdata *data, struct pwitem *item);
int init_pwdata(struct yamlpwdata *data, char *fname);
void close_pwdata(int del, char *fname);

#endif
