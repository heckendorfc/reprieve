#ifndef DATA_H
#define DATA_H

#include "io/io_common.h"

void add_password(struct yamlpwdata *data, struct pwitem *item);
void add_oath(struct yamlpwdata *data, struct pwitem *item);
void print_oath_token(struct yamlpwdata *data, struct pwitem *item, char *mpw);
void print_password(struct pwitem *item, char *pw, int print_user);
void copy_password(struct pwitem *item, char *pw, int selcb);
void generic_use_password(struct yamlpwdata *data, struct pwitem *item, int flag, void(*cb)(struct pwitem*,char*,int));
void print_entries(struct yamlpwdata *data);
void print_info(struct yamlpwdata *data, struct pwitem *item);
int init_pwdata(struct yamlpwdata *data, char *fname);
void close_pwdata(int del, char *fname);

#endif
