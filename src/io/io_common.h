#ifndef IO_COMMON_H
#define IO_COMMON_H

#include <yamldom.h>

struct pwitem{
	struct pwitem *next;
	char *name;
	char *location;
	char *user;
	char *pass;
	char *iv;
	char *oath;
	char *oathiv;
};

struct pwdata{
	struct pwitem *items;
};

struct config{
};

struct yamldata{
	yamldom_data_t ydd;
	yamldom_node_t *root;
	yamldom_anchor_list_t *anchors;
};

struct yamlpwdata{
	struct yamldata yaml;
	struct pwdata data;
	int valid;
};

struct yamlconfig{
	struct yamldata yaml;
	struct config conf;
};

char* inttostr(char *buf, int x);
char* dbltostr(char *buf,double x);
yamldom_node_t* intseq(int *arr, int num, char *buffer);

#endif
