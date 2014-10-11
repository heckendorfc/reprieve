#ifndef IO_CONFIG_H
#define IO_CONFIG_H

#include "io_common.h"

void parse_graph(struct yamlconfig *conf);
void read_conf(struct yamlconfig *conf, const char *path);

#endif
