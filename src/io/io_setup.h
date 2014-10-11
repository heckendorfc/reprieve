#ifndef SETUP_H
#define SETUP_H

#include <yamldom.h>
#include "io_common.h"

int io_general_init(yamldom_data_t *ydd);
int io_general_close(yamldom_data_t *ydd);

#endif
