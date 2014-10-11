/* Copyright 2014, Heckendorf */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "config.h"
#include "common_defs.h"
#include "io/io_common.h"
#include "io/io_config.h"

void load_config(struct yamlconfig *conf){
	memset(conf,0,sizeof(*conf));

	read_conf(conf,SHARE_PATH CONF_FILE);
	read_conf(conf,CUSTOM_PATH CONF_FILE);
}
