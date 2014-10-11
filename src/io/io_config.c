/* Copyright 2014, Heckendorf */

#include <stdio.h>
#include <yamldom.h>
#include "io_setup.h"
#include "io_common.h"

void parse_graph(struct yamlconfig *conf){
	yamldom_node_t *nodes,*tmp;
	char buffer[100];

	nodes=NULL;
}

static void dump_graph(struct yamlconfig *data){
	yamldom_dump(&data->yaml.ydd,data->yaml.root);
}

void write_conf(struct yamlconfig *data, FILE *infd, FILE *outfd){
	data->yaml.ydd.infd=infd;
	data->yaml.ydd.outfd=outfd;

	io_general_init(&data->yaml.ydd);

	data->yaml.anchors=NULL;
	data->yaml.root=yamldom_gen(&data->yaml.ydd,NULL); // Second argument is optional (anchors).

	//edit_graph(data);
	dump_graph(data);

	io_general_close(&data->yaml.ydd);

	yamldom_free_nodes(data->yaml.root);
	yamldom_free_anchors(data->yaml.anchors);
}

void read_conf(struct yamlconfig *conf, const char *path){
	FILE *infd,*outfd;

	infd=fopen(path,"r");
	outfd=NULL;

	if(!infd)
		return;

	conf->yaml.ydd.infd=infd;
	conf->yaml.ydd.outfd=outfd;

	io_general_init(&conf->yaml.ydd);

	conf->yaml.anchors=NULL;
	conf->yaml.root=yamldom_gen(&conf->yaml.ydd,NULL); // Second argument is optional (anchors).

	parse_graph(conf);

	io_general_close(&conf->yaml.ydd);
	fclose(infd);

	yamldom_free_nodes(conf->yaml.root);
	yamldom_free_anchors(conf->yaml.anchors);
}

