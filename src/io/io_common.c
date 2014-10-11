/* Copyright 2014, Heckendorf */

#include <yamldom.h>

char* inttostr(char *buf, int x){
	sprintf(buf,"%d",x);
	return buf;
}

char* dbltostr(char *buf,double x){
	sprintf(buf,"%f",x);
	return buf;
}

yamldom_node_t* intseq(int *arr, int num, char *buffer){
	yamldom_node_t *seq, *nodes,*tmp;
	int i;

	seq=yamldom_make_seq(NULL);
	nodes=NULL;

	for(i=0;i<num;i++){
		tmp=yamldom_make_scalar(NULL,inttostr(buffer,arr[i]),-1);
		nodes=yamldom_append_node(nodes,tmp);
	}

	YAMLDOM_SEQ_NODES(seq)=nodes;

	return seq;
}
