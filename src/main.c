/* Copyright 2014, Heckendorf */

#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include "config.h"
#include "data.h"

void usage(char *name){
	char *extra="";

#ifdef USE_X11
	extra=", xpw, cbpw";
#endif

	printf("%s {list, info, add, rm, pw, upw, addoath, oath%s} [-n name] [-l location] [-u username] [-p password]\n",name,extra);
}

int main(int argc, char **argv){
	struct config conf;
	struct yamlpwdata data;
	struct pwitem item;
	int ch;
	int newfile;
	int changed;
	char filename[256];
	char *p;

	if(argc<2){
		usage(argv[0]);
		return 1;
	}

	p=getenv("HOME");
	sprintf(filename,"%s/.reprievedb",p);

	memset(&item,0,sizeof(item));

	//load_config(&conf);
	newfile=init_pwdata(&data,filename);

	while((ch=getopt(argc-1,argv+1,"n:l:u:p:"))!=-1){
		switch(ch){
			case 'n':
				item.name=optarg;
				break;
			case 'l':
				item.location=optarg;
				break;
			case 'u':
				item.user=optarg;
				break;
			case 'p':
				item.pass=optarg;
				break;
		}
	}

	changed=0;
	if(strcmp(argv[1],"list")==0)
		print_entries(&data);
	else if(strcmp(argv[1],"info")==0)
		print_info(&data,&item);
	else if(strcmp(argv[1],"addoath")==0){
		changed=1;
		add_oath(&data,&item);
	}
	else if(strcmp(argv[1],"add")==0){
		changed=1;
		add_password(&data,&item);
	}
	else if(strcmp(argv[1],"rm")==0)
		changed=1;
	else if(strcmp(argv[1],"pw")==0)
		generic_use_password(&data,&item,0,print_password);
	else if(strcmp(argv[1],"upw")==0)
		generic_use_password(&data,&item,1,print_password);
	else if(strcmp(argv[1],"oath")==0)
		print_oath_token(&data,&item,NULL);
#ifdef USE_X11
	else if(strcmp(argv[1],"xpw")==0)
		generic_use_password(&data,&item,0,copy_password);
	else if(strcmp(argv[1],"cbpw")==0)
		generic_use_password(&data,&item,1,copy_password);
#endif
	else
		usage(argv[0]);

	close_pwdata(newfile && !changed, filename);

	return 0;
}
