/* Copyright 2014, Heckendorf */

#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>
#include <termios.h>
#include <stdint.h>
#include <pwd.h>
#include "io/io_data.h"

#define EZMATCH(ret,temp,field) entry_matches(ret,temp->field,offsetof(struct pwitem,field))

static int str_contains(const char *e, const int e_len, const char *s, const int s_len){
	int i,j;

	for(i=0;i<=s_len-e_len;i++){
		while(i+1<=s_len-e_len && s[i]!=e[0])
			i++;
		for(j=0;j<e_len && s[i+j]==e[j];j++)
			;
		if(j==e_len)
			return i;
	}

	return -1;
}

int entry_matches(struct pwitem *a, char *s, size_t o){
	uint8_t *p=(uint8_t*)a;
	char *f;

	if(!s)
		return 0;

	p+=o;

	f=*(char**)p;

	if(!f)
		return 1;

	return str_contains(s,strlen(s),f,strlen(f))==-1;
}

struct pwitem* find_entry(struct yamlpwdata *data, struct pwitem *item){
	struct pwitem *ret=data->data.items;
	int found=0;

	while(ret){
		found=0;
		found+=EZMATCH(ret,item,name);
		found+=EZMATCH(ret,item,location);
		found+=EZMATCH(ret,item,user);
		if(found==0)
			return ret;

		ret=ret->next;
	}

	return NULL;
}

char *getpassword(const char *prompt){
	const int maxlen=128;
	char *ret=malloc(maxlen);
	int i;
	struct termios orig,noecho;

	if(!ret)
		exit(1);

	tcgetattr(0,&orig);
	tcgetattr(0,&noecho);
	noecho.c_lflag&=(~ECHO);
	tcsetattr(0,TCSANOW,&noecho);

	printf("%s",prompt);
	if(!fgets(ret,maxlen,stdin)){
		fprintf(stderr,"Password read error\n");
		free(ret);
		tcsetattr(0,TCSANOW,&orig);
		exit(1);
	}

	for(i=0;i<maxlen-1 && ret[i] && ret[i]!='\n';i++);
	ret[i]=0;

	tcsetattr(0,TCSANOW,&orig);
	putchar('\n');

	return ret;
}

void add_password(struct yamlpwdata *data, struct pwitem *item){
	char *pw;
	char *rpw=NULL;
	char *mpw=NULL;

	if(item->pass==NULL){
		pw=getpassword("Remote password: ");
		rpw=item->pass=pw;
		//rpw=item->pass=strdup(pw);
		//while(*pw)*(pw++)=0;
	}

	mpw=pw=getpassword("Master password: ");

	append_data_item(data,item,pw);
	while(*pw)*(pw++)=0;

	if(rpw)
		free(rpw);
	free(mpw);

	write_data(data);
}

char* return_password(struct yamlpwdata *data, struct pwitem **item){
	char *tpw,*pw;
	char *ret;

	if((*item=find_entry(data,*item))==NULL){
		fprintf(stderr,"No entry found.\n");
		cleanup_data(data);
		return NULL;
	}

	tpw=pw=getpassword("Master password: ");

	ret=(char*)get_password(*item,pw);

	while(*pw)*(pw++)=0;
	free(tpw);

	return ret;
}

void print_password(struct yamlpwdata *data, struct pwitem *item, int print_user){
	char *pw=return_password(data,&item);

	if(print_user)
		printf("%s:%s\n",item->user,pw);
	else
		printf("%s\n",pw);

	while(*pw)*(pw++)=0;

	cleanup_data(data);
}

#ifdef USE_X11
#include "xsel.h"

void copy_password(struct yamlpwdata *data, struct pwitem *item){
	char *pw=return_password(data,&item);

	printf("Copying password to primary X clipboard.\n");

	xsel_init();
	set_x11_selection((unsigned char *)pw);

	while(*pw)*(pw++)=0;

	cleanup_data(data);
}
#endif

void print_entries(struct yamlpwdata *data){
	struct pwitem *e;

	printf("%s\t%s\n",  "Name","Location");
	printf("%s\t%s\n\n","----","--------");

	for(e=data->data.items;e;e=e->next){
		printf("%s\t%s\n",e->name,e->location);
	}

	cleanup_data(data);
}

void print_info(struct yamlpwdata *data, struct pwitem *item){
	if((item=find_entry(data,item))==NULL){
		fprintf(stderr,"No entry found.\n");
		cleanup_data(data);
		return;
	}

	printf("Name:    \t%s\nLocation:\t%s\nUsername:\t%s\n",item->name,item->location,item->user);

	cleanup_data(data);
}

int init_pwdata(struct yamlpwdata *data, char *fname){
	FILE *infd,*outfd;
	int newfile=0;

	umask(0077);

	infd=fopen(fname,"r");
	if(infd)
		outfd=fopen(fname,"r+");
	else{
		outfd=fopen(fname,"w");
		newfile=1;
	}

	memset(&data->data,0,sizeof(data->data));

	init_data(data,infd,outfd);

	return newfile;
}

void close_pwdata(int del, char *fname){
	if(del){
		if(unlink(fname))
			fprintf(stderr,"Failed to unlink.\n");
	}
}
