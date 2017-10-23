/* Copyright 2017, Heckendorf */

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
#include "oath/totp.h"

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
	char *pw2;
	char *rpw=NULL;
	char *mpw=NULL;

	if(item->pass==NULL){
		pw=getpassword("Remote password: ");
		rpw=item->pass=pw;
		//rpw=item->pass=strdup(pw);
		//while(*pw)*(pw++)=0;
	}

	mpw=pw=getpassword("Master password: ");
	pw2=getpassword("Confirm password: ");

	if(strcmp(pw,pw2)){
		fprintf(stderr,"Passwords do not match.\n");
		while(*pw)*(pw++)=0;
		pw=pw2;
		while(*pw)*(pw++)=0;
		free(pw2);
		free(mpw);
		return;
	}

	append_data_item(data,item,pw);
	while(*pw)*(pw++)=0;

	if(rpw){
		pw=rpw;
		while(*pw)*(pw++)=0;
		free(rpw);
	}
	free(mpw);

	write_data(data);
}

char* return_password(struct yamlpwdata *data, struct pwitem **item, char **master){
	char *tpw,*pw = NULL;
	char *ret;
	int len;

	if((*item=find_entry(data,*item))==NULL){
		fprintf(stderr,"No entry found.\n");
		cleanup_data(data);
		return NULL;
	}

	if(master)
		pw = *master;

	if(pw == NULL)
		*master=tpw=pw=getpassword("Master password: ");

	ret=(char*)get_password(*item,pw,&len);

	if(master == NULL){
		while(*pw)*(pw++)=0;
		free(tpw);
	}

	return ret;
}

char* return_master_password(struct yamlpwdata *data, struct pwitem **item){
	char *tpw,*pw;
	char *ret;
	int len;

	if((*item=find_entry(data,*item))==NULL){
		fprintf(stderr,"No entry found.\n");
		cleanup_data(data);
		return NULL;
	}

	ret=getpassword("Master password: ");

	tpw=pw=(char*)get_password(*item,ret,&len);
	if(pw==NULL)
		return NULL;

	while(*pw)*(pw++)=0;
	free(tpw);

	return ret;
}

void add_oath(struct yamlpwdata *data, struct pwitem *item){
	struct pwitem *dbitem;
	char *code;
	char *pw=NULL;
	char *tpw, *tmp;

	dbitem = item;
	tmp=tpw=return_password(data,&dbitem,&pw);
	while(*tmp)*(tmp++)=0;
	free(tpw);

	if(pw==NULL)
		return;

	if(item->pass==NULL){
		item->pass=getpassword("OATH Code: ");
	}
	item->oath = item->pass;

	add_oath_item(data,item,pw);

	pw=item->pass;
	while(*pw)*(pw++)=0;

	write_data(data);
}

void print_oath_token(struct yamlpwdata *data, struct pwitem *item, char *mpw){
	char *pw=NULL,*tmp,*tpw;
	char *code;
	char ret[10]; // actually 6+1 needed
	int len,i;

	if(mpw)
		pw=mpw;
	else{
		if((tmp=tpw=return_password(data,&item,&pw))){
			while(*tmp)*(tmp++)=0;
			free(tpw);
		} else
			return;
	}

	code = (char*)get_oath_code(item,pw,&len);
	tmp=item->pass;
	while(*tmp)*(tmp++)=0;
	if(mpw == NULL){
		tmp=pw;
		while(*tmp)*(tmp++)=0;
	}

	if(oath_totp_generate(code,len,30,6,ret)){
		fprintf(stderr,"OATH error!\n");
		return;
	}

	printf("OATH Token: %s\n",ret);

	tmp=code; 
	for(i=0;i<len;i++)tmp[i]=0;
	tmp=ret;
	while(*tmp)*(tmp++)=0;

	cleanup_data(data);
}

void print_password(struct pwitem *item, char *pw, int print_user){
	if(print_user)
		printf("%s:%s\n",item->user,pw);
	else
		printf("%s\n",pw);
}

#ifdef USE_X11
#include "xsel.h"

void copy_password(struct pwitem *item, char *pw, int selcb){
	if(selcb)
		printf("Copying password to X clipboard.\n");
	else
		printf("Copying password to primary X selector.\n");

	xsel_init(selcb);
	set_x11_selection((unsigned char *)pw);
}
#endif

void generic_use_password(struct yamlpwdata *data, struct pwitem *item, int flag, void(*cb)(struct pwitem*,char*,int)){
	char *tmp,*pw,*mpw=NULL;

	pw = return_password(data,&item,&mpw);
	if(mpw && (item->oath == NULL || !*item->oath)){
		tmp=mpw;
		while(*tmp)*(tmp++)=0;
		free(mpw);
		mpw=NULL;
	}

	cb(item,pw,flag);

	if(mpw)
		print_oath_token(data,item,mpw);

	tmp=pw;
	while(*tmp)*(tmp++)=0;
	if(mpw){
		tmp=mpw;
		while(*tmp)*(tmp++)=0;
		free(mpw);
	}

	cleanup_data(data);
}

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
