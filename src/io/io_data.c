/* Copyright 2017, Heckendorf */

#include <stdint.h>
#include <time.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
//#include <openssl/blowfish.h>
#include <openssl/evp.h>
#include <yamldom.h>
#include "io_data.h"
#include "io_setup.h"
#include "io_common.h"

static unsigned char base64_deindex(unsigned char ind){
	if(ind<26)
		return ind+'A';
	else if(ind<52)
		return ind-26+'a';
	else if(ind<62)
		return ind-52+'0';
	else if(ind==62)
		return '+';
	else if(ind==63)
		return '/';
	return '=';
}

int base64_encode(const unsigned char *in, unsigned char *out, const int len){
	int i;
	int outlen;
	int m=len%3;
	int looplen=len-m;

	for(outlen=i=0;i<looplen;i+=3){
		out[outlen++]=base64_deindex(in[i]>>2);
		out[outlen++]=base64_deindex(((in[i]&0x03)<<4)|(in[i+1]>>4));
		out[outlen++]=base64_deindex(((in[i+1]&0x0F)<<2)|(in[i+2]>>6));
		out[outlen++]=base64_deindex(in[i+2]&0x3F);
	}

	if(m>0){
		out[outlen]=base64_deindex(in[i]>>2);
		out[outlen+3]='=';

		if(m==1){
			out[outlen+1]=base64_deindex((in[i]&0x03)<<4);
			out[outlen+2]='=';
		}
		else if(m==2){
			out[outlen+1]=base64_deindex(((in[i]&0x03)<<4)|(in[i+1]>>4));
			out[outlen+2]=base64_deindex((in[i+1]&0x0F)<<2);
		}

		return outlen+4;
	}

	return outlen;
}

int base64_decode(const unsigned char *in, unsigned char *out, const int len){
	int i,j;
	unsigned char group[4];
	int outlen;

	group[0]=group[1]=group[2]=group[3]=0;

	for(i=0;i<len/4;i++){
		for(j=0;j<4;j++){
			group[j]=in[i*4+j];
			if(group[j]>='A' && group[j]<='Z')
				group[j]-='A';
			else if(group[j]>='a' && group[j]<='z')
				group[j]=(group[j]-'a')+26;
			else if(group[j]>='0' && group[j]<='9')
				group[j]=(group[j]-'0')+52;
			else if(group[j]=='+')
				group[j]=62;
			else if(group[j]=='/')
				group[j]=63;
			else // '='
				group[j]=64;
		}

		out[i*3]=(group[0]<<2)|(group[1]>>4);
		out[i*3+1]=((group[1]&0x0F)<<4)|(group[2]>>2);
		out[i*3+2]=((group[2]&0x03)<<6)|(group[3]);
	}

	//outlen=len;
	outlen=(len*3)/4;
	if(group[3]==64)
		outlen--;
	if(group[2]==64)
		outlen--;

	return outlen;
}

unsigned char* do_crypt(const unsigned char *data, const int dlen, const char *pw, unsigned char *iv, int do_encrypt, int *olen){
	int outlen,finallen;
	unsigned char *out=malloc(dlen+ENC_BLOCK_SIZE);
	unsigned char genkey[ENC_KEY_SIZE];
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

	EVP_CIPHER_CTX_init(ctx);
	EVP_CipherInit_ex(ctx, ENC_FUNCTION, NULL, NULL, NULL, do_encrypt);
	EVP_CIPHER_CTX_set_padding(ctx,1);
	OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == ENC_KEY_SIZE);
	OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == ENC_IV_SIZE);

	if(!PKCS5_PBKDF2_HMAC(pw,strlen(pw),NULL,0,1024,EVP_sha1(),ENC_KEY_SIZE,genkey)){
		fprintf(stderr,"Key gen failed\n");
		EVP_CIPHER_CTX_free(ctx);
		exit(1);
		return NULL;
	}

	EVP_CipherInit_ex(ctx, NULL, NULL, genkey, iv, do_encrypt);

	if(!EVP_CipherUpdate(ctx, out, &outlen, data , dlen)){
		fprintf(stderr,"CipherUpdate failed\n");
		EVP_CIPHER_CTX_free(ctx);
		exit(1);
		return NULL;
	}
	if(!EVP_CipherFinal_ex(ctx, out+outlen, &finallen)){
		fprintf(stderr,"CipherFinal failed. Invalid Password?\n");
		EVP_CIPHER_CTX_free(ctx);
		exit(1);
		return NULL;
	}

	EVP_CIPHER_CTX_free(ctx);

	*olen=outlen+finallen;
	return out;
}

unsigned char* decrypt_yaml(unsigned char *iv, unsigned char *pass, const char *pw, int *dlen){
	unsigned char *out;
	unsigned char ivout[ENC_IV_SIZE+1];
	int len;

	base64_decode(iv,ivout,strlen((char*)iv));
	ivout[ENC_IV_SIZE]=0;

	len=strlen((char*)pass);
	out=malloc(len);
	len=base64_decode(pass,out,len);

	return do_crypt(out,len,pw,ivout,0,dlen);
}

unsigned char* get_password(struct pwitem *item,const char *pw, int *len){
	return decrypt_yaml((unsigned char*)item->iv,(unsigned char*)item->pass,pw,len);
}

unsigned char* get_oath_code(struct pwitem *item,const char *pw, int *len){
	return decrypt_yaml((unsigned char*)item->oathiv,(unsigned char*)item->oath,pw,len);
}

// Robert Jenkins' 96 bit Mix Function
uint32_t mix_96(uint32_t a, uint32_t b, uint32_t c)
{
	a=a-b;  a=a-c;  a=a^(c >> 13);
	b=b-c;  b=b-a;  b=b^(a << 8);
	c=c-a;  c=c-b;  c=c^(b >> 13);
	a=a-b;  a=a-c;  a=a^(c >> 12);
	b=b-c;  b=b-a;  b=b^(a << 16);
	c=c-a;  c=c-b;  c=c^(b >> 5);
	a=a-b;  a=a-c;  a=a^(c >> 3);
	b=b-c;  b=b-a;  b=b^(a << 10);
	c=c-a;  c=c-b;  c=c^(b >> 15);

	return c;
}

uint32_t get_seed() {
	uint32_t pid;
	uint32_t ret;
	time_t t;

	pid = (uint32_t) getpid();
	ret = mix_96(time(&t), pid, rand());

	return ret;
}

char* gen_iv(){
	const int len=ENC_IV_SIZE;
	unsigned char in[len];
	unsigned char *out=malloc((len*4/3)+5);
	uint32_t *p=(uint32_t*)in;
	int olen;
	int i;

	srandom(get_seed());

	for(i=0;i<ENC_IV_SIZE/4;i++)
		p[i]=random();

	olen=base64_encode(in,out,len);
	out[olen]=0;

	return (char*)out;
}

void encode_yaml_pass(char **pass, char **iv,const char *pw){
	unsigned char *bout,*out64;
	unsigned char *biv;
	int len,ivlen,i;

	*iv=gen_iv();
	ivlen=strlen(*iv);
	biv=malloc(ivlen);
	if(base64_decode((unsigned char*)*iv,biv,ivlen)!=ENC_IV_SIZE){
		fprintf(stderr,"IV decode error\n");
		exit(1);
	}

	len=strlen(*pass)+1;
	bout=malloc(len);

	bout=do_crypt((unsigned char*)*pass,len,pw,biv,1,&len);
	for(i=0;(*pass)[i];i++)
		(*pass)[i]=0;

	out64=malloc((len*4/3)+5);

	len=base64_encode(bout,out64,len);
	out64[len]=0;
	*pass=(char*)out64;
}

void set_password(struct pwitem *item,const char *pw){
	encode_yaml_pass(&item->pass,&item->iv,pw);
}

void set_oath(struct pwitem *item,const char *pw){
	encode_yaml_pass(&item->oath,&item->oathiv,pw);
}

void parse_data(struct yamlpwdata *data){
	struct pwitem *tmppwi;
	yamldom_node_t *nodes,*tmp;
	char buffer[100];

	nodes=NULL;
	data->data.items=NULL;

	for(tmp=YAMLDOM_SEQ_NODES(data->yaml.root);tmp;tmp=tmp->next){
		tmppwi=data->data.items;
		data->data.items=calloc(1,sizeof(*data->data.items));
		data->data.items->next=tmppwi;
		tmppwi=data->data.items;

		for(nodes=YAMLDOM_MAP_NODES(tmp);nodes;nodes=nodes->next->next){
			if(strcmp(YAMLDOM_SCALAR_DATA(nodes)->val,"name")==0)
				tmppwi->name=YAMLDOM_SCALAR_DATA(nodes->next)->val;
			else if(strcmp(YAMLDOM_SCALAR_DATA(nodes)->val,"location")==0)
				tmppwi->location=YAMLDOM_SCALAR_DATA(nodes->next)->val;
			else if(strcmp(YAMLDOM_SCALAR_DATA(nodes)->val,"user")==0)
				tmppwi->user=YAMLDOM_SCALAR_DATA(nodes->next)->val;
			else if(strcmp(YAMLDOM_SCALAR_DATA(nodes)->val,"pass")==0)
				tmppwi->pass=YAMLDOM_SCALAR_DATA(nodes->next)->val;
			else if(strcmp(YAMLDOM_SCALAR_DATA(nodes)->val,"iv")==0)
				tmppwi->iv=YAMLDOM_SCALAR_DATA(nodes->next)->val;
			else if(strcmp(YAMLDOM_SCALAR_DATA(nodes)->val,"oath")==0)
				tmppwi->oath=YAMLDOM_SCALAR_DATA(nodes->next)->val;
			else if(strcmp(YAMLDOM_SCALAR_DATA(nodes)->val,"oathiv")==0)
				tmppwi->oathiv=YAMLDOM_SCALAR_DATA(nodes->next)->val;
		}
	}
}

static void dump_graph(struct yamlpwdata *data){
	yamldom_dump(&data->yaml.ydd,data->yaml.root);
}

void init_data(struct yamlpwdata *data, FILE *infd, FILE *outfd){
	data->yaml.ydd.infd=infd;
	data->yaml.ydd.outfd=outfd;

	io_general_init(&data->yaml.ydd);

	data->yaml.anchors=NULL;
	if(infd)
		data->yaml.root=yamldom_gen(&data->yaml.ydd,NULL); // Second argument is optional (anchors).
	else{
		data->yaml.root=yamldom_make_seq(NULL);
	}

	parse_data(data);
	data->valid = 1;
}

void append_data_item(struct yamlpwdata *data, struct pwitem *item, char *pw){
	yamldom_node_t *nodes,*tmp,*mapr;

	set_password(item,pw);

	mapr=yamldom_make_map(NULL);

	nodes=NULL;

	tmp=yamldom_make_scalar(NULL,"name",-1);
	nodes=yamldom_append_node(nodes,tmp);
	tmp=yamldom_make_scalar(NULL,item->name?item->name:"",-1);
	nodes=yamldom_append_node(nodes,tmp);

	tmp=yamldom_make_scalar(NULL,"location",-1);
	nodes=yamldom_append_node(nodes,tmp);
	tmp=yamldom_make_scalar(NULL,item->location?item->location:"",-1);
	nodes=yamldom_append_node(nodes,tmp);

	tmp=yamldom_make_scalar(NULL,"user",-1);
	nodes=yamldom_append_node(nodes,tmp);
	tmp=yamldom_make_scalar(NULL,item->user?item->user:"",-1);
	nodes=yamldom_append_node(nodes,tmp);

	tmp=yamldom_make_scalar(NULL,"pass",-1);
	nodes=yamldom_append_node(nodes,tmp);
	tmp=yamldom_make_scalar(NULL,item->pass,-1);
	nodes=yamldom_append_node(nodes,tmp);

	tmp=yamldom_make_scalar(NULL,"iv",-1);
	nodes=yamldom_append_node(nodes,tmp);
	tmp=yamldom_make_scalar(NULL,item->iv,-1);
	nodes=yamldom_append_node(nodes,tmp);

	YAMLDOM_MAP_NODES(mapr)=nodes;

	YAMLDOM_SEQ_NODES(data->yaml.root)=yamldom_append_node(YAMLDOM_SEQ_NODES(data->yaml.root),mapr);
}

int check_mapval(yamldom_node_t *map, char *field, char *val){
	yamldom_node_t *tmp;

	if(val==NULL)
		return 1;

	if((tmp=yamldom_find_map_val(map,field)) &&
		strcmp(YAMLDOM_SCALAR_DATA(tmp)->val,val)==0)
		return 1;

	return 0;
}

int add_oath_item(struct yamlpwdata *data, struct pwitem *item, char *pw){
	yamldom_node_t *nodes,*tmp,*mapr;

	set_oath(item,pw);

	for(nodes=YAMLDOM_SEQ_NODES(data->yaml.root);nodes;nodes=nodes->next){
		if(check_mapval(nodes,"name",item->name) && 
			check_mapval(nodes,"location",item->location) && 
			check_mapval(nodes,"user",item->user))
			break;
	}

	if(nodes==NULL)
		return 1;

	mapr = nodes;
	nodes = YAMLDOM_MAP_NODES(mapr);

	tmp=yamldom_make_scalar(NULL,"oath",-1);
	nodes=yamldom_append_node(nodes,tmp);
	tmp=yamldom_make_scalar(NULL,item->oath,-1);
	nodes=yamldom_append_node(nodes,tmp);

	tmp=yamldom_make_scalar(NULL,"oathiv",-1);
	nodes=yamldom_append_node(nodes,tmp);
	tmp=yamldom_make_scalar(NULL,item->oathiv,-1);
	nodes=yamldom_append_node(nodes,tmp);

	YAMLDOM_MAP_NODES(mapr)=nodes;

	return 0;
}

void cleanup_data(struct yamlpwdata *data){
	if(!data->valid)
		return;

	data->valid = 0;
	io_general_close(&data->yaml.ydd);

	yamldom_free_nodes(data->yaml.root);
	yamldom_free_anchors(data->yaml.anchors);
}

void write_data(struct yamlpwdata *data){
	dump_graph(data);

	cleanup_data(data);
}
