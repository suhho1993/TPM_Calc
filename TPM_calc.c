/***************************************z``******************************
* Filename:   sha256.c
* Author:     Brad Conte (brad AT bradconte.com)
* Copyright:
* Disclaimer: This code is presented "as is" without any guarantees.
* Details:    Performs known-answer tests on the corresponding SHA1
	          implementation. These tests do not encompass the full
	          range of available test vectors, however, if the tests
	          pass it is very, very likely that the code is correct
	          and was compiled properly. This code also serves as
	          example usage of the functions.
*********************************************************************/

/*************************** HEADER FILES ***************************/
#include <stdio.h>
#include <string.h>
#include "sha256.h"
#include <stdlib.h>
/*********************** FUNCTION DEFINITIONS ***********************/
void sha256_print(BYTE* in){
	int i = 0;
	char res[65]={0,};
	for(i=0; i<32; i++){
		sprintf(res+(i*2),"%02x",in[i]);
	}
	printf("SHA256:      %s\n",res);
	return ;
}
int sha256_calc(char *line, BYTE* rt_v)
{

	if(!strncmp(line,"GRUB",sizeof(char)*4)){
		printf("this is Grub\n");
		FILE* file = fopen("GRUB.efi","r");
		if(!file){
			printf("fileopen fail\n");
			return -1;
		}
		size_t sizeof_FILE = 615216;
		//fseek(file,0,SEEK_END);
		//size_t sizeof_FILE = ftell(file);
		//fseek(file,0,SEEK_SET);

		void* data =NULL;
		data= malloc(sizeof_FILE);
		if(!data){	
			printf("data malloc fail\n");
			return -1;
		}
		SHA256_CTX ctx;
		fread(data,sizeof_FILE,1,file);
		sha256_init(&ctx);
		sha256_update(&ctx, data, sizeof_FILE);
		sha256_final(&ctx, rt_v);
		sha256_print(rt_v);
		free(data);
		return 1;
	}
	else if(!strncmp(line,"KERNEL_1",sizeof(char)*8)){
		printf("this is kernel_2\n");
		FILE* file = fopen("KERNEL.efi","r");
		if(!file){
			printf("fileopen fail\n");
			return -1;
		}
		size_t sizeof_FILE = 7104112;

		void* data =NULL;
		data= malloc(sizeof_FILE);
		if(!data){	
			printf("data malloc fail\n");
			return -1;
		}
		SHA256_CTX ctx;
		fread(data,sizeof_FILE,1,file);
		sha256_init(&ctx);
		sha256_update(&ctx, data+0x200,sizeof_FILE-0x200);
		sha256_final(&ctx, rt_v);
		sha256_print(rt_v);
		free(data);
		return 1;
	}
	else if(!strncmp(line,"KERNEL_2",sizeof(char)*8)){
		printf("this is kernel_2\n");
		FILE* file = fopen("KERNEL_2.efi","r");
		if(!file){
			printf("fileopen fail\n");
			return -1;
		}
		size_t sizeof_FILE = 7104528;

		void* data =NULL;
		data= malloc(sizeof_FILE);
		if(!data){	
			printf("data malloc fail\n");
			return -1;
		}
		SHA256_CTX ctx;
		fread(data,sizeof_FILE,1,file);
		sha256_init(&ctx);
		sha256_update(&ctx, data+0x200,sizeof_FILE-0x200);
		sha256_final(&ctx, rt_v);
		sha256_print(rt_v);
		free(data);
		return 1;
	}else if(!strncmp(line,"UBUNTU",sizeof(char)*6)){
		printf("this is UBUNTU\n");
		FILE* file = fopen("UBUNTU.txt","r");
		if(!file){
			printf("fileopen fail\n");
			return -1;
		}
		size_t sizeof_FILE =781;

		char* data =NULL;
		data= malloc(sizeof_FILE);
		if(!data){	
			printf("data malloc fail\n");
			return -1;
		}
		SHA256_CTX ctx;
		fread(data,sizeof_FILE,1,file);

		size_t len = sizeof_FILE;
		data[len-1]='\0';
		printf("size: %d\n%s\n",len,data);
		sha256_init(&ctx);
		sha256_update(&ctx, (unsigned char*) data, len);
		sha256_final(&ctx, rt_v);
		sha256_print(rt_v);
		free(data);
		return 1;
	}
	else if(!strncmp(line,"UBUNTU2",sizeof(char)*7)){
		printf("this is UBUNTU2\n");
		FILE* file = fopen("UNUNTU2.txt","r");
		if(!file){
			printf("fileopen fail\n");
			return -1;
		}
		size_t sizeof_FILE =831;

		char* data =NULL;
		data= malloc(sizeof_FILE);
		if(!data){	
			printf("data malloc fail\n");
			return -1;
		}
		SHA256_CTX ctx;
		fread(data,sizeof_FILE,1,file);

		size_t len = strlen(data);
		data[len-1]='\0';
		printf("size: %d\n%s\n",len,data);
		sha256_init(&ctx);
		sha256_update(&ctx, (unsigned char*) data, len);
		sha256_final(&ctx, rt_v);
		sha256_print(rt_v);
		free(data);
		return 1;
	}
	else if(!strncmp(line,"SYSTEM",sizeof(char)*5)){
		printf("this is SYSTEM\n");
		FILE* file = fopen("SYSTEM.txt","r");
		if(!file){
			printf("fileopen fail\n");
			return -1;
		}
		size_t sizeof_FILE =55;
		
		char* data =NULL;
		data= malloc(sizeof_FILE);
		if(!data){	
			printf("data malloc fail\n");
			return -1;
		}
		SHA256_CTX ctx;
		fread(data,sizeof_FILE,1,file);

		data[sizeof_FILE-1]='\0';
		printf("size: %d\n%s\n",sizeof_FILE,data);
		sha256_init(&ctx);
		sha256_update(&ctx, (unsigned char*) data, sizeof_FILE);
		sha256_final(&ctx, rt_v);
		sha256_print(rt_v);
		free(data);
		return 1;

	}
	else {
		printf("this is CMD\n");//	size_t sizeof_FILE =615216;
		size_t len = strlen(line);
		len-=1;
		line[len]='\0';
		printf("size: %d /// %s\n", len, line);
		SHA256_CTX ctx;
		sha256_init(&ctx);
		sha256_update(&ctx, line, len);
		sha256_final(&ctx, rt_v);
		sha256_print(rt_v);
		return 1;
	}
}
void sha256_extend(BYTE* old, BYTE* new)
{
	BYTE cat[64];

	int i =0;
	for(i=0;i<32;i++){
		cat[i]=old[i];
	}
	for(i=0;i<32;i++){
		cat[32+i]=new[i];
	}
	char test[129]={0,};
	for(i=0;i<64;i++){
		sprintf(test+(i*2),"%02x",cat[i]);
	}
	printf("cat: %s\n",test);

	BYTE res[32]={0,};

	SHA256_CTX ctx;
	sha256_init(&ctx);
	sha256_update(&ctx, cat, sizeof(cat));
	sha256_final(&ctx, res);	 
	sha256_print(res);

	for(i=0;i<32;i++){
		old[i] = res[i];
	}
	memset(new,0,sizeof(new));
	return ;
}	

int main(int argc, char* argv[])
{
	BYTE old[32]={0,};
	BYTE new[32]={0,};

	FILE * file;
	char * line = malloc(sizeof(char)*150);
	size_t len = 150;
	printf("%s\n",argv[1]);
	file = fopen(argv[1], "r");
	if(!file){
		printf("ToMeasure open fail\n");
		return 0;
	}

	while(fgets(line, len, file)!= NULL){
		printf( "\nread line :%s", line);
		sha256_calc(line, new);
		sha256_extend(old,new);
		memset(line,0,len);
	}
	free(line);

	return(0);
}
