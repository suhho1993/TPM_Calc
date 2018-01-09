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
#include <memory.h>
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
	return 1;
}

int sha256_test(BYTE* rt_v)
{
	FILE* file = fopen("kernel.efi","r");
	if(!file){
		printf("fileopen fail\n");
		return -1;
	}
	size_t sizeof_FILE =7106040;
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
	return 1;
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
	return ;
}	
int main()
{
	BYTE old[32]={0,};
	BYTE new[32]={0,};

	sha256_test(new);
	sha256_extend(old,new);
	return(0);
}
