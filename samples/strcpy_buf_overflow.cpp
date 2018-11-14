#include<stdio.h>
#include<unistd.h>
#include<stdlib.h>
int main(){
	char dst[16];
	char *src=(char *)malloc(1024);
	scanf("%1023s",src);
	strcpy(dst,src);
	puts(dst);
	return 0;
}
