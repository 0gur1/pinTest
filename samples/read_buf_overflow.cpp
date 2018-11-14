#include<stdio.h>
#include<unistd.h>
int main(){
	char buf[16];
	read(0,buf,32);
	puts(buf);
}
