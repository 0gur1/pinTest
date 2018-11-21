#include<stdio.h>
#include<unistd.h>
void vuln(){
	char buf[16];
	read(0,buf,32);
	puts(buf);
}
int main(){
	vuln();
}
