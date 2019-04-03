#include<stdio.h>
#include<iostream>
#include<exception>
#include<unistd.h>
using namespace std;
void vuln(){
	char buf[16];
	read(0,buf,32);
	puts(buf);
}
int main(){
		vuln();

}
