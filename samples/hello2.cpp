#include<stdio.h>
#include<stdlib.h>
#include<string.h>
int add(int a,int b){
	return a+b;
}
int main()
{
	//Sleep(60000);
	int i;
	char a[10];
	
	gets(a);
	puts(a);
	
	scanf("%d",&i);
	printf("%d\n",i);
	
	malloc(10);
	malloc(10);
	malloc(10);
	malloc(10);
	malloc(10);
	
	if( strcmp(a,"hell"))
		puts("not equal");
	
	i=add(3,4);
	printf("%d\n",i);
}

