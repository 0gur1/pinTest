#include<stdio.h>
#include<windows.h>
typedef UINT (CALLBACK* LPFNDLLFUNC1)(UINT);  
int main()
{
	HINSTANCE hDLL;
	LPFNDLLFUNC1 lpfnDllFunc1; 
	 
	  
	hDLL = LoadLibrary("kernel32.dll");  
	if (hDLL != NULL)  
	{  
	   lpfnDllFunc1 = (LPFNDLLFUNC1)GetProcAddress(hDLL,"Sleep");  
	   if (!lpfnDllFunc1)  
	   {  
	      // handle the error  
	      FreeLibrary(hDLL);  
	      return 0;  
	   }  
	   else  
	   {  
	      // call the function  
	      //Sleep(60000);
	      lpfnDllFunc1(60000);  
	   }  
	}  
	
	
	int i;
	scanf("%d",&i);
	puts("hello world");
}

