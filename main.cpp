#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "hook.h"

int WINAPI myMessageBoxA(
    __in_opt HWND *hWnd,
    __in_opt LPCSTR *lpText,
    __in_opt LPCSTR *lpCaption,
    __in UINT *uType,
	apiproxy *proxy)
{
	*lpText = "hello";
	*uType = MB_YESNOCANCEL;
	printf("%d",proxy->call());
	return printf("%d,%s,%s,%d\r\n",*hWnd,*lpText,*lpCaption,*uType);
}

int main()
{
	//__asm INT 3;
	apihook * hook = new apihook;
	hook->init("MessageBoxA","User32.dll",myMessageBoxA,4,5);
	hook->install();
	MessageBoxA((HWND)0,"text","title",0);
	return 0;
}
