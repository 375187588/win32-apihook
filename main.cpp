/*
   +----------------------------------------------------------------------+
   | Win32 Apihook                                                        |
   +----------------------------------------------------------------------+
   | Author: Y.L. <270656184@qq.com>                                      |
   | Blog  : http://zhaoyl.sinaapp.com/                                   |
   | Copyright (c) 2013                                                   |
   +----------------------------------------------------------------------+
 */
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
	APIProxy *proxy)
{
	*lpText = "hello";
	*uType = MB_YESNOCANCEL;
	printf("%d",proxy->call());
	return printf("%d,%s,%s,%d\r\n",*hWnd,*lpText,*lpCaption,*uType);
}

int main()
{
	//__asm INT 3;
	APIHook * hook = new APIHook;
	hook->init("MessageBoxA","User32.dll",myMessageBoxA,4,5);
	hook->install();
	MessageBoxA((HWND)0,"text","title",0);
	return 0;
}
