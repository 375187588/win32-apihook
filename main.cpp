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
	int ret;
	*lpText = "hello";
	*uType = MB_YESNOCANCEL;
	ret = proxy->call();
	printf("arg(%d,%s,%s,%d) ret: %d\r\n", *hWnd, *lpText, *lpCaption, *uType, ret);
	return ret;
}

int main()
{
	APIHook * hook = new APIHook;
	hook->init("MessageBoxA","User32.dll",myMessageBoxA,4,5);
	hook->install();
	MessageBoxA((HWND)0,"text","title",0);
	return 0;
}
