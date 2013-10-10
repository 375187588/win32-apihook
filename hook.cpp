#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "hook.h"

typedef ulong (apihook::*t0)(void);
typedef ulong (apihook::*t1)(ulong p1);
typedef ulong (apihook::*t2)(ulong p1, ulong p2);
typedef ulong (apihook::*t3)(ulong p1, ulong p2, ulong p3);
typedef ulong (apihook::*t4)(ulong p1, ulong p2, ulong p3, ulong p4);
typedef ulong (apihook::*t5)(ulong p1, ulong p2, ulong p3, ulong p4, ulong p5);
typedef ulong (apihook::*t6)(ulong p1, ulong p2, ulong p3, ulong p4, ulong p5, ulong p6);
typedef ulong (apihook::*t7)(ulong p1, ulong p2, ulong p3, ulong p4, ulong p5, ulong p6, ulong p7);
typedef ulong (apihook::*t8)(ulong p1, ulong p2, ulong p3, ulong p4, ulong p5, ulong p6, ulong p7, ulong p8);
typedef ulong (apihook::*t9)(ulong p1, ulong p2, ulong p3, ulong p4, ulong p5, ulong p6, ulong p7, ulong p8, ulong p9);
typedef ulong (apihook::*t10)(ulong p1, ulong p2, ulong p3, ulong p4, ulong p5, ulong p6, ulong p7, ulong p8, ulong p9, ulong p10);

apiproxy::apiproxy(void * api_bak, ulong *param, int param_num)
{
	this->api_bak = api_bak;
	this->param = param;
	this->param_num = param_num;
}

ulong apiproxy::call()
{
	void * function = api_bak;
	for(int i=param_num-1; i>=0; i--){
		ulong p = param[i];
		__asm push dword ptr[p];
	}
	return ((unsigned long (*)(void))function)();
}

ulong apihook::exec(void)
{
	return _exec(0);
}

ulong apihook::exec(ulong p1)
{
	return _exec(&p1);
}

ulong apihook::exec(ulong p1, ulong /*p2*/)
{
	return _exec(&p1);
}

ulong apihook::exec(ulong p1, ulong /*p2*/, ulong /*p3*/)
{
	return _exec(&p1);
}

ulong apihook::exec(ulong p1, ulong /*p2*/, ulong /*p3*/, ulong /*p4*/)
{
	return _exec(&p1);
}

ulong apihook::exec(ulong p1, ulong /*p2*/, ulong /*p3*/, ulong /*p4*/, ulong /*p5*/)
{
	return _exec(&p1);
}

ulong apihook::exec(ulong p1, ulong /*p2*/, ulong /*p3*/, ulong /*p4*/, ulong /*p5*/,
					ulong /*p6*/)
{
	return _exec(&p1);
}

ulong apihook::exec(ulong p1, ulong /*p2*/, ulong /*p3*/, ulong /*p4*/, ulong /*p5*/,
					ulong /*p6*/, ulong /*p7*/)
{
	return _exec(&p1);
}

ulong apihook::exec(ulong p1, ulong /*p2*/, ulong /*p3*/, ulong /*p4*/, ulong /*p5*/,
					ulong /*p6*/, ulong /*p7*/, ulong /*p8*/)
{
	return _exec(&p1);
}

ulong apihook::exec(ulong p1, ulong /*p2*/, ulong /*p3*/, ulong /*p4*/, ulong /*p5*/,
					ulong /*p6*/, ulong /*p7*/, ulong /*p8*/, ulong /*p9*/)
{
	return _exec(&p1);
}

ulong apihook::exec(ulong p1, ulong /*p2*/, ulong /*p3*/, ulong /*p4*/, ulong /*p5*/,
					ulong /*p6*/, ulong /*p7*/, ulong /*p8*/, ulong /*p9*/, ulong /*p10*/)
{
	return _exec(&p1);
}

unsigned long apihook::getptr()
{
	if(param_num==0){
		t0 m = &apihook::exec;
		__asm mov eax,dword ptr [m];
	}else if(param_num==1){
		t1 m = &apihook::exec;
		__asm mov eax,dword ptr [m];
	}else if(param_num==2){
		t2 m = &apihook::exec;
		__asm mov eax,dword ptr [m];
	}else if(param_num==3){
		t3 m = &apihook::exec;
		__asm mov eax,dword ptr [m];
	}else if(param_num==4){
		t4 m = &apihook::exec;
		__asm mov eax,dword ptr [m];
	}else if(param_num==5){
		t5 m = &apihook::exec;
		__asm mov eax,dword ptr [m];
	}else if(param_num==6){
		t6 m = &apihook::exec;
		__asm mov eax,dword ptr [m];
	}else if(param_num==7){
		t7 m = &apihook::exec;
		__asm mov eax,dword ptr [m];
	}else if(param_num==8){
		t8 m = &apihook::exec;
		__asm mov eax,dword ptr [m];
	}else if(param_num==9){
		t9 m = &apihook::exec;
		__asm mov eax,dword ptr [m];
	}else if(param_num==10){
		t10 m = &apihook::exec;
		__asm mov eax,dword ptr [m];
	}else{
		return 0;
	}
}

apihook::apihook()
{
	ulong oldprotect;
	jump_code_1 = (char*)malloc(5);
	jump_code_2 = (char*)malloc(10);
	api_bak		= (char*)malloc(1024);
	VirtualProtect(jump_code_1,  5,	PAGE_EXECUTE_READWRITE, &oldprotect);
	VirtualProtect(jump_code_2, 10, PAGE_EXECUTE_READWRITE, &oldprotect);
	VirtualProtect(api_bak,	  1024, PAGE_EXECUTE_READWRITE, &oldprotect);
}

void apihook::init(char *func, char *dll, void *new_function, int param_num, int align)
{
	assert ( param_num>=0 && param_num<=10 );
	assert ( align>=5 );

	this->new_function = new_function;
	this->param_num = param_num;
	this->align = align;

	api = (char*)GetProcAddress(GetModuleHandleA(dll),func);
	assert( api!=0 );

	jump_code_1[0] = '\xe9';
	ulong *jump_offset_to_jump2 = (ulong *)&jump_code_1[1];
	*jump_offset_to_jump2 = (ulong)jump_code_2 - (ulong)api - 5;

	jump_code_2[0] = '\xb9';
	ulong * this_ptr = (ulong *)&jump_code_2[1];
	*this_ptr = (ulong)this;

	jump_code_2[5] = '\xe9';
	ulong *jump_offset_to_exec = (ulong *)&jump_code_2[6];
	*jump_offset_to_exec =  getptr() - (ulong)&jump_code_2[10];

	memcpy(api_bak,api,align);
	api_bak[align] = '\xe9';
	ulong *jump_back_offset = (ulong *)&api_bak[align+1];
	*jump_back_offset = (ulong)api - (ulong)api_bak - 5 ;
}

ulong apihook::_exec(ulong *param)
{
	apiproxy proxy(api_bak,param,param_num);
	apiproxy *p = &proxy;
	__asm push dword ptr[p];

	ulong nf = (ulong)new_function;
	for(int i=param_num-1;i>=0;i--){
		ulong p = (ulong)(param+i);
		__asm push dword ptr[p];
	}
	return ((unsigned long (*)(void))nf)();
}

apihook::~apihook()
{
	uninstall();
	free(api_bak);
	free(jump_code_2);
	free(jump_code_1);
}

bool apihook::install()
{
	return WriteProcessMemory((HANDLE)-1,api,jump_code_1,5,NULL)!=0;
}

bool apihook::uninstall()
{
	return WriteProcessMemory((HANDLE)-1,api,api_bak,5,NULL)!=0;
}
