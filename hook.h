#ifndef HOOK_H
#define HOOK_H
typedef unsigned long ulong;
class APIHook
{
private:
	int param_num;
	int align;
	char * api;
	char * api_bak;
	char * jump_code_1;
	char * jump_code_2;
	void * new_function;
	ulong getptr();

public:
	APIHook();
	~APIHook();
	void init(
		const char *func,
		const char *dll,
		void *new_function,
		int param_num,
		int align = 5);
	bool install();
	bool uninstall();

	ulong _exec(ulong *param);
	ulong exec(void);
	ulong exec(ulong p1);
	ulong exec(ulong p1, ulong p2);
	ulong exec(ulong p1, ulong p2, ulong p3);
	ulong exec(ulong p1, ulong p2, ulong p3, ulong p4);
	ulong exec(ulong p1, ulong p2, ulong p3, ulong p4, ulong p5);
	ulong exec(ulong p1, ulong p2, ulong p3, ulong p4, ulong p5, ulong p6);
	ulong exec(ulong p1, ulong p2, ulong p3, ulong p4, ulong p5, ulong p6, ulong p7);
	ulong exec(ulong p1, ulong p2, ulong p3, ulong p4, ulong p5, ulong p6, ulong p7, ulong p8);
	ulong exec(ulong p1, ulong p2, ulong p3, ulong p4, ulong p5, ulong p6, ulong p7, ulong p8, ulong p9);
	ulong exec(ulong p1, ulong p2, ulong p3, ulong p4, ulong p5, ulong p6, ulong p7, ulong p8, ulong p9, ulong p10);

};

class APIProxy
{
private:
	void  * api_bak;
	ulong * param;
	int param_num;
public:
	APIProxy(void *api_bak, ulong * param, int param_num);
	ulong call();
};

#endif // HOOK_H
