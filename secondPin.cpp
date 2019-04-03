#include "pin.H"
#include <iostream>
#include <string>
#include <map>
#include <ctime>
namespace WINDOWS{
#include <windows.h>
}

//设定最大时间，超时退出程序执行Fini
#define MAX_LIMIT_SECONDS 60

//记录StartProgram的时间
long g_time_begin = 0;



FILE *p_outImg = NULL;
FILE *p_outRegister= NULL;

UINT32 indexBBL = 0;
UINT32 imgID=0 ;
ADDRINT addr=0 ;
UINT32 esp_offset =0;

KNOB<string> KnobLogPath(KNOB_MODE_WRITEONCE,  "pintool",
						 "lp", "", "log path");
KNOB<UINT32> KnobImgID(KNOB_MODE_WRITEONCE,  "pintool",
						 "i", "0", "imgID");
KNOB<ADDRINT> KnobBBLAddr(KNOB_MODE_WRITEONCE,  "pintool",
						 "ba", "0", "BBL addr");
KNOB<UINT32> KnobESPOFF(KNOB_MODE_WRITEONCE,  "pintool",
						 "eo", "0", "esp offset");




//PIN默认函数写法
INT32 Usage()
{
	cerr << "This tool prints out the number of dynamically executed " << endl <<
		"instructions, basic blocks and threads in the application." << endl << endl;

	cerr << KNOB_BASE::StringKnobSummary() << endl;

	return -1;
}

//PIN默认函数写法，Fini用于在程序退出时进行处理
VOID Fini(INT32 code, VOID *v)
{
	cout << "[+]Fini" << endl;

	if(p_outRegister != NULL){
		fclose(p_outRegister);
		p_outRegister = NULL;
	}
	
}


//每个INS执行时，检查是否已经超时
//采用INS是避免在BBL内进行循环，但是也会面临对一条指令等待响应卡死的情景。
//目前解决方式是辅以外部终止，但是这样没法调用Fini函数。
VOID INSTimeControl()
{
	long cur_time = time(0);
	//cout << cur_time - g_time_begin<<endl;
	if (cur_time - g_time_begin > MAX_LIMIT_SECONDS)
	{
		cout << "Time limit " <<  MAX_LIMIT_SECONDS << "s exceed! Now is: " << cur_time - g_time_begin << "s!" << endl;
		PIN_ExitApplication(0);
	}
}
VOID RecordRtnRegister(CONTEXT *ctxt,UINT8 retFlag){
	INSTimeControl();
	ADDRINT ebp=PIN_GetContextReg(ctxt,REG_EBP);

	ADDRINT esp=PIN_GetContextReg(ctxt,REG_STACK_PTR);
	ADDRINT eip=PIN_GetContextReg(ctxt,REG_INST_PTR);
	ADDRINT eax=PIN_GetContextReg(ctxt,REG_EAX);
	ADDRINT *addr;
		
	fprintf(p_outRegister, "EBP:%p\nESP:%p\nEIP:%p\nEAX:%p\n",ebp,esp,eip,eax); /**/
	fprintf(p_outRegister, "stack:\n");
	
	//stack
	if(!retFlag)
	{
		for(addr =(ADDRINT *)ebp-esp_offset/4;addr <=(ADDRINT *) ebp+1;addr++)
		{
			fprintf(p_outRegister,"%p:%p\n",addr,*addr);
		}
	}
	else{
		for(addr =(ADDRINT *)esp-1-esp_offset/4;addr <=(ADDRINT *)esp;addr++)
		{
			fprintf(p_outRegister,"%p:%p\n",addr,*addr);
		}
	}
	fprintf(p_outRegister, "\n\n");
} 

/*Trace插装函数*/
VOID Trace (TRACE trace, VOID *v)
{
	//用于控制程序执行时间
	RTN rtn = TRACE_Rtn(trace);
	IMG img = IMG_FindByAddress(TRACE_Address(trace));
	UINT32 imgId = IMG_Id(img);
	UINT8 retFlag=0;

	// 遍历Trace中的所有BBL
	if (imgId == imgID)
		for (BBL bbl = TRACE_BblHead (trace); BBL_Valid (bbl); bbl = BBL_Next (bbl) )
		{
			//考虑到可能陷入其中一个BBL的死循环，所以对INS插桩
			if(BBL_Address(bbl)==addr)
			{
				for (INS ins= BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
				{
					//INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)INSTimeControl, IARG_END);//检查是否超时
					if(INS_IsRet(ins))
						retFlag=1;
					INS_InsertCall(ins, IPOINT_BEFORE,(AFUNPTR)RecordRtnRegister,IARG_CONST_CONTEXT,IARG_ADDRINT,retFlag,IARG_END);
				}
			}
			
		}
}



int main(int argc, char *argv[])
{

	//日志目录和系统调用函数信息目录
	//string runtime_dir = "F:\\PinFWSandBox\\PIN_Runtime_File\\PIN_Runtime_File\\";
	cout << "[+]start" << endl;
	if( PIN_Init(argc,argv) )
	{
		return Usage();
	}
	PIN_InitSymbols();
	string work_dir = argv[argc-1];
	int index = work_dir.rfind("\\");

	if (index == string::npos)
	{
		cout << "work_dir error! " << work_dir << endl;
		return -1;
	}

	string name;
	//assign：从work_dir的第index+1位开始读取到后缀名之前的内容为name 
	name.assign(work_dir, index+1, work_dir.length()-index-5);

	cout << name << endl;
	//work_dir为路径 
	work_dir.assign(work_dir, 0, index);
	cout << work_dir << endl;
	//计算并设置工作目录到目标文件的平行目录，避免相对路径读取引发的问题
	WINDOWS::SetCurrentDirectory(work_dir.c_str());

	work_dir += "\\";
	work_dir += name;
	work_dir += "\\";
	string log_dir = KnobLogPath.Value();
	log_dir += "\\";
	log_dir += name;
	log_dir += "\\";
	//string command = "rd /q/s " + log_dir;
	//system(command.c_str());

	//计算并生成日志目录
	string command = "mkdir " + log_dir;
	system(command.c_str());

	//addtional record

	string reg_file = log_dir + name + "_registers.fw";

	p_outRegister=fopen(reg_file.c_str(),"w");

	if (  p_outRegister == NULL)
	{
		cout << "Ins log file not open!" << endl;
		return -1;
	}


	//记录当前时间
	g_time_begin = time(0);

	imgID = KnobImgID.Value();
	addr = KnobBBLAddr.Value();
	esp_offset = KnobESPOFF.Value();
	printf("%d\t%d\t%d\n",imgID,addr,esp_offset);

	//添加对Trace翻译的功能函数
	TRACE_AddInstrumentFunction(Trace, 0);
	//IMG_AddInstrumentFunction(ImageLoad, 0);


	PIN_AddFiniFunction(Fini, 0);
	PIN_StartProgram();

	return 0;
}
