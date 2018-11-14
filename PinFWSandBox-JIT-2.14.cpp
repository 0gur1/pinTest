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


//FILE *p_ins_mid_file = NULL;//记录被翻译的指令流信息
//FILE *p_ins_real_file = NULL;//记录实际执行的指令流信息
FILE *p_ins_imm_file = NULL;//记录实际执行指令流中常量信息
FILE *p_ins_opcode_file = NULL;//记录实际执行指令流中操作码信息
FILE *p_outImg = NULL;
FILE *p_outBBL = NULL;
FILE *p_outProcess = NULL;
FILE *p_outRoutine = NULL;

UINT32 indexBBL = 0;

typedef struct RtnCount{
	string _name;
	UINT32 _imgId;
	ADDRINT _address;
	RTN _rtn;
	UINT32 _rtnCount;
	struct RtnCount * _next;
} RTN_COUNT;
RTN_COUNT * RtnList = NULL;

map<string, UINT> g_opcode_count;//记录opcode频率

KNOB<string> KnobLogPath(KNOB_MODE_WRITEONCE,  "pintool",
    "lp", "", "log path");

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

	if (p_ins_imm_file != NULL)
	{
		fclose(p_ins_imm_file);
		p_ins_imm_file = NULL;
	}

	if (p_ins_opcode_file != NULL)
	{
		for (map<string, UINT>::iterator it = g_opcode_count.begin(); it!=g_opcode_count.end(); it++)
		{
			fprintf(p_ins_opcode_file, "%s_%u ", it->first.c_str(), it->second);
		}

		fclose(p_ins_opcode_file);
		p_ins_opcode_file = NULL;
	}
	if(p_outBBL != NULL){
		fclose(p_outBBL);
		p_outBBL = NULL;
	}
	if(p_outProcess != NULL){
		fclose(p_outProcess);
		p_outProcess = NULL;
	}
	if(p_outImg != NULL){
		fclose(p_outImg);
		p_outImg = NULL;
	}
	if(p_outRoutine != NULL){
		fprintf(p_outRoutine, "%s %8s %8s %8s\n", "RoutineName", "Image", "Address", "Calls");
		for(RTN_COUNT *rc = RtnList; rc; rc = rc->_next){
			if(rc->_rtnCount > 0){
				fprintf(p_outRoutine, "%s %d %08x %d\n", rc->_name.c_str(), rc->_imgId, rc->_address, rc->_rtnCount);
			}
		}
		fclose(p_outRoutine);
		p_outRoutine = NULL;
	}
}


//每个INS执行时，检查是否已经超时
//采用INS是避免在BBL内进行循环，但是也会面临对一条指令等待响应卡死的情景。
//目前解决方式是辅以外部终止，但是这样没法调用Fini函数。
VOID INSTimeControl()
{
	long cur_time = time(0);
	if (cur_time - g_time_begin > MAX_LIMIT_SECONDS)
	{
		cout << "Time limit " <<  MAX_LIMIT_SECONDS << "s exceed! Now is: " << cur_time - g_time_begin << "s!" << endl;
		PIN_ExitApplication(0);
	}
}



//记录opcode频率
VOID INSOpcodeLog(char *opcode)
{
	string opcode_s = opcode;
	g_opcode_count[opcode_s] ++;
}

//记录立即数信息
VOID INSImmLog(char *opcode, UINT imm)
{
	fprintf(p_ins_imm_file, "%s_%x ", opcode, imm);
}

VOID RecordProcess(UINT32 IndexBBL)
{
	fprintf(p_outProcess,"BBL %x\n",IndexBBL);
}

/*Trace插装函数*/
VOID Trace (TRACE trace, VOID *v)
{
	//用于控制程序执行时间
	RTN rtn = TRACE_Rtn(trace);
	IMG img = IMG_FindByAddress(TRACE_Address(trace));
	UINT32 imgId = IMG_Id(img);
	string RtnName = "";
	if(RTN_Valid(rtn))
		RtnName = PIN_UndecorateSymbolName(RTN_Name(rtn), UNDECORATION_NAME_ONLY);
	else
		RtnName = "InvalidRTN";
	// 遍历Trace中的所有BBL
	for (BBL bbl = TRACE_BblHead (trace); BBL_Valid (bbl); bbl = BBL_Next (bbl) )
	{
		//考虑到可能陷入其中一个BBL的死循环，所以对INS插桩
		//BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)BBLTimeControl, IARG_END);
		fprintf(p_outBBL, "BBL %x\n", ++indexBBL);
		fprintf(p_outBBL, "%d %s\n", imgId, RtnName.c_str());
		for (INS ins= BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
		{
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)INSTimeControl, IARG_END);//检查是否超时

			//针对指令流相关记录处理和插装
			//if (!IMG_Valid(img) || !IMG_IsMainExecutable(img))
			if (!IMG_Valid(img))
			{
				break;
			}

			string dis = INS_Disassemble(ins);

			int index = dis.find(' ');
			string opcode;
			if (index == string::npos)
			{
				opcode = dis;
			}
			else
			{
				opcode.assign(dis.c_str(), index);
			}

			char *opcode_str = new char[opcode.length()+1];
			char *oper_str = new char[dis.length()+1];
			strcpy(opcode_str, opcode.c_str());
			strcpy(oper_str, dis.c_str());

			//fprintf(p_ins_mid_file, "%s\n", dis.c_str());
			fprintf(p_outBBL, "0x%08x %s\n", INS_Address(ins), oper_str);

			//INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)INSLog, IARG_PTR, oper_str, IARG_END);
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)INSOpcodeLog, IARG_PTR, opcode_str, IARG_END);//记录操作码频率

			index = dis.find("0x");
			while (index != string::npos && opcode != "ret" && opcode[0]!='j' && opcode != "call")
			{
				if (dis[index - 1] == ' ')
				{
					string left;
					UINT imm;
					left.assign(dis, index, dis.length()-index);

					sscanf(left.c_str(), "%x", &imm);

					INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)INSImmLog, IARG_PTR, opcode_str, IARG_UINT32, imm, IARG_END);//记录立即数
				}

				index = dis.find("0x", index+1);
			}

		}
		fprintf(p_outBBL, "0\n");
		BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)RecordProcess, IARG_UINT32, indexBBL, IARG_END);//记录BBL的执行顺序
	}
}

void ImageLoad(IMG img, VOID *v)
{
	if(IMG_Valid(img))
		fprintf(p_outImg, "%4d 0x%08x 0x%08x %s\n", IMG_Id(img), IMG_LowAddress(img), IMG_HighAddress(img), IMG_Name(img).c_str());
}

VOID RecordRtnCount(CONTEXT *ctxt,RTN_COUNT *rc){
	rc->_rtnCount++;
	//ADDRINT *esp=reinterpret_cast<ADDRINT *>(PIN_GetContextReg(ctxt,REG_STACK_PTR));
	ADDRINT esp=PIN_GetContextReg(ctxt,REG_STACK_PTR);
	ADDRINT ebp=PIN_GetContextReg(ctxt,REG_EBP);
	//cout << rc->_name<<endl;
	if (!strcmp(rc->_name.c_str(),"read"))
	{
		//printf("ESP:%p,%p\n",esp,&esp);
		cout << "ESP:"<< hex  <<esp << endl;
		cout << "EBP:"<< hex  << ebp << endl;
		ADDRINT *addr = (ADDRINT *)esp;
		cout << hex << *(addr+1) << endl;
	}
}

void Routine(RTN rtn, VOID *v){
	RTN_COUNT * rc = new RTN_COUNT;
	//rc->_name = RTN_Name(rtn);
	rc->_name = PIN_UndecorateSymbolName(RTN_Name(rtn), UNDECORATION_NAME_ONLY);
	rc->_imgId = IMG_Id(SEC_Img(RTN_Sec(rtn)));
	rc->_address = RTN_Address(rtn);
	rc->_rtnCount = 0;
	rc->_rtn = rtn;
	rc->_next = RtnList;
	RtnList = rc;

	RTN_Open(rtn);
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)RecordRtnCount,IARG_CONST_CONTEXT, IARG_PTR, rc, IARG_END);
	RTN_Close(rtn);
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
	string command = "rd /q/s " + log_dir;
	system(command.c_str());

	//计算并生成日志目录
	command = "mkdir " + log_dir;
	system(command.c_str());

	//addtional record

	string ins_imm_file = log_dir + "ins_immediate.fw";
	string ins_opcode_file = log_dir + "ins_opcode.fw";


	string image_file = log_dir + name + "_image_list.fw";
	string bbl_file = log_dir + name + "_bbl_list.fw";
	string process_file = log_dir + name + "_process.fw";
	string routine_file = log_dir + name + "_routine.fw";

	p_ins_imm_file = fopen(ins_imm_file.c_str(), "w");
	p_ins_opcode_file = fopen(ins_opcode_file.c_str(), "w");


	p_outImg = fopen(image_file.c_str(), "w");
	p_outBBL = fopen(bbl_file.c_str(), "w");
	p_outProcess = fopen(process_file.c_str(), "w");
	p_outRoutine = fopen(routine_file.c_str(), "w");

	if ( p_ins_imm_file == NULL || p_ins_opcode_file == NULL || p_outBBL == NULL || p_outImg == NULL || p_outProcess == NULL || p_outRoutine == NULL)
	{
		cout << "Ins log file not open!" << endl;
		return -1;
	}


	//记录当前时间
	g_time_begin = time(0);

	//添加对Trace翻译的功能函数
	TRACE_AddInstrumentFunction(Trace, 0);
	IMG_AddInstrumentFunction(ImageLoad, 0);
	//RTN_AddInstrumentFunction(Routine, 0);
	RTN_AddInstrumentFunction(Routine,0);

	PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram();

    return 0;
}

