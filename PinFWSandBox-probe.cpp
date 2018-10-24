#pragma once
#include "pin.H"

#include <iostream>
#include <string>
#include <map>
#include <ctime>
#include <fstream>
#include <stdlib.h>
#include <assert.h>
#include <pthread.h>

//#include "FWSandBox.h"

using std::cerr;
namespace WINDOWS
{
#include <windows.h>
}
//设定最大时间，超时退出程序执行Fini
#define MAX_LIMIT_SECONDS 10

#define MAX_ITERATION 5
//记录StartProgram的时间
long g_time_begin = 0;

//主沙箱类
//CFWSandBox g_fw_sand_box;

//FILE *p_ins_imm_file = NULL;//记录实际执行指令流中常量信息
//FILE *p_ins_opcode_file = NULL;//记录实际执行指令流中操作码信息
FILE *p_outImg = NULL;
//FILE *p_outBBL = NULL;
//FILE *p_outProcess = NULL;
FILE *p_outRoutine = NULL;
//ofstream p_outImg;
//ofstream p_outRoutine;
ofstream TraceFile;
PIN_LOCK lock;
FILE *log_fd;

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

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "o", "reattach_probed_tool.out", "specify file name");
	
KNOB<LEVEL_BASE::BOOL> KnobUniqueTraceFile(KNOB_MODE_WRITEONCE, "pintool",
    "uniq", "0", "unique trace file name");
//PIN默认函数写法
INT32 Usage()
{
    cerr << "This tool prints out the number of dynamically executed " << endl <<
            "instructions, basic blocks and threads in the application." << endl << endl;

    cerr << KNOB_BASE::StringKnobSummary() << endl;

    return -1;
}

//PIN默认函数写法，Fini用于在程序退出时进行处理
int unload_count=0;
VOID fini(IMG img,void *Arg)
{
	cout << "[+]Fini" << endl;
	if(unload_count > 0)
	{
		unload_count++;
		return;
	}
	unload_count++;
	
	/*if (p_ins_imm_file != NULL)
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
	}*/
	if(p_outImg != NULL){
		/*p_outImg.close();*/
		fclose(p_outImg);
		p_outImg = NULL;
	}
	if(p_outRoutine != NULL){
		/*p_outRoutine << "RoutineName" << "   Image" << " Address"<<"   Calls";
		p_outRoutine.flush();*/
		fprintf(p_outRoutine, "%s %8s %8s %8s\n", "RoutineName", "Image", "Address", "Calls");
		fflush(p_outRoutine);
		for(RTN_COUNT *rc = RtnList; rc; rc = rc->_next){
			if(rc->_rtnCount > 0){
				/*p_outRoutine << rc->_name.c_str() << " "<<rc->_imgId<<" "<<rc->_address<<" "<<rc->_rtnCount<<endl;
				p_outRoutine.flush();*/
				fprintf(p_outRoutine, "%s %d %08x %d\n", rc->_name.c_str(), rc->_imgId, rc->_address, rc->_rtnCount);
				fflush(p_outRoutine);
			}
		}
		/*p_outImg.close();*/
		fclose(p_outRoutine);
		p_outRoutine = NULL;
	}
	TraceFile.close();
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
//VOID INSImmLog(char *opcode, UINT imm)
//{
//	fprintf(p_ins_imm_file, "%s_%x ", opcode, imm);
//}
//
//VOID RecordProcess(UINT32 IndexBBL)
//{
//	fprintf(p_outProcess,"BBL %x\n",IndexBBL);
//}

/*Trace插装函数*/
//VOID Trace (TRACE trace, VOID *v)
//{
//	//用于控制程序执行时间
//	RTN rtn = TRACE_Rtn(trace);
//	IMG img = IMG_FindByAddress(TRACE_Address(trace));
//	UINT32 imgId = IMG_Id(img);
//	string RtnName = "";
//	if(RTN_Valid(rtn))
//		RtnName = PIN_UndecorateSymbolName(RTN_Name(rtn), UNDECORATION_NAME_ONLY);
//	else
//		RtnName = "InvalidRTN";
//	// 遍历Trace中的所有BBL
//	for (BBL bbl = TRACE_BblHead (trace); BBL_Valid (bbl); bbl = BBL_Next (bbl) )
//	{
//		//考虑到可能陷入其中一个BBL的死循环，所以对INS插桩
//		//BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)BBLTimeControl, IARG_END);
//		fprintf(p_outBBL, "BBL %x\n", ++indexBBL);
//		fprintf(p_outBBL, "%d %s\n", imgId, RtnName.c_str());
//		for (INS ins= BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
//		{
//			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)INSTimeControl, IARG_END);//检查是否超时
//
//			//针对指令流相关记录处理和插装
//			//if (!IMG_Valid(img) || !IMG_IsMainExecutable(img))
//			if (!IMG_Valid(img))
//			{
//				break;
//			}
//
//			string dis = INS_Disassemble(ins);
//
//			int index = dis.find(' ');
//			string opcode;
//			if (index == string::npos)
//			{
//				opcode = dis;
//			}
//			else
//			{
//				opcode.assign(dis.c_str(), index);
//			}
//
//			char *opcode_str = new char[opcode.length()+1];
//			char *oper_str = new char[dis.length()+1];
//			strcpy(opcode_str, opcode.c_str());
//			strcpy(oper_str, dis.c_str());
//
//			//fprintf(p_ins_mid_file, "%s\n", dis.c_str());
//			fprintf(p_outBBL, "0x%08x %s\n", INS_Address(ins), oper_str);
//
//			//INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)INSLog, IARG_PTR, oper_str, IARG_END);
//			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)INSOpcodeLog, IARG_PTR, opcode_str, IARG_END);//记录操作码频率
//
//			index = dis.find("0x");
//			while (index != string::npos && opcode != "ret" && opcode[0]!='j' && opcode != "call")
//			{
//				if (dis[index - 1] == ' ')
//				{
//					string left;
//					UINT imm;
//					left.assign(dis, index, dis.length()-index);
//
//					sscanf(left.c_str(), "%x", &imm);
//
//					INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)INSImmLog, IARG_PTR, opcode_str, IARG_UINT32, imm, IARG_END);//记录立即数
//				}
//
//				index = dis.find("0x", index+1);
//			}
//
//		}
//		fprintf(p_outBBL, "0\n");
//		BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)RecordProcess, IARG_UINT32, indexBBL, IARG_END);//记录BBL的执行顺序
//	}
//}

bool Sanity(IMG img, RTN rtn)
{
    if ( PIN_IsProbeMode() &&  !RTN_IsSafeForProbe(rtn) &&! RTN_IsSafeForProbedInsertion( rtn ) )
    {
		TraceFile << "Cannot insert calls around " << RTN_Name(rtn) <<
            "() in " << IMG_Name(img) << endl;
        //exit(1);
		return false;
    }
	else
		TraceFile << RTN_Name(rtn) <<
            "in " << IMG_Name(img) <<"can be inserted"<< endl;
	return true;
}
VOID RecordRtnCount(RTN_COUNT * rc){//UINT32 * count
	rc->_rtnCount++;
	//cout << rc->_name << ","<<rc->_rtnCount<<endl;
	//if(rc->_rtnCount>1)
	//{
	//    char* tmp = (char *)malloc(1024);

	//	fseek(p_outRoutine,0,SEEK_SET);
	//	ftell(p_outRoutine);
	//	int num = fread(tmp,1,256,p_outRoutine);
	//	//cout << num<<endl;
	//	while(num>0)
	//	{
	//		//cout << tmp;
	//		char* pos = strstr(tmp,rc->_name.c_str());
	//		cout << pos;
	//		if (pos)
	//		{
	//			char buf[256];
	//			sprintf(buf,"%s %d %08x %d\n",rc->_name.c_str(),rc->_imgId,rc->_address,rc->_rtnCount);
	//			memcpy(pos,buf,strlen(buf));
	//			fseek(p_outRoutine,0-num,SEEK_CUR);
	//			ftell(p_outRoutine);
	//			fwrite(tmp,1,num,p_outRoutine);
	//			fflush(p_outRoutine);
	//			//cout <<tmp;
	//			break;
	//		}
	//		 num = fread(tmp,1,256,p_outRoutine);
	//	}
	//	fseek(p_outRoutine,0,SEEK_END);
	//	ftell(p_outRoutine);
	//	free(tmp);
	//	tmp=0;
	//}
	//else
	{
	
		fprintf(p_outRoutine, "%s %d %08x %d\n", rc->_name.c_str(), rc->_imgId, rc->_address, rc->_rtnCount);
		fflush(p_outRoutine);
	}
}
void ImageLoad(IMG img, VOID *v)
{
	if(IMG_Valid(img))
	{

		fprintf(p_outImg, "%4d 0x%08x 0x%08x %s\n", IMG_Id(img), IMG_LowAddress(img), IMG_HighAddress(img), IMG_Name(img).c_str());
		fflush(p_outImg);

		/*if(!IMG_IsMainExecutable(img))
		{
			cout <<IMG_Name(img).c_str()<< " not main executable img " << endl;
			return ;
		}*/

		//!strcmp(IMG_Name(img).c_str(),"C:\\WINDOWS\\SYSTEM32\\ntdll.dll") ||
		if( !strcmp(IMG_Name(img).c_str(),"C:\\WINDOWS\\System32\\msvcrt.dll")
			|| !strcmp(IMG_Name(img).c_str(),"C:\\WINDOWS\\System32\\KERNEL32.DLL")
			|| !strcmp(IMG_Name(img).c_str(),"C:\\WINDOWS\\System32\\KERNELBASE.dll"))
		{
			return;
		}
		cout <<IMG_Name(img).c_str() << endl;

		for (SEC sec=IMG_SecHead(img);SEC_Valid(sec);sec=SEC_Next(sec))
		{
			if(SEC_IsExecutable(sec))
			{
				for(RTN rtn = SEC_RtnHead(sec);RTN_Valid(rtn);rtn = RTN_Next(rtn))
				{
					//cout <<"rtn:"<<RTN_Name(rtn) <<endl;
					//if(!strcmp(RTN_Name(rtn).c_str(),".text") || !strcmp(RTN_Name(rtn).c_str(),"_chkesp")  || !strcmp(RTN_Name(rtn).c_str(),"_adj_fpatan") ||!strcmp(RTN_Name(rtn).c_str(),"RtlAllocateWnfSerializationGroup")||!strcmp(RTN_Name(rtn).c_str(),"ZwMapViewOfSection"))
						//continue;
					if(Sanity(img,rtn))
					{

						RTN_COUNT * rc = new RTN_COUNT;
						rc->_name = PIN_UndecorateSymbolName(RTN_Name(rtn), UNDECORATION_NAME_ONLY);
						rc->_imgId = IMG_Id(SEC_Img(RTN_Sec(rtn)));
						rc->_address = RTN_Address(rtn);
						rc->_rtnCount = 0;
						rc->_rtn = rtn;
						rc->_next = RtnList;
						RtnList = rc;
					
					
						//RTN_Open(rtn);
						RTN_InsertCallProbed(rtn, IPOINT_BEFORE, (AFUNPTR)RecordRtnCount, IARG_PTR, rc, IARG_END);//&(rc->_rtnCount)
						//RTN_Close(rtn);
					}
					
				}
			}
		}
	}
	else
	{
		/*p_outImg << "invalid\n";
		p_outImg.flush();*/
		fprintf(p_outImg, "invalid\n");
		fflush(p_outImg);
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
	RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)RecordRtnCount, IARG_PTR, &(rc->_rtnCount), IARG_END);
	RTN_Close(rtn);
}



/* ===================================================================== */




/*
 * Main function for re-attach
 */
VOID AttachMain(VOID *arg);


/* Session control checks that there is no callbacks mix between different 
 * attach-detach iterations
 */
class SESSION_CONTROL
{
  public:
    SESSION_CONTROL():_currentIteration(0), 
        _threadCounter(0),
        _startAttachSession(FALSE),
        _startDetachSession(FALSE) 
    {}

    static VOID ApplicationStart(VOID *v);
    static VOID AttachedThreadStart(VOID *sigmask, VOID *v);
    static WINDOWS::DWORD WINAPI DedicatedThread(VOID *arg);

    VOID StartIteration(LEVEL_BASE::UINT32 it) { _currentIteration = it; _threadCounter = 0;}
    LEVEL_BASE::UINT32 CurrentIteration() { return _currentIteration; }
    bool GotFirstThreadNotification(LEVEL_BASE::UINT32 it)
    {
        return ((it == _currentIteration) && (_threadCounter > 0));
    }
    static SESSION_CONTROL* Instance() { return &m_instance; }
    VOID StartDetach() 
    { 
        _startDetachSession = TRUE; 
        _startAttachSession = FALSE; 
    }
    VOID StartAttach() 
    { 
        _startAttachSession = TRUE; 
        _startDetachSession = FALSE; 
    }
    VOID WaitForDetach() //{ while (!_startDetachSession)  WINDOWS::Sleep(1000); }
	{ 
		char buf[2]={'\x00'};
		char flag[2]={'0','\x00'};
		//fread(buf,1,1,fd);

		while (!_startDetachSession || strcmp(buf,flag))
		{
			log_fd= fopen("log.txt","r");
			fread(buf,1,1,log_fd);
			WINDOWS::Sleep(1000);
			fclose(log_fd);
			WINDOWS::Sleep(1000);
		}
	}
    VOID WaitForAttach() //{ while (!_startAttachSession)  WINDOWS::Sleep(1000); }
	{ 
		char buf[2]={'\x00'};
		char flag[2]={'1','\x00'};
		//fread(buf,1,1,fd);

		while (!_startAttachSession || strcmp(buf,flag))
		{
			log_fd= fopen("log.txt","r");
			fread(buf,1,1,log_fd);
			WINDOWS::Sleep(1000);
			fclose(log_fd);
			WINDOWS::Sleep(1000);
		}
	}
  private:
    UINT32 _currentIteration;
    UINT32 _threadCounter;
    volatile BOOL _startAttachSession;
    volatile BOOL _startDetachSession;
    static SESSION_CONTROL m_instance;
};

SESSION_CONTROL SESSION_CONTROL::m_instance;

SESSION_CONTROL *SessionControl() { return SESSION_CONTROL::Instance(); }

/* Detach session 
 * Callbacks and function replacements
 */
class DETACH_SESSION
{
  public:
    DETACH_SESSION()  {}
	// Detach completion notification 
    static VOID DetachCompleted(VOID *v);
    static VOID ImageLoad(IMG img, void *v);
    static VOID ImageUnload(IMG img, void *v);
   
    static DETACH_SESSION* Instance() { return &m_instance; }
  private:
    static DETACH_SESSION m_instance;
};

DETACH_SESSION DETACH_SESSION::m_instance;

DETACH_SESSION* DtSession() { return DETACH_SESSION::Instance(); }

/* Reattach session */
class REATTACH_SESSION
{
  public:
    REATTACH_SESSION() {}
    static VOID ImageLoad(IMG img, void *v);
    static VOID ImageUnload(IMG img, void *v);
    static VOID ApplicationStart(VOID *v);
    static VOID AttachedThreadStart(VOID *sigmask, VOID *v);
	static BOOL IsAttachCompleted();
	
    static REATTACH_SESSION* Instance() { return &m_instance; }
  private:
    static REATTACH_SESSION m_instance;
};

REATTACH_SESSION REATTACH_SESSION::m_instance;

REATTACH_SESSION* AtSession() { return REATTACH_SESSION::Instance(); }

/*
 * Pin-tool detach-completed callback
 * Called from Pin
 */
VOID DETACH_SESSION::DetachCompleted(VOID *arg)
{
	cout << "DetachCompleted" << endl;
	unsigned long detachIteration = (unsigned long)arg;
    if (detachIteration != SessionControl()->CurrentIteration())
    {
        cerr << "Detach iteration error: Expected " << SessionControl()->CurrentIteration()
            << " Rececived " << detachIteration << " In DetachCompleted" << endl;
        exit(-1);
    }
    PIN_GetLock(&lock, PIN_GetTid());
    TraceFile << "Detach session " << detachIteration << " Detach completed; tid = "
	         << PIN_GetTid() << endl;
	
    fprintf(stderr, "Iteration %lu completed\n",detachIteration);
    //cerr << "Iteration " << detachIteration << " completed." << endl;
	if (detachIteration == MAX_ITERATION)
	{
        TraceFile <<  "TEST PASSED" << endl;
		TraceFile.close();
        exit(0);
	}
	PIN_ReleaseLock(&lock);
	
    WINDOWS::Sleep(1000);
    SessionControl()->StartAttach();
}

/* 
 *Image load callback for the first Pin session
 */
VOID DETACH_SESSION::ImageLoad(IMG img, void *arg)
{
    unsigned long detachIteration = (unsigned long)arg;
    if (detachIteration != SessionControl()->CurrentIteration())
    {
        cerr << "Detach iteration error: Expected " << SessionControl()->CurrentIteration()
            << " Received " << detachIteration << " In ImageLoad" << endl;
        exit(-1);
    }

    PIN_GetLock(&lock, PIN_GetTid());
	TraceFile << "Load image " << IMG_Name(img) << endl;
	PIN_ReleaseLock(&lock);
}
VOID DETACH_SESSION::ImageUnload(IMG img, void *arg)
{
    unsigned long detachIteration = (unsigned long)arg;
    if (detachIteration != SessionControl()->CurrentIteration())
    {
        cerr << "Detach iteration error: Expected " << SessionControl()->CurrentIteration()
            << " Received " << detachIteration << " In ImageUnload" << endl;
        exit(-1);
    }
}
/* Application start notification in the first session */
VOID SESSION_CONTROL::ApplicationStart(VOID *arg)
{
    unsigned long iteration = (unsigned long)arg;
    if (iteration != SessionControl()->CurrentIteration())
    {
        cerr << "Iteration error: Expected " << SessionControl()->CurrentIteration()
            << " Received " << iteration << " In ApplicationStart" << endl;
        exit(-1);
    }
	
    PIN_GetLock(&lock, PIN_GetTid());
    TraceFile << "Application start notification at session " << iteration << endl;
	PIN_ReleaseLock(&lock);
    
    WINDOWS::Sleep(1000);
	if(iteration <= 1)
		SessionControl()->StartDetach();
	

}

/* Thread start notification in the first session */
VOID SESSION_CONTROL::AttachedThreadStart(VOID *sigmask, VOID *arg)
{
    unsigned long iteration = (unsigned long)arg;
    if (iteration != SessionControl()->CurrentIteration())
    {
        cerr << "Iteration error: Expected " << SessionControl()->CurrentIteration()
            << " Received " << iteration << " In AttachedThreadStart" << endl;
        exit(-1);
    }
    PIN_GetLock(&lock, PIN_GetTid());
    TraceFile << "Thread start " << ++(SessionControl()->_threadCounter) << " notification at session " << iteration << " tid " << PIN_GetTid() << endl;
	PIN_ReleaseLock(&lock);
		
}

WINDOWS::DWORD WINAPI SESSION_CONTROL::DedicatedThread(VOID *arg)
{
    static ADDRINT reattachIteration = 2;
    while (1)
    {
        SessionControl()->WaitForDetach();
        PIN_GetLock(&lock, PIN_GetTid());
        TraceFile << "Pin tool: sending detach request" << endl;
        PIN_ReleaseLock(&lock);
		//cout << "prepare to detach" << endl;
        PIN_DetachProbed();

        SessionControl()->WaitForAttach();
        PIN_GetLock(&lock, PIN_GetTid());
        TraceFile << "Pin tool: sending attach request" << endl;
        PIN_ReleaseLock(&lock);
		PIN_AttachProbed(AttachMain, (VOID *)reattachIteration++);
    }
    return 0;
}


/* 
 *Image load callback for the second Pin session
 */
VOID REATTACH_SESSION::ImageLoad(IMG img, void *arg)
{
    unsigned long reattachIteration = (unsigned long)arg;
    if (reattachIteration != SessionControl()->CurrentIteration())
    {
        cerr << "Iteration error: Expected " << SessionControl()->CurrentIteration()
            << " Received " << reattachIteration << " In ImageLoad" << endl;
        exit(-1);
    }
	PIN_GetLock(&lock, PIN_GetTid());
	TraceFile << "Load image " << IMG_Name(img) << endl;
	PIN_ReleaseLock(&lock);
}

VOID REATTACH_SESSION::ImageUnload(IMG img, void *arg)
{
    unsigned long reattachIteration = (unsigned long)arg;
    if (reattachIteration != SessionControl()->CurrentIteration())
    {
        cerr << "Iteration error: Expected " << SessionControl()->CurrentIteration()
            << " Received " << reattachIteration << " In ImageUnload" << endl;
        exit(-1);
    }
}

/* Return TRUE if the tool is notified about app start */
bool REATTACH_SESSION::IsAttachCompleted()
{
    return SessionControl()->GotFirstThreadNotification(2);
}

VOID AttachMain(VOID *arg)
{
    LEVEL_BASE::UINT32 reattachIteration = *(reinterpret_cast <LEVEL_BASE::UINT32 *> (&arg));
    SessionControl()->StartIteration(reattachIteration);
	
    PIN_GetLock(&lock, PIN_GetTid());
    TraceFile << "Re-attach session start, inside AttachMain; iteration " << reattachIteration << endl;
    PIN_ReleaseLock(&lock);

	PIN_AddApplicationStartFunction(SESSION_CONTROL::ApplicationStart, arg);
	
	//PIN_AddThreadAttachProbedFunction(SESSION_CONTROL::AttachedThreadStart,arg);
	IMG_AddInstrumentFunction(ImageLoad, 0);
	//IMG_AddUnloadFunction(fini,0);
	//IMG_AddInstrumentFunction(REATTACH_SESSION::ImageLoad, arg);

	//记录当前时间
	g_time_begin = time(0);

    return;

    
}
	
/* ===================================================================== */
int main(int argc,LEVEL_BASE::CHAR *argv[])
{
    PIN_InitSymbols();

    PIN_Init(argc,argv);
	
	PIN_InitLock(&lock);
	
	
    SessionControl()->StartIteration(1);
    
    PIN_AddDetachFunctionProbed(DETACH_SESSION::DetachCompleted, (VOID *)1);
    PIN_AddApplicationStartFunction(SESSION_CONTROL::ApplicationStart, (VOID *)1);
	//PIN_AddThreadAttachFunction(SESSION_CONTROL::AttachedThreadStart,(VOID *)1);
	//PIN_AddThreadAttachProbedFunction(SESSION_CONTROL::AttachedThreadStart,(VOID *)1);

	//日志目录和系统调用函数信息目录
	string work_dir = argv[argc-1];
	int index = work_dir.rfind("\\");

	if (index == string::npos)
	{
		cout << "work_dir error! " << work_dir << endl;
		return 0;
	}

	string name;
	//assign：从work_dir的第index+1位开始读取到后缀名之前的内容为name 
	name.assign(work_dir, index+1, work_dir.length()-index-5);

	//work_dir为路径 
	work_dir.assign(work_dir, 0, index);
	//计算并设置工作目录到目标文件的平行目录，避免相对路径读取引发的问题
	//WINDOWS::SetCurrentDirectory(work_dir.c_str());

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
	//string ins_mid_file = log_dir  +  name + "_d_ins_mid.fw";
	/*string ins_imm_file = log_dir + "ins_immediate.fw";
	string ins_opcode_file = log_dir + "ins_opcode.fw";
*/
	string image_file = log_dir + name + "_image_list.fw";
	/*string bbl_file = log_dir + name + "_bbl_list.fw";
	string process_file = log_dir + name + "_process.fw";*/
	string routine_file = log_dir + name + "_routine.fw";
	string traceFileName = log_dir + name + "_detach_attach.fw";


	TraceFile.open(traceFileName.c_str());

	/*p_ins_imm_file = fopen(ins_imm_file.c_str(), "w");
	p_ins_opcode_file = fopen(ins_opcode_file.c_str(), "w");
*/
	/*p_outImg.open(image_file.c_str());
	p_outRoutine.open(routine_file.c_str());*/
	p_outImg = fopen(image_file.c_str(), "w");
	//p_outBBL = fopen(bbl_file.c_str(), "w");
	//p_outProcess = fopen(process_file.c_str(), "w"); p_ins_imm_file == NULL || p_ins_opcode_file == NULL || p_outBBL == NULL ||p_outProcess == NULL ||
	p_outRoutine = fopen(routine_file.c_str(), "wb+");

	/*if (  !p_outImg.is_open() || ! p_outRoutine.is_open()|| !TraceFile.is_open() )
	{
		cout << "Ins log file not open!" << endl;
		return -1;
	}*/
	/*p_outRoutine << "RoutineName" << "   Image" << " Address"<<"   Calls"<<endl;;
	p_outRoutine.flush();*/
	fprintf(p_outRoutine, "%s %8s %8s %8s\n", "RoutineName", "Image", "Address", "Calls");
	fflush(p_outRoutine);

	//PIN_AddFiniFunction(Fini, 0);
	
	WINDOWS::HANDLE handle = WINDOWS::CreateThread(NULL,0,SESSION_CONTROL::DedicatedThread,NULL,0,NULL);
    
    PIN_StartProgramProbed();
	
    return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
