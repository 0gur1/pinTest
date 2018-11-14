#include "pin.H"
#include <iostream>
#include <string>
#include <map>
#include <ctime>
namespace WINDOWS{
   #include <windows.h>
}

//�趨���ʱ�䣬��ʱ�˳�����ִ��Fini
#define MAX_LIMIT_SECONDS 60

//��¼StartProgram��ʱ��
long g_time_begin = 0;


//FILE *p_ins_mid_file = NULL;//��¼�������ָ������Ϣ
//FILE *p_ins_real_file = NULL;//��¼ʵ��ִ�е�ָ������Ϣ
FILE *p_ins_imm_file = NULL;//��¼ʵ��ִ��ָ�����г�����Ϣ
FILE *p_ins_opcode_file = NULL;//��¼ʵ��ִ��ָ�����в�������Ϣ
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

map<string, UINT> g_opcode_count;//��¼opcodeƵ��

KNOB<string> KnobLogPath(KNOB_MODE_WRITEONCE,  "pintool",
    "lp", "", "log path");

//PINĬ�Ϻ���д��
INT32 Usage()
{
    cerr << "This tool prints out the number of dynamically executed " << endl <<
            "instructions, basic blocks and threads in the application." << endl << endl;

    cerr << KNOB_BASE::StringKnobSummary() << endl;

    return -1;
}

//PINĬ�Ϻ���д����Fini�����ڳ����˳�ʱ���д���
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


//ÿ��INSִ��ʱ������Ƿ��Ѿ���ʱ
//����INS�Ǳ�����BBL�ڽ���ѭ��������Ҳ�����ٶ�һ��ָ��ȴ���Ӧ�������龰��
//Ŀǰ�����ʽ�Ǹ����ⲿ��ֹ����������û������Fini������
VOID INSTimeControl()
{
	long cur_time = time(0);
	if (cur_time - g_time_begin > MAX_LIMIT_SECONDS)
	{
		cout << "Time limit " <<  MAX_LIMIT_SECONDS << "s exceed! Now is: " << cur_time - g_time_begin << "s!" << endl;
		PIN_ExitApplication(0);
	}
}



//��¼opcodeƵ��
VOID INSOpcodeLog(char *opcode)
{
	string opcode_s = opcode;
	g_opcode_count[opcode_s] ++;
}

//��¼��������Ϣ
VOID INSImmLog(char *opcode, UINT imm)
{
	fprintf(p_ins_imm_file, "%s_%x ", opcode, imm);
}

VOID RecordProcess(UINT32 IndexBBL)
{
	fprintf(p_outProcess,"BBL %x\n",IndexBBL);
}

/*Trace��װ����*/
VOID Trace (TRACE trace, VOID *v)
{
	//���ڿ��Ƴ���ִ��ʱ��
	RTN rtn = TRACE_Rtn(trace);
	IMG img = IMG_FindByAddress(TRACE_Address(trace));
	UINT32 imgId = IMG_Id(img);
	string RtnName = "";
	if(RTN_Valid(rtn))
		RtnName = PIN_UndecorateSymbolName(RTN_Name(rtn), UNDECORATION_NAME_ONLY);
	else
		RtnName = "InvalidRTN";
	// ����Trace�е�����BBL
	for (BBL bbl = TRACE_BblHead (trace); BBL_Valid (bbl); bbl = BBL_Next (bbl) )
	{
		//���ǵ�������������һ��BBL����ѭ�������Զ�INS��׮
		//BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)BBLTimeControl, IARG_END);
		fprintf(p_outBBL, "BBL %x\n", ++indexBBL);
		fprintf(p_outBBL, "%d %s\n", imgId, RtnName.c_str());
		for (INS ins= BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
		{
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)INSTimeControl, IARG_END);//����Ƿ�ʱ

			//���ָ������ؼ�¼����Ͳ�װ
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
			INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)INSOpcodeLog, IARG_PTR, opcode_str, IARG_END);//��¼������Ƶ��

			index = dis.find("0x");
			while (index != string::npos && opcode != "ret" && opcode[0]!='j' && opcode != "call")
			{
				if (dis[index - 1] == ' ')
				{
					string left;
					UINT imm;
					left.assign(dis, index, dis.length()-index);

					sscanf(left.c_str(), "%x", &imm);

					INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)INSImmLog, IARG_PTR, opcode_str, IARG_UINT32, imm, IARG_END);//��¼������
				}

				index = dis.find("0x", index+1);
			}

		}
		fprintf(p_outBBL, "0\n");
		BBL_InsertCall(bbl, IPOINT_BEFORE, (AFUNPTR)RecordProcess, IARG_UINT32, indexBBL, IARG_END);//��¼BBL��ִ��˳��
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
	
	//��־Ŀ¼��ϵͳ���ú�����ϢĿ¼
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
	//assign����work_dir�ĵ�index+1λ��ʼ��ȡ����׺��֮ǰ������Ϊname 
	name.assign(work_dir, index+1, work_dir.length()-index-5);

	cout << name << endl;
	//work_dirΪ·�� 
	work_dir.assign(work_dir, 0, index);
	cout << work_dir << endl;
	//���㲢���ù���Ŀ¼��Ŀ���ļ���ƽ��Ŀ¼���������·����ȡ����������
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

	//���㲢������־Ŀ¼
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


	//��¼��ǰʱ��
	g_time_begin = time(0);

	//��Ӷ�Trace����Ĺ��ܺ���
	TRACE_AddInstrumentFunction(Trace, 0);
	IMG_AddInstrumentFunction(ImageLoad, 0);
	//RTN_AddInstrumentFunction(Routine, 0);
	RTN_AddInstrumentFunction(Routine,0);

	PIN_AddFiniFunction(Fini, 0);
    PIN_StartProgram();

    return 0;
}

