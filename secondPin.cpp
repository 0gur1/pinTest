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

	if(p_outRegister != NULL){
		fclose(p_outRegister);
		p_outRegister = NULL;
	}
	
}


//ÿ��INSִ��ʱ������Ƿ��Ѿ���ʱ
//����INS�Ǳ�����BBL�ڽ���ѭ��������Ҳ�����ٶ�һ��ָ��ȴ���Ӧ�������龰��
//Ŀǰ�����ʽ�Ǹ����ⲿ��ֹ����������û������Fini������
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

/*Trace��װ����*/
VOID Trace (TRACE trace, VOID *v)
{
	//���ڿ��Ƴ���ִ��ʱ��
	RTN rtn = TRACE_Rtn(trace);
	IMG img = IMG_FindByAddress(TRACE_Address(trace));
	UINT32 imgId = IMG_Id(img);
	UINT8 retFlag=0;

	// ����Trace�е�����BBL
	if (imgId == imgID)
		for (BBL bbl = TRACE_BblHead (trace); BBL_Valid (bbl); bbl = BBL_Next (bbl) )
		{
			//���ǵ�������������һ��BBL����ѭ�������Զ�INS��׮
			if(BBL_Address(bbl)==addr)
			{
				for (INS ins= BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
				{
					//INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)INSTimeControl, IARG_END);//����Ƿ�ʱ
					if(INS_IsRet(ins))
						retFlag=1;
					INS_InsertCall(ins, IPOINT_BEFORE,(AFUNPTR)RecordRtnRegister,IARG_CONST_CONTEXT,IARG_ADDRINT,retFlag,IARG_END);
				}
			}
			
		}
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
	//string command = "rd /q/s " + log_dir;
	//system(command.c_str());

	//���㲢������־Ŀ¼
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


	//��¼��ǰʱ��
	g_time_begin = time(0);

	imgID = KnobImgID.Value();
	addr = KnobBBLAddr.Value();
	esp_offset = KnobESPOFF.Value();
	printf("%d\t%d\t%d\n",imgID,addr,esp_offset);

	//��Ӷ�Trace����Ĺ��ܺ���
	TRACE_AddInstrumentFunction(Trace, 0);
	//IMG_AddInstrumentFunction(ImageLoad, 0);


	PIN_AddFiniFunction(Fini, 0);
	PIN_StartProgram();

	return 0;
}
