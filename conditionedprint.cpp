#include <fstream>
#include <iostream>
#include "pin.H"

ofstream OutFile;

FILE * trace;

//static uint64_t counter = 0;

void docount(uint64_t addr, std::string disassins)
{
	std::cout<<std::hex<<addr<<":"<<disassins<<"\n";	
}

void Instruction(INS ins, VOID *v)
{
	if ((INS_Address(ins) >= 4195510) && (INS_Address(ins) < 4195633))
	{
	
	std::cout<<std::hex<<INS_Address(ins)<<" : " << INS_Disassemble(ins).c_str()<<"\n";
	
	}
	// Insert a call to docount before every instruction, no arguments are passed
	//INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount, IARG_ADDRINT,
	 //INS_Address(ins), IARG_PTR, new string(INS_Disassemble(ins)), IARG_END);
}

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "mytool.out", "specify output file name");
/*
VOID Fini(INT32 code, VOID *v)
{
    // Write to a file since cout and cerr maybe closed by the application
    OutFile.setf(ios::showbase);
    OutFile << "Count " << count << endl;
    OutFile.close();
}
*/

int32_t Usage()
{
  cerr << "This is my custom tool" << endl;
  cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
  return -1;
}

int main(int argc, char * argv[])
{
  PIN_InitSymbols();
  if (PIN_Init(argc, argv)) return Usage();

  OutFile.open(KnobOutputFile.Value().c_str());
  PIN_SetSyntaxIntel();
  //IMG_AddInstrumentFunction(Image, 0);
  INS_AddInstrumentFunction(Instruction, 0);
  //PIN_AddFiniFunction(Fini, 0);

  // Start the program here
  PIN_StartProgram();

  return 0;

}
