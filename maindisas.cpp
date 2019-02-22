/*******************

Author: Ruturaj Kiran vaidya
Advisor: Dr. Kulkarni

*******************/

#include <fstream>
#include <iostream>
#include "pin.H"

// Additional library calls go here

/*********************/

// Output file object
ofstream OutFile;

//static uint64_t counter = 0;

uint32_t lock = 0;

void printmaindisas(uint64_t addr, std::string disassins)
{
	if (lock == 1)
	{
		// Don't print the instructions which are in the memory	
		if (addr > 0x700000000000)
			return;
		std::cout<<std::hex<<addr<<"\t"<<disassins<<std::endl;	
	
	}
}

void mutex_lock()
{

lock = 0;
std::cout<<"out";

}
void mutex_unlock()
{

lock = 1;
std::cout<<"in";

}

void Routine(RTN rtn, VOID *V)

{
	if (RTN_Name(rtn) == "main")
	{
		std::cout<<"Loading: "<<RTN_Name(rtn) << endl;
		RTN_Open(rtn);
		// Take a lock before the routine
		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)mutex_unlock, IARG_END);
		// Take a lock after the routine
		RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)mutex_lock, IARG_END);
		RTN_Close(rtn);
	}
}

void Instruction(INS ins, VOID *v)
{
	// Insert a call to docount before every instruction, no arguments are passed
	INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)printmaindisas, IARG_ADDRINT, INS_Address(ins),
	IARG_PTR, new string(INS_Disassemble(ins)), IARG_END);
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
  // It must be called for image instrumentation
  // Initialize the symbol table
  PIN_InitSymbols();
  
  // Initialize pin
  if (PIN_Init(argc, argv)) return Usage();
  // Open the output file to write
  OutFile.open(KnobOutputFile.Value().c_str());

  // Set instruction format as intel
  PIN_SetSyntaxIntel();

  RTN_AddInstrumentFunction(Routine, 0);
  //IMAGE_AddInstrumentFunction(Image, 0);
 
  // Add an isntruction instrumentation
  INS_AddInstrumentFunction(Instruction, 0);

  //PIN_AddFiniFunction(Fini, 0);

  // Start the program here
  PIN_StartProgram();

  return 0;

}
