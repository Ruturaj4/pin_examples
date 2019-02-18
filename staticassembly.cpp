#include <fstream>
#include <iostream>
#include "pin.H"

//Optional
//ofstream OutFile;

void Instruction(INS ins, VOID *v)
{
	// prints the static binary assembly instructions
	std::cout<<std::hex<<INS_Address(ins)<<" : " << INS_Disassemble(ins).c_str()<<"\n";
}

//KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "mytool.out", "specify output file name");

int32_t Usage()
{
  cerr << "This is my custom tool" << endl;
  cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
  return -1;
}

int main(int argc, char * argv[])
{
  //PIN_InitSymbols();
  if (PIN_Init(argc, argv)) return Usage();

  //OutFile.open(KnobOutputFile.Value().c_str());
  PIN_SetSyntaxIntel();
  INS_AddInstrumentFunction(Instruction, 0);

  // Start the program here
  PIN_StartProgram();

  return 0;

}
