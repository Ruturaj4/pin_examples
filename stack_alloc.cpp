#include <iostream>
#include <fstream>
#include "pin.H"
#include <unordered_map>
#include <stack>

// key to open the main Routine
static uint32_t key = 0;

// Main stack to store the stack size

struct Node
{
	int value;
	uint64_t rbp_up;
	uint64_t rsp_lb;
};

std::stack<Node> mainStack;

// Ins object mapping
class Insr
{
private:
  // Disassembled instruction
	string insDis;
  INS ins;

public:
	Insr(string insDis, INS ins) { this->insDis = insDis; this->ins = ins;}
	string get_insDis() { return insDis;}
  INS get_ins() { return ins;}
};

// Stack for the Insr structure
static std::unordered_map<ADDRINT, Insr*> insstack;

// This function is called before every instruction is executed
VOID protect(uint64_t addr, CONTEXT *ctx)
{
  if (addr > 0x700000000000)
		return;
	if (!key)
		return;
  // Initialize the diassembled instruction
  string insdis = insstack[addr]->get_insDis();
  INS ins = insstack[addr]->get_ins();

	if (INS_OperandCount(ins) > 0)
	{
		if (REG(INS_OperandReg(ins, 0)))
			std::cout << "register: " << REG_StringShort(REG(INS_OperandReg(ins, 0))) << '\n';
		std::cout << "Mnemonic: " << INS_Mnemonic(ins) << '\n';
	}
	// std::cout << "rsp::::" << hex<< PIN_GetContextReg(ctx, REG_RSP) << '\n';
	// std::cout << "rbp::::" << hex<< PIN_GetContextReg(ctx, REG_RBP) << '\n';
	// std::cout << "rax::::" << hex<< PIN_GetContextReg(ctx, REG_RAX) << '\n';
	// if (INS_Opcode(ins) == XED_ICLASS_MOV)
	// {
	// 	std::cout << REG_StringShort(INS_OperandMemoryBaseReg(ins, 0)) << ": "
	// 	<< hex << PIN_GetContextReg(ctx, INS_OperandMemoryBaseReg(ins, 0)) << '\n';
	// 	// PIN_GetContextRegval(ctx, INS_OperandMemoryBaseReg(ins, 0), );
	// }
	// MPX mpx takes the total size size as a upper bound for the last allocated array
	// We don't know the individual array bounds
	// We will define 0 as lower bound and stack size as the upper bound
  if((INS_Opcode(ins) == XED_ICLASS_ADD || INS_Opcode(ins) == XED_ICLASS_SUB)
		&& INS_OperandIsImmediate(ins, 1))
	{
	  int value = INS_OperandImmediate(ins, 1);
		Node node{value, PIN_GetContextReg(ctx, REG_RBP), PIN_GetContextReg(ctx, REG_RSP)};
		mainStack.push(node);
		std::cout << "Pushed the value: " << dec<<node.value << " on the stack" << '\n';
		std::cout << "Base pointer" << node.rbp_up << '\n';
		std::cout << "Stack pointer" << node.rsp_lb << '\n';

	}

	// If the function is returned then pop the value off the stack
	if (INS_Opcode(ins) == XED_ICLASS_LEAVE && mainStack.size() >= 2)
	{
		std::cout << "Popping out: " << mainStack.top().value << '\n';
		mainStack.pop();
		std::cout << "stack top: " << mainStack.top().value << " as leaving" << '\n';
	}

	if ((INS_Opcode(ins) == XED_ICLASS_MOV) && INS_OperandIsMemory(ins, 0)
		&& (INS_OperandWidth(ins, 0) == 32)
		&& ((INS_OperandMemoryBaseReg(ins, 0) == REG_RBP)
		|| (INS_OperandMemoryBaseReg(ins, 0) == REG_EBP)))
	{
			if (INS_MemoryDisplacement(ins) >= 0)
				std::cout << "Access over allowed bounds detected!" << '\n';
	}

	// instructions executed in the main routine
  std::cout << hex <<addr << "\t" << insdis << std::endl;
}

// Pin calls this function every time a new instruction is encountered
VOID Instruction(INS ins, VOID *v)
{
		// if (INS_Address(ins) > 0x700000000000)
		// return;
    insstack.insert(std::make_pair(INS_Address(ins), new Insr(string(INS_Disassemble(ins)),
    ins)));
    // if (REG_valid_for_iarg_reg_value(INS_MemoryIndexReg(ins)))
    //   std::cout << "true" << '\n';
    // Insert a call to docount before every instruction, no arguments are passed
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)protect, IARG_ADDRINT, INS_Address(ins),
		IARG_CONTEXT,
  IARG_END);
}

// Lock Routine
void mutex_lock()
{
key = 0;
std::cout<<"out\n";
}
void mutex_unlock()
{
	key = 1;
	std::cout<<"in\n";
}

void Routine(RTN rtn, VOID *V)
{
	if (RTN_Name(rtn) == "main")
	{
		RTN_Open(rtn);
		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)mutex_unlock, IARG_END);
		RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)mutex_lock, IARG_END);
		RTN_Close(rtn);
	}
}

INT32 Usage()
{
    cerr << "This tool counts the number of dynamic instructions executed" << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

int main(int argc, char * argv[])
{
    // Initialize the symbol table
    PIN_InitSymbols();

    // Initialize pin
    if (PIN_Init(argc, argv)) return Usage();

    PIN_SetSyntaxIntel();

    // Routine instrumentation
    RTN_AddInstrumentFunction(Routine, 0);

    // Register Instruction to be called to instrument instructions
    INS_AddInstrumentFunction(Instruction, 0);

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}
