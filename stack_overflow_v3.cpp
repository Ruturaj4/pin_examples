#include <iostream>
#include <cstdlib>
#include <fstream>
#include "pin.H"
#include <unordered_map>
#include <stack>

// To enable debugging
#define ENABLE_DEBUG

// key to open the main Routine
static uint32_t key = 0;

// To save the malloc area
struct mallocArea
{
  UINT64  base;
  UINT64  size;
  BOOL    status;
};

// Main stack to store the stack size
struct Node
{
	// Total stack size allocated
	uint64_t value;
	// Upper limit
	uint64_t cu;
	// Lower limit
	uint64_t cl;
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
VOID protect(uint64_t addr)
{
  if (addr > 0x700000000000)
		return;
	if (!key)
		return;
  // Initialize the diassembled instruction
  string insdis = insstack[addr]->get_insDis();
  INS ins = insstack[addr]->get_ins();

	// If the function is returned then pop the value off the stack
	if (INS_Opcode(ins) == XED_ICLASS_LEAVE && mainStack.size() >= 2)
	{
		std::cout << hex << "Popping out: " << mainStack.top().value << '\n';
		mainStack.pop();
		std::cout << hex <<"stack top: " << mainStack.top().value << " as leaving" << '\n';
	}
	// instructions executed in the main routine
  //std::cout << hex <<addr << "\t" << insdis << std::endl;
}

VOID bounds_detection(uint64_t addr)
{

  if (addr > 0x700000000000)
		return;
	if (!key)
		return;
  std::cout << "Access over allowed bounds detected!" << '\n';
}

VOID stack_size(uint64_t addr, CONTEXT * ctxt)
{
	if (addr > 0x700000000000)
		return;
	if (!key)
		return;
	// Get the corresponsing instruction to print
	string insdis = insstack[addr]->get_insDis();
	// Print stack and base pointer registers
	std::cout << hex << "Reg::" << PIN_GetContextReg(ctxt, REG_RSP) << '\n';
	std::cout << hex << "Reg::" << PIN_GetContextReg(ctxt, REG_RBP) << '\n';

	// MPX mpx takes the total size size as a upper bound for the last allocated array
	// We don't know the individual array bounds
	// We will define rsp as lower bound and rbp as the upper bound
	// Total stack size
	uint64_t value = PIN_GetContextReg(ctxt, REG_RBP) - PIN_GetContextReg(ctxt, REG_RSP);
	Node node{value, PIN_GetContextReg(ctxt, REG_RBP), PIN_GetContextReg(ctxt, REG_RSP)};
	mainStack.push(node);
	std::cout << hex << "Pushed the value: " << dec << node.value << " on the stack" << '\n';
}

// Pin calls this function every time a new instruction is encountered
VOID Instruction(INS ins, VOID *v)
{
    // #ifdef ENABLE_DEBUG
    //   std::cerr << "getUserInput() called\n";
    // #endif
		// if (INS_Address(ins) > 0x700000000000)
		// return;
    insstack.insert(std::make_pair(INS_Address(ins), new Insr(string(INS_Disassemble(ins)),
    ins)));
    // if (REG_valid_for_iarg_reg_value(INS_MemoryIndexReg(ins)))
    //   std::cout << "true" << '\n';
		if((INS_Opcode(ins) == XED_ICLASS_ADD || INS_Opcode(ins) == XED_ICLASS_SUB) &&
		   REG(INS_OperandReg(ins, 0)) == REG_STACK_PTR && INS_OperandIsImmediate(ins, 1))
		{
			INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)stack_size, IARG_ADDRINT, INS_Address(ins),
			IARG_CONTEXT,
	  IARG_END);
		  // Obtain the immediate operand information as shown above.
		  // You can obtain the RSP register value before or after the instruction by
		  // passing IARG_REG_VALUE, REG_STACK_PTR to INS_Insert*.
		}
//##########################################################
    if ((INS_Opcode(ins) == XED_ICLASS_MOV) && INS_OperandIsMemory(ins, 0)
      && ((INS_OperandWidth(ins, 0) == 32)
          || (INS_OperandWidth(ins, 0) == 64))
      && ((INS_OperandMemoryBaseReg(ins, 0) == REG_RBP)
      || (INS_OperandMemoryBaseReg(ins, 0) == REG_EBP)
      || (INS_OperandMemoryBaseReg(ins, 0) == REG_RSP)
      || (INS_OperandMemoryBaseReg(ins, 0) == REG_ESP)))
      {
        if (INS_Address(ins) > 0x700000000000)
      		return;
        if (INS_MemoryDisplacement(ins) >= 0
        && ((INS_OperandMemoryBaseReg(ins, 0) == REG_RBP)
        || (INS_OperandMemoryBaseReg(ins, 0) == REG_EBP)))
        {
          INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)bounds_detection, IARG_ADDRINT,
          INS_Address(ins), IARG_END);
        }
        else if (INS_MemoryDisplacement(ins) < 0
        && ((INS_OperandMemoryBaseReg(ins, 0) == REG_RSP)
        || (INS_OperandMemoryBaseReg(ins, 0) == REG_ESP)))
        {
          INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)bounds_detection, IARG_ADDRINT,
          INS_Address(ins), IARG_END);
        }
        else
        {
          std::cout << hex << INS_Address(ins) << "\t" << INS_Disassemble(ins) << std::endl;
          if (abs(INS_MemoryDisplacement(ins)) >= static_cast<int64_t>(mainStack.top().value))
            std::cout << hex<<"Overflow detected: " << INS_MemoryDisplacement(ins) << ":"
            << mainStack.top().value << "\t" << INS_Disassemble(ins) <<'\n';
        }
      }

    if ((INS_Opcode(ins) == XED_ICLASS_MOV) && INS_OperandIsMemory(ins, 1)
  		&& ((INS_OperandWidth(ins, 1) == 32)
  				|| (INS_OperandWidth(ins, 1) == 64))
  		&& ((INS_OperandMemoryBaseReg(ins, 1) == REG_RBP)
  		|| (INS_OperandMemoryBaseReg(ins, 1) == REG_EBP)
  		|| (INS_OperandMemoryBaseReg(ins, 1) == REG_RSP)
  		|| (INS_OperandMemoryBaseReg(ins, 1) == REG_ESP)))
      {
        if (INS_Address(ins) > 0x700000000000)
      		return;
        // Check for array bounds
        if (INS_MemoryDisplacement(ins) >= 0
        && ((INS_OperandMemoryBaseReg(ins, 1) == REG_RBP)
        || (INS_OperandMemoryBaseReg(ins, 1) == REG_EBP)))
        {
          INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)bounds_detection, IARG_ADDRINT,
          INS_Address(ins), IARG_END);
        }
        else if (INS_MemoryDisplacement(ins) < 0
        && ((INS_OperandMemoryBaseReg(ins, 1) == REG_RSP)
        || (INS_OperandMemoryBaseReg(ins, 1) == REG_ESP)))
        {
          INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)bounds_detection, IARG_ADDRINT,
          INS_Address(ins), IARG_END);
        }
        else
        {
          std::cout << hex << INS_Address(ins) << "\t" << INS_Disassemble(ins) << std::endl;
          std::cout << "Store: " << abs(INS_MemoryDisplacement(ins)) << '\n';
          if (abs(INS_MemoryDisplacement(ins)) >= static_cast<int64_t>(mainStack.top().value))
            std::cout << hex<<"Overflow detected: " << INS_MemoryDisplacement(ins) << ":"
            << mainStack.top().value << "\t" << INS_Disassemble(ins) <<'\n';
        }
      }
//##########################################################
		INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)protect, IARG_ADDRINT, INS_Address(ins),
	IARG_END);
    // Insert a call to docount before every instruction, no arguments are passed
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

VOID malloc_before(CHAR * name, ADDRINT size)
{
	if (!key)
		return;
	std::cout << name << "(" << size << ")" << '\n';
}

VOID malloc_after(ADDRINT ret)
{
	if (!key)
		return;
	std::cout << "\treturns " << ret << '\n';
}

VOID free_before(CHAR * name, ADDRINT size)
{
	if (!key)
		return;
	std::cout << name << "(" << size << ")" << '\n';
}

void Image(IMG img, VOID *v)
{
	// Find the malloc function
	RTN mallocRtn = RTN_FindByName(img, "malloc");
	// Find the free() function.
	RTN freeRtn = RTN_FindByName(img, "free");

    if (RTN_Valid(mallocRtn))
    {
        RTN_Open(mallocRtn);

        // Instrument malloc() to print the input argument value and the return value.
        RTN_InsertCall(mallocRtn, IPOINT_BEFORE, (AFUNPTR)malloc_before,
                       IARG_ADDRINT, "malloc",
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                       IARG_END);
        RTN_InsertCall(mallocRtn, IPOINT_AFTER, (AFUNPTR)malloc_after,
                       IARG_FUNCRET_EXITPOINT_VALUE, IARG_END);

        RTN_Close(mallocRtn);
    }

    if (RTN_Valid(freeRtn))
    {
        RTN_Open(freeRtn);
        // Instrument free() to print the input argument value.
        RTN_InsertCall(freeRtn, IPOINT_BEFORE, (AFUNPTR)free_before,
                       IARG_ADDRINT, "free",
                       IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                       IARG_END);
        RTN_Close(freeRtn);
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

    // Image instrumentation
    IMG_AddInstrumentFunction(Image, 0);

    // Register Instruction to be called to instrument instructions
    INS_AddInstrumentFunction(Instruction, 0);

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}
