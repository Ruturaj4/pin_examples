#include <iostream>
#include "pin.H"
#include <fstream>
#include <string>
#include <list>
#include <boost/algorithm/string.hpp>
#include <unordered_map>
#include <exception>

//#define RPB_DEBUG // comment out to disable rbp debugging
// #define DISASS_DEBUG // comment out to disable disassembly debugging

// key to detect the main Routine
static uint32_t key = 0;

// List of blocks
std::list<struct Block> Blocks;

// Owner infomation of each location
class InsInfo
{
private:
  ADDRINT address;
  std::string owner;
public:
  InsInfo(ADDRINT address, std::string owner) { this->address = address; this->owner = owner;}
  ADDRINT get_address() {return address;}
  std::string get_owner() {return owner;}
};

// Actual process stack on which all the objects are located
class ObjInfo
{
private:
  // Location from the base pointer and the upper bound
  int64_t ub;
  // Data Type
  std::string type;
  // Object Type
  std::string obj;
  // Object name
  std::string owner;
  // Object size
  int64_t obj_size;
  // lower bound
  int64_t lb;
public:
  ObjInfo(int64_t ub, std::string type, std::string obj, string owner, int64_t obj_size)
  {
    this->ub = ub;
    this->type = type;
    this->obj = obj;
    this->owner = owner;
    this->obj_size = obj_size;
    // Lower bounds calculated here
    this->lb = ub - obj_size;
  }
  int64_t get_ub() {return ub;}
  std::string get_type() {return type;}
  std::string get_obj() {return obj;}
  std::string get_owner() {return owner;}
  int64_t get_obj_size() {return obj_size;}
  int64_t get_lb() {return lb;}
};

// A structure to store all the file related information
struct Block
{
  // Block name
  std::string name;
  // Allocated stack size
  uint64_t size;
  // Set the rbp value for the particular block
  uint64_t rbp_value;
  // Actual variable stack
  std::unordered_map <std::string, ObjInfo*> objinfostack;
  // static code locations
  std::unordered_map <ADDRINT, InsInfo*> inscodestack;
};

// rbp value Check
VOID rpb_check(uint64_t addr, CONTEXT * ctxt, Block &i, std::string disassins)
{
  if (addr > 0x700000000000)
    return;
  #ifdef DISASS_DEBUG
  std::cout<<std::hex<<addr<<"\t"<<disassins<<dec<<std::endl;
  #endif
  // Set the rbp value for the particular function.
  // Check if the rbp value is 0 which is equivalent to either return or unset
  // If rbp value is changed other than 0 for the function give an error
  if (i.rbp_value == PIN_GetContextReg(ctxt, REG_RBP))
  {
    #ifdef RPB_DEBUG
    std::cout << hex << "rbp: " << i.rbp_value << '\n';
    #endif
  }
  else if (i.rbp_value == 0)
  {
    #ifdef RPB_DEBUG
    std::cout << "return: " << i.rbp_value << '\n';
    #endif
  }
  else
  {
    std::cout << "RBP is changed(!) to: " << i.rbp_value << '\n';
  }
}

// set the value of rbp after detecting using sub rsp, xx instruction
VOID rbp_set(uint64_t addr, CONTEXT * ctxt, Block &i, std::string disassins)
{
  #ifdef RPB_DEBUG
  std::cout << "rbp set: " << i.rbp_value << '\n';
  std::cout << "rbp_routine name: " << i.name << '\n';
  #endif
  // set the rbp value -- This value will stay same throughout the function
  i.rbp_value = PIN_GetContextReg(ctxt, REG_RBP);
  // #ifdef RPB_DEBUG
  std::cout << hex << "rbp set: " << i.rbp_value << dec << '\n';
  // #endif
}
// Pin calls this function every time a new instruction is encountered
VOID Instruction(INS ins, VOID *v)
{
    // First check if the routine is valid
    if (RTN_Valid(RTN_FindByAddress(INS_Address(ins))))
    {
      // Find the current routine
      for(std::list<struct Block>::iterator i = Blocks.begin(); i!=Blocks.end(); ++i)
      {
        // Returns the name of the block -- e.g. main, foo
        if (RTN_Name(RTN_FindByAddress(INS_Address(ins))) == i->name);
          //std::cout << "RTN: " << RTN_Name(RTN_FindByAddress(INS_Address(ins))) << '\n';
          // Continue if the routine is not found
        else
          continue;

        #ifdef RPB_DEBUG
        std::cout << "rbp: " << i->rbp_value << '\n';
        #endif

        // Detect the mov rbp, rsp instruction
        if (INS_Opcode(ins) == XED_ICLASS_MOV && (INS_OperandReg(ins,0) == REG_RBP))
        {
          std::cout << "ins disass: " << INS_Disassemble(ins) << '\n';
          INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)rbp_set, IARG_ADDRINT,
          INS_Address(ins), IARG_CONTEXT, IARG_PTR, &(*i), IARG_PTR, new string(INS_Disassemble(ins)), IARG_END);
        }
        // Detect sub rbp, rsp instruction
        // if (REG_is_stackptr_type(INS_OperandReg(ins, 0)))
        // {
        //   INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)rbp_set, IARG_ADDRINT,
        //   INS_Address(ins), IARG_CONTEXT, IARG_PTR, i, IARG_PTR, new string(INS_Disassemble(ins)), IARG_END);
        // }
        // Detect the return instruction
        if (INS_IsRet(ins))
        {
          #ifdef RPB_DEBUG
          std::cout << "Return instruction detected" << '\n';
          #endif
          // Make rbp 0 before each return
          i->rbp_value = 0;
          INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)rpb_check, IARG_ADDRINT,
          INS_Address(ins), IARG_CONTEXT, IARG_PTR, &(*i), IARG_PTR, new string(INS_Disassemble(ins)), IARG_END);
        }

        // Detect all memory store instructions (check only fro rbp and not rsp)
        if ((INS_Opcode(ins) == XED_ICLASS_MOV) && INS_OperandIsMemory(ins, 0)
        && ((INS_OperandWidth(ins, 0) == 32)
            || (INS_OperandWidth(ins, 0) == 64))
        && ((INS_OperandMemoryBaseReg(ins, 0) == REG_RBP)
        || (INS_OperandMemoryBaseReg(ins, 0) == REG_EBP)))
        {
        // skip if the address is over 0x700000000000
        if (INS_Address(ins) > 0x700000000000)
      		return;
        // Check if the rbp is not changed
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)rpb_check, IARG_ADDRINT,
        INS_Address(ins), IARG_CONTEXT, IARG_PTR, &(*i), IARG_PTR, new string(INS_Disassemble(ins)), IARG_END);
        // std::cout << "Mem dispacement: " << abs(INS_MemoryDisplacement(ins)) << '\n';
        // std::cout << hex <<INS_Address(ins)<< "\t" << string(INS_Disassemble(ins)) << dec << '\n';
        // Get the owner for the particular static address
        std::cout << "BLock name: " << i->name << "\n";
        std::cout << i->inscodestack[INS_Address(ins)]->get_owner() << '\n';
        std::string owner = i->inscodestack[INS_Address(ins)]->get_owner();
        // Now check if the owner has correct stack access, i.e. if the owner is accessible
        // this can be used to validate, otherwise it leads to seg fault
        auto iter = i->objinfostack.find(owner);
        if ( iter != i->objinfostack.end());
        else
          break;
        std::cout << "Owner:: " << i->objinfostack[owner]->get_owner() << '\n';
        std::cout << "Input file is invalid" << '\n';
        // Check if the address really has an owner: (this is equivalent to pass in python)
        //while (i->inscodestack[INS_Address(ins)]);
        // Get The lower and upper bounds
        std::cout << "Upper bounds: " << i->objinfostack[owner]->get_ub() << '\n';
        std::cout << "Lower bounds: " << i->objinfostack[owner]->get_lb() << '\n';
        // If the type is array and the access is not within the bounds
        // If rsp is to be detected and rsp + x is equivalent to ebp - (rsp + x)
        if ((abs(INS_MemoryDisplacement(ins)) > i->objinfostack[owner]->get_ub() ||
        abs(INS_MemoryDisplacement(ins)) < i->objinfostack[owner]->get_lb()) &&
        i->objinfostack[owner]->get_obj() == "array")
        std::cout << "Boundover accessed by " << owner << '\n';
        }
      }
    }
}

// This function is called when the application exits
VOID Fini(INT32 code, VOID *v)
{
}

INT32 Usage()
{
    cerr << "This tool counts the number of dynamic instructions executed" << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

void readInput(char *filename)
{
  std::string line;
  std::ifstream myfile(filename);
  if (myfile.is_open())
  {
    // Get the count of the total number of blocks
    getline (myfile,line);
    int64_t count = atoi(line.c_str());
    // Ignore newline after the count
    getline (myfile,line);
    while (count)
    {
      // Initialize the structure
      Block block;
      // for the function name
      getline (myfile,line);
      block.name = line;
      // for the stack size
      getline (myfile,line);
      block.size = atoi(line.c_str());
      block.rbp_value = 0;
      while ( getline (myfile,line) )
      {
        if (line.empty())
        {
            break;
        }
        else
        {
          std::vector<std::string> temp;
          boost::split(temp, line, boost::is_any_of("\t "));
          block.inscodestack.insert(std::make_pair(strtol(temp[0].c_str(), NULL, 16), new InsInfo(strtol(temp[0].c_str(), NULL, 16), temp[1])));
          //std::cout << "temp[1]: " << hex <<strtol(temp[0].c_str(), NULL, 16) << '\n';
        }
      }
      while ( getline (myfile,line) )
      {
        if (line.empty())
        {
            break;
        }
        else
        {
          std::vector<std::string> temp;
          boost::split(temp, line, boost::is_any_of("\t "));
          //ObjInfo *objinfo = new ObjInfo {atoi(temp[0].c_str()), temp[1], temp[2], temp[3], atoi(temp[4].c_str())};
          block.objinfostack.insert(std::make_pair(temp[3], new ObjInfo(atoi(temp[0].c_str()), temp[1], temp[2], temp[3], atoi(temp[4].c_str()))));
        }
      }
      Blocks.push_front(block);
      --count;
    }
    myfile.close();
  }
  else std::cout << "Unable to open file\n";
}

// Lock Routines
void mutex_lock()
{
  key = 0;
  //std::cout<<"out\n";
}
void mutex_unlock()
{
	key = 1;
	//std::cout<<"in\n";
}

void Image(IMG img, VOID *v)
{
  RTN mainrtn = RTN_FindByName(img, "main");
  if (RTN_Valid(mainrtn))
    {
        std::cout << "Routine " << RTN_Name(mainrtn)<< '\n';
        RTN_Open(mainrtn);
        // Apply the locks to the main routine
        RTN_InsertCall(mainrtn, IPOINT_BEFORE, (AFUNPTR)mutex_unlock, IARG_END);
        RTN_InsertCall(mainrtn, IPOINT_AFTER, (AFUNPTR)mutex_lock, IARG_END);
        RTN_Close(mainrtn);
    }
}

int main(int argc, char * argv[])
{
    // Initialize pin
    PIN_InitSymbols();
    if (PIN_Init(argc, argv)) return Usage();
    // Argv[7] is the name of the input file
    readInput(argv[7]);
    // Register Instruction to be called to instrument instructions
    INS_AddInstrumentFunction(Instruction, 0);

    // Image instrumentation
    IMG_AddInstrumentFunction(Image, 0);

    // Register Fini to be called when the application exits
    PIN_AddFiniFunction(Fini, 0);

    // Start the program, never returns
    PIN_StartProgram();

    return 0;
}
