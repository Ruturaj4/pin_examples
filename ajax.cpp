#include <iostream>
#include "pin.H"
#include <fstream>
#include <string>
#include <list>
#include <boost/algorithm/string.hpp>
#include <unordered_map>

// key to detect the main Routine
static uint32_t key = 0;

int icount = 0;

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
  // Actual variable stack
  std::unordered_map <std::string, ObjInfo*> objinfostack;
  // static code locations
  std::unordered_map <ADDRINT, InsInfo*> inscodestack;
};

// This function is called before every instruction is executed
VOID docount()
{
  icount++;
}

// rbp value Check
VOID stack_size(uint64_t addr, CONTEXT * ctxt)
{
  if (addr > 0x700000000000)
    return;
  std::cout << hex << "ebp: " << PIN_GetContextReg(ctxt, REG_RBP) << '\n';
}

// Pin calls this function every time a new instruction is encountered
VOID Instruction(INS ins, VOID *v)
{
    if (RTN_Valid(RTN_FindByAddress(INS_Address(ins))))
    {
      for(std::list<struct Block>::iterator i = Blocks.begin(); i!=Blocks.end(); ++i)
      {
        if (RTN_Name(RTN_FindByAddress(INS_Address(ins))) == i->name)
        std::cout << "RTN: " << RTN_Name(RTN_FindByAddress(INS_Address(ins))) << '\n';
        // for(std::list<struct ObjInfo>::iterator j = i->objinfostack.begin(); j!=i->objinfostack.end(); ++j)
        // std::cout << j->location << '\n';
        if ((INS_Opcode(ins) == XED_ICLASS_MOV) && INS_OperandIsMemory(ins, 0)
        && ((INS_OperandWidth(ins, 0) == 32)
            || (INS_OperandWidth(ins, 0) == 64))
        && ((INS_OperandMemoryBaseReg(ins, 0) == REG_RBP)
        || (INS_OperandMemoryBaseReg(ins, 0) == REG_EBP)
        || (INS_OperandMemoryBaseReg(ins, 0) == REG_RSP)
        || (INS_OperandMemoryBaseReg(ins, 0) == REG_ESP)))
        {
        // skip if the address is over 0x700000000000
        if (INS_Address(ins) > 0x700000000000)
      		return;
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)stack_size, IARG_ADDRINT,
        INS_Address(ins), IARG_CONTEXT, IARG_END);
        std::cout << "Mem dispacement: " << abs(INS_MemoryDisplacement(ins)) << '\n';
        std::cout << hex <<INS_Address(ins)<< "\t" << string(INS_Disassemble(ins)) << dec << '\n';
        // Get the owner for the particular static address
        std::string owner = i->inscodestack[INS_Address(ins)]->get_owner();
        // Now check if the owner has correct stack access
        std::cout << "Owner:: " << i->objinfostack[owner]->get_owner() << '\n';
        // Check if the address really has an owner: (this is equivalent to pass in python)
        //while (i->inscodestack[INS_Address(ins)]);
        std::cout << "Upper bounds: " << i->objinfostack[owner]->get_ub() << '\n';
        std::cout << "Lower bounds: " << i->objinfostack[owner]->get_lb() << '\n';
        if (abs(INS_MemoryDisplacement(ins)) > i->objinfostack[owner]->get_ub() || abs(INS_MemoryDisplacement(ins)) < i->objinfostack[owner]->get_lb())
        std::cout << "Boundover accessed by " << owner << '\n';
        std::cout << "Owner: " << owner << '\n';

        }
      }
    }

    // Insert a call to docount before every instruction, no arguments are passed
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)docount, IARG_END);
}

// This function is called when the application exits
VOID Fini(INT32 code, VOID *v)
{
  std::cout << icount << '\n';
}

INT32 Usage()
{
    cerr << "This tool counts the number of dynamic instructions executed" << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

void readInput()
{
  std::string line;
  std::ifstream myfile("./test_cases/2-case.text");
  if (myfile.is_open())
  {
    // Initialize the structure
    Block block;
    // Get the count of the total number of blocks
    getline (myfile,line);
    int64_t count = atoi(line.c_str());
    // Ignore newline after the count
    getline (myfile,line);
    while (count)
    {
      // for the function name
      getline (myfile,line);
      block.name = line;
      // for the stack size
      getline (myfile,line);
      block.size = atoi(line.c_str());
      while ( getline (myfile,line) )
      {
        if (line.empty())
        {
            std::cout << "Empty line" << '\n';
            break;
        }
        else
        {
          std::vector<std::string> temp;
          boost::split(temp, line, boost::is_any_of("\t "));
          block.inscodestack.insert(std::make_pair(strtol(temp[0].c_str(), NULL, 16), new InsInfo(strtol(temp[0].c_str(), NULL, 16), temp[1])));
          std::cout << "temp[1]: " << hex <<strtol(temp[0].c_str(), NULL, 16) << '\n';
        }
      }
      while ( getline (myfile,line) )
      {
        if (line.empty())
        {
            std::cout << "Empty line" << '\n';
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
    readInput();
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
