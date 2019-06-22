#include <iostream>
#include "pin.H"
#include <fstream>
#include <string>
#include <list>
#include <boost/algorithm/string.hpp>
#include <unordered_map>
#include <exception>

// TODOs can be searched with ----> TODO:

// #define RPB_DEBUG // comment out to disable rbp debugging
// #define RBP_DETECTION // comment out to disable rbp detection
// #define DISASS_DEBUG // comment out to disable disassembly debugging

// key to detect the main Routine
static uint32_t key = 0;

// Map containing Blocks
// The keys are function name and the values are blocks per function
// std::list<struct Block> Blocks;
std::unordered_map <std::string, struct Block*> blocks;

// access bounds
class AccessBounds
{
private:
  uint64_t base;
  uint64_t bound;
public:
  AccessBounds(uint64_t base, uint64_t bound){this->base = base; this->bound = bound;}
  uint64_t get_base(){return base;}
  uint64_t get_bound(){return bound;}
};

// Map to store all bound information globally
// key: owner
std::unordered_map <std::string, AccessBounds*> accessboundsmap;

// Stucture holds the control flow information
class RegisterBlock
{
private:
  // -32
  int64_t stack_pos;
  // Actual value
  int64_t value = -1;
public:
  RegisterBlock(int64_t stack_pos, int64_t value)
  {
    this->stack_pos = stack_pos;
    this-> value = value;
  }
  void set_stack_pos(int64_t stack_pos)
  {
    this->stack_pos = stack_pos;
  }
  void set_value(int64_t value)
  {
    this->value = value;
  }
  int64_t get_stack_pos()
  {
    return stack_pos;
  }
  int64_t get_value()
  {
    return value;
  }
};

// position relative to the rbp
class RelPos
{
private:
  // value present at the particular location on the stack
  int64_t value;
  // Owner
  std::string owner;
  // other info such as owner can be added here
public:
  RelPos(int64_t value, std::string owner){this->value = value; this->owner = owner;}
  void set_val(int64_t value){this->value = value;}
  void set_owner(int64_t owner){this->owner = owner;}
  int64_t get_value(){return value;}
  std::string get_owner(){return owner;}
};

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

// Contains the information of all the objects
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
    this->lb = ub + obj_size;
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
  // Set the rsp value for the particular block
  uint64_t rsp_value;
  // Stucture to store control flow block information
  // TODO: update this per control flow block
  std::unordered_map <std::string, RegisterBlock*> registerblock;
  // Object information hash map
  std::unordered_map <std::string, ObjInfo*> objinfostack;
  // static code locations hash map
  std::unordered_map <ADDRINT, InsInfo*> inscodestack;
  // Actual stack (positions related to rbp) hash map
  std::unordered_map <uint64_t, RelPos*> relPosStack;
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

// This sets up rbp and rsp values and sets the size of the stack for the corresponding block
VOID reg_val_set(uint64_t addr, CONTEXT * ctxt, Block &i, std::string disassins)
{
  std::cout << "rbp val: " << PIN_GetContextReg(ctxt, REG_RBP) << '\n';
  // set the rbp value -- This value will stay same throughout the function
  i.rbp_value = PIN_GetContextReg(ctxt, REG_RBP);
  std::cout << "rsp val: " << PIN_GetContextReg(ctxt, REG_RSP) << '\n';
  // set the rsp value -- This value will stay same throughout the function
  i.rsp_value = PIN_GetContextReg(ctxt, REG_RSP);
  // Set the stack size
  i.size = i.rbp_value - i.rsp_value;
}

// mov  DWORD PTR [rbp-0x20],0x1
VOID mov_immediate(uint64_t addr, CONTEXT * ctxt, Block &i, std::string disassins,
  std::string owner, int64_t displacement, int64_t immediate)
{
  // Now check if the owner has correct stack access, i.e. if the owner is accessible
  // this can be used to validate, otherwise it leads to a seg fault
  auto iter = i.objinfostack.find(owner);
  if ( iter == i.objinfostack.end())
  {
      std::cout << "Check your input!" << '\n';
      std::exit(1);
  }
  // if the value is already in the map
  // TODO: see if this is really required
  // TODO: Effective address = Displacement + BaseReg + IndexReg * Scale
  uint64_t effective_dispacement = i.rbp_value + displacement;
  std::cout << "effective dispacement: " << effective_dispacement << '\n';
  if(i.relPosStack.find(effective_dispacement) != i.relPosStack.end())
  {
    // Set the value of immediate at the particular stack position
    i.relPosStack[effective_dispacement]->set_val(immediate);
  }
  else
  {
    // set the value and the owner
    // There is no need of the absolute value, as the stack can grow both ways
    i.relPosStack.insert(std::make_pair(effective_dispacement, new RelPos(immediate, owner)));
  }
  /* This part can actually be deleted or make bound check enabled*/
  // Check if the address really has an owner: (this is equivalent to pass in python)
  //while (i->inscodestack[INS_Address(ins)]);
  // Get The lower and upper bounds
  std::cout << "Upper bounds: " << i.objinfostack[owner]->get_ub() << '\n';
  std::cout << "Lower bounds: " << i.objinfostack[owner]->get_lb() << '\n';
  // If the type is array and the access is not within the bounds
  // If rsp is to be detected and rsp + x is equivalent to ebp - (rsp + x)
  if ((effective_dispacement < i.objinfostack[owner]->get_ub() + i.rbp_value ||
  effective_dispacement > i.objinfostack[owner]->get_lb() + i.rbp_value) &&
  i.objinfostack[owner]->get_obj() == "array")
  std::cout << "Boundover accessed by " << owner << '\n';
}

// lea  rax,[rbp-0x20]
VOID lea_inreg(uint64_t addr, CONTEXT * ctxt, Block &i, std::string disassins,
  int64_t displacement, REG reg)
{
  std::cout << "reg val: " << hex << PIN_GetContextReg(ctxt, reg) << '\n';
  std::cout<< hex <<addr<<"\t"<<disassins<<dec<<std::endl;
  // std::cout << i->inscodestack[INS_Address(ins)]->get_owner() << '\n';
  std::cout << "disas: " << hex << disassins << dec << '\n';
  // move that value in the
  // INS_MemoryDisplacement(ins) gives the location of the stack and then
  // get_value() gives the value at that particular location of the stack
  // register used in the instruction
  std::string insreg = REG_StringShort(reg);
  // Let the register structure hold the location on the stack for the particular register
  // and not the value
  // set the Register with the apporpriate value
  // I made a map, using which we can work with any register
  if(i.registerblock.find(insreg) != i.registerblock.end())
  {
    // TODO: Check if the register value needs to be set everytime
    i.registerblock[insreg]->set_stack_pos(i.rbp_value + displacement);
  }
  else
  {
    // Setting the register value -1, as for now
    i.registerblock.insert(std::make_pair(insreg, new RegisterBlock(i.rbp_value + displacement, i.rbp_value + displacement)));
  }
}

// mov  QWORD PTR [rbp-0x8],rax
VOID mov_reg(uint64_t addr, CONTEXT * ctxt, Block &i, std::string disassins,
  std::string owner, int64_t displacement, REG reg)
{
  // Get the register value
  std::string insreg = REG_StringShort(reg);
  // TODO: temporary
  if (insreg == "eax")
    insreg = "rax";
  // TODO: temporary
  if (insreg == "edi")
    return;
  if (insreg == "rsi")
    return;
  std::cout << "disas: " << hex << disassins << dec << '\n';
  // set the value of of the pos stack if the owner is a pointer
  // TODO: Check is needed here - to check whether the register value is available in the
  // structure as a key - maybe look for other places for the same
  if(i.relPosStack.find(i.rbp_value + displacement) != i.relPosStack.end())
  {
    i.relPosStack[i.rbp_value + displacement]->set_val(i.registerblock[insreg]->get_stack_pos());
  }
  else
  {
    // set the value and the owner
    // There is no need of the absolute value, as the stack can grow both ways
    i.relPosStack.insert(std::make_pair(i.rbp_value + displacement, new RelPos(i.registerblock[insreg]->get_stack_pos(), owner)));
  }
  // Check to see if the owner is a pointer
  if (i.objinfostack[owner]->get_obj() == "pointer")
  {
    // get the Register value
    // pointer is getting the address of owner_prop and hence its bounds
    std::string owner_prop = i.relPosStack[i.registerblock[insreg]->get_stack_pos()]->get_owner();
    accessboundsmap.insert(std::make_pair(owner, new AccessBounds(i.objinfostack[owner_prop]->get_lb() +
    i.rbp_value, i.objinfostack[owner_prop]->get_ub() + i.rbp_value)));
    std::cout << "lower bounds: " << accessboundsmap[owner]->get_base() <<'\n';
    std::cout << "Upper bounds: " << accessboundsmap[owner]->get_bound() <<'\n';
  }
}

// mov  rax,QWORD PTR [rbp-0x8]
VOID mov_mem_reg(uint64_t addr, CONTEXT * ctxt, Block &i, std::string disassins,
  std::string owner, int64_t displacement, REG reg)
{
  std::cout << "reg val: " << hex << PIN_GetContextReg(ctxt, reg) << '\n';
  std::cout<< hex <<addr<<"\t"<<disassins<<dec<<std::endl;
  if (i.objinfostack[owner]->get_obj() == "pointer")
  {
    std::string insreg = REG_StringShort(reg);
    i.registerblock[insreg]->set_stack_pos(i.rbp_value + displacement);
  }
}

// mov  DWORD PTR [rbp-0xc],eax
VOID mov_mem_reg_2(uint64_t addr, CONTEXT * ctxt, Block &i, std::string disassins,
  std::string owner, int64_t displacement, REG base_reg)
{
  if (i.objinfostack[owner]->get_obj() == "scalar")
  {
    // operand memory base register
    std::string opbasereg = REG_StringShort(base_reg);
    std::cout << "INS_OperandMemoryIndexReg: " << base_reg << '\n';
    // Checks can be done here
    // Get the owner
    if (i.objinfostack[i.relPosStack[i.registerblock[opbasereg]->get_stack_pos()]->get_owner()]->get_obj() == "pointer")
    {
      if (((accessboundsmap[i.relPosStack[i.registerblock[opbasereg]->get_stack_pos()]->get_owner()]->get_base() -
        i.rbp_value + displacement) > (accessboundsmap[i.relPosStack[i.registerblock[opbasereg]->get_stack_pos()]->get_owner()]->get_base())) ||
        ((accessboundsmap[i.relPosStack[i.registerblock[opbasereg]->get_stack_pos()]->get_owner()]->get_base()) - i.objinfostack[owner]->get_obj_size() -
        i.rbp_value + displacement) < accessboundsmap[i.relPosStack[i.registerblock[opbasereg]->get_stack_pos()]->get_owner()]->get_bound())
        {
            std::cout << "abort" << '\n';
        }
    }
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
  // Functin variables
  std::string opbasereg = "";
  // First check if the routine is valid
  if (!RTN_Valid(RTN_FindByAddress(INS_Address(ins))))
    return;
  // skip if the address is over 0x700000000000
  if (INS_Address(ins) > 0x700000000000)
    return;
  // Block hash map access
  // Find the current routine
  if ( blocks.find(RTN_Name(RTN_FindByAddress(INS_Address(ins)))) == blocks.end())
    return;
  struct Block *i = blocks[RTN_Name(RTN_FindByAddress(INS_Address(ins)))];
                                /* set rbp and rsp values */
  // mov rbp, rsp
  // This is so that, a function can be detected
  // If the below insturction is not detected, rsp and rbp will remain same
  // Detect sub rbp, rsp instruction - another way
  // if (REG_is_stackptr_type(INS_OperandReg(ins, 0)))
  if (INS_Opcode(ins) == XED_ICLASS_MOV && (INS_OperandReg(ins,0) == REG_RBP)
  && (INS_OperandReg(ins,1) == REG_RSP))
  {
    INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)reg_val_set, IARG_ADDRINT,
    INS_Address(ins), IARG_CONTEXT, IARG_PTR, &(*i), IARG_PTR, new string(INS_Disassemble(ins)), IARG_END);
  }
  if((INS_Opcode(ins) == XED_ICLASS_ADD || INS_Opcode(ins) == XED_ICLASS_SUB)
    &&(INS_OperandIsImmediate(ins, 1)) && (INS_OperandReg(ins,0) == REG_RSP))
  {
    INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)reg_val_set, IARG_ADDRINT,
    INS_Address(ins), IARG_CONTEXT, IARG_PTR, &(*i), IARG_PTR, new string(INS_Disassemble(ins)), IARG_END);
  }
                                        /* END */
                                        /* Get the owner */
  // Get the owner for the particular static address
  std::string owner;
  if ( i->inscodestack.find(INS_Address(ins)) == i->inscodestack.end())
  {
    // An exeption can be called here
    return;
  }
  else
  {
    owner = i->inscodestack[INS_Address(ins)]->get_owner();
  }
                                                    /* END */
  // Returns the name of the block
  // std::cout << "RTN: " << RTN_Name(RTN_FindByAddress(INS_Address(ins))) << '\n';
  #ifdef RPB_DEBUG
  std::cout << "rbp: " << i->rbp_value << '\n';
  #endif
  #ifdef RBP_DETECTION
  // Detect the mov rbp, rsp instruction
  // This is so that, a function can be detected
  if (INS_Opcode(ins) == XED_ICLASS_MOV && (INS_OperandReg(ins,0) == REG_RBP))
  {
    INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)rbp_set, IARG_ADDRINT,
    INS_Address(ins), IARG_CONTEXT, IARG_PTR, &(*i), IARG_PTR, new string(INS_Disassemble(ins)), IARG_END);
  }
  #endif
  // Detect the return instruction
  // For rbp detection
  // This can be done after the end of a particular function - but not needed as the
  // values of rbp and rsp are specific to the function and not global
  #ifdef RBP_DETECTION
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
  #endif

              /**** Detection of instructions starts here ****/

  // Detect all memory store instructions (check only fro rbp and not rsp)
  // Array bounds check - not related to the softbounds technique
  // But it protects the array overflow
  // DWORD PTR [rbp-0x20],0x1
  if ((INS_Opcode(ins) == XED_ICLASS_MOV) && INS_OperandIsMemory(ins, 0)
  && ((INS_OperandWidth(ins, 0) == 32)
      || (INS_OperandWidth(ins, 0) == 64))
  && ((INS_OperandMemoryBaseReg(ins, 0) == REG_RBP)
  || (INS_OperandMemoryBaseReg(ins, 0) == REG_EBP))
  && INS_OperandIsImmediate(ins, 1))
  {
    // Check if the rbp is not changed
    #ifdef RBP_DETECTION
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)rpb_check, IARG_ADDRINT,
    INS_Address(ins), IARG_CONTEXT, IARG_PTR, &(*i), IARG_PTR, new string(INS_Disassemble(ins)), IARG_END);
    #endif

    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)mov_immediate, IARG_ADDRINT,
    INS_Address(ins), IARG_CONTEXT, IARG_PTR, &(*i), IARG_PTR, new string(INS_Disassemble(ins)),
      IARG_PTR, new string(owner), IARG_ADDRINT, INS_OperandMemoryDisplacement(ins, 0),
      IARG_ADDRINT, INS_OperandImmediate(ins, 1), IARG_END);
  }

  // If the owner is a pointer
  // First check for the load instruction in the register
  // This will assume that the register will be used in future
  if ((INS_Opcode(ins) == XED_ICLASS_LEA) && (INS_OperandIsReg(ins, 0)) &&
    INS_HasExplicitMemoryReference(ins))
  {
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)lea_inreg, IARG_ADDRINT,
    INS_Address(ins), IARG_CONTEXT, IARG_PTR, &(*i), IARG_PTR, new string(INS_Disassemble(ins)),
      IARG_ADDRINT, INS_MemoryDisplacement(ins), IARG_UINT32, REG(INS_OperandReg(ins, 0)), IARG_END);
  }

  // If operand is a register - mov QWORD PTR [rbp-0x8],rax
  if ((INS_Opcode(ins) == XED_ICLASS_MOV) && INS_OperandIsMemory(ins, 0)
  && ((INS_OperandWidth(ins, 0) == 32)
      || (INS_OperandWidth(ins, 0) == 64))
  && ((INS_OperandMemoryBaseReg(ins, 0) == REG_RBP)
  || (INS_OperandMemoryBaseReg(ins, 0) == REG_EBP))
  && INS_OperandIsReg(ins, 1))
  {
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)mov_reg, IARG_ADDRINT,
    INS_Address(ins), IARG_CONTEXT, IARG_PTR, &(*i), IARG_PTR, new string(INS_Disassemble(ins)),
      IARG_PTR, new string(owner), IARG_ADDRINT, INS_MemoryDisplacement(ins), IARG_UINT32, REG(INS_OperandReg(ins, 1)), IARG_END);
  }

  // If the pointer value is loaded
  // rax,QWORD PTR [rbp-0x8]
  if ((INS_Opcode(ins) == XED_ICLASS_MOV) && INS_OperandIsMemory(ins, 1) && INS_OperandIsReg(ins, 0)
  && ((INS_OperandWidth(ins, 1) == 32)
      || (INS_OperandWidth(ins, 1) == 64))
  && ((INS_OperandMemoryBaseReg(ins, 1) == REG_RBP)
  || (INS_OperandMemoryBaseReg(ins, 1) == REG_EBP)))
  {
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)mov_mem_reg, IARG_ADDRINT,
    INS_Address(ins), IARG_CONTEXT, IARG_PTR, &(*i), IARG_PTR, new string(INS_Disassemble(ins)),
      IARG_PTR, new string(owner), IARG_ADDRINT, INS_MemoryDisplacement(ins), IARG_UINT32, REG(INS_OperandReg(ins, 0)), IARG_END);
  }

  if ((INS_Opcode(ins) == XED_ICLASS_MOV) && INS_OperandIsMemory(ins, 1)
  && ((INS_OperandWidth(ins, 1) == 32)
      || (INS_OperandWidth(ins, 1) == 64))
  && ((INS_OperandMemoryBaseReg(ins, 1) != REG_RBP)
  && (INS_OperandMemoryBaseReg(ins, 1) != REG_EBP)))
  {
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)mov_mem_reg_2, IARG_ADDRINT,
    INS_Address(ins), IARG_CONTEXT, IARG_PTR, &(*i), IARG_PTR, new string(INS_Disassemble(ins)),
      IARG_PTR, new string(owner), IARG_ADDRINT, INS_OperandMemoryDisplacement(ins, 1),
      IARG_UINT32, REG(INS_OperandMemoryBaseReg(ins, 1)), IARG_END);
  }

  // if (i->objinfostack[owner]->get_obj() == "pointer")
  // {
  //   std::cout << hex << INS_Disassemble(ins) << dec << '\n';
  //   // if ((INS_Opcode(ins) == XED_ICLASS_MOV) && (INS_OperandIsReg(ins, 1)))
  // }

  // For control flow Blocks
  if (INS_BranchTakenPrefix(ins))
    std::cout << "!!!!!!!!!!!!!!!!!!!!!!!!!!!!" << '\n';
  if (INS_IsBranchOrCall(ins))
    std::cout << "Branch: " << hex << INS_Disassemble(ins) << dec << '\n';
  if (!INS_HasFallThrough(ins))
    std::cout<<"\nbranch!\n\n";
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
      struct Block *block = new Block;
      // for the function name
      getline (myfile,line);
      block->name = line;
      // for the stack size
      getline (myfile,line);
      block->size = atoi(line.c_str());
      block->rbp_value = 0;
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
          block->inscodestack.insert(std::make_pair(strtol(temp[0].c_str(), NULL, 16), new InsInfo(strtol(temp[0].c_str(), NULL, 16), temp[1])));
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
          block->objinfostack.insert(std::make_pair(temp[3], new ObjInfo(atoi(temp[0].c_str()), temp[1], temp[2], temp[3], atoi(temp[4].c_str()))));
        }
      }
      // // make every location zero upon initialization
      // for (uint64_t i = 0; i <= block.size; ++i)
      //   block.relPosStack.insert(std::make_pair(i, new RelPos(0)));
      blocks.insert(std::make_pair(block->name, block));
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
