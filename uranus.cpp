#include <iostream>
#include "pin.H"
#include <fstream>
#include <string>
#include <list>
#include <vector>
#include <unordered_map>
#include <exception>
#include <sstream>

using std::string;
using std::cerr;
using std::endl;

// Argv[6] is the program image
std::string ProgramImage;

// to string patch
namespace patch
{
    template < typename T > std::string to_string( const T& n )
    {
        std::ostringstream stm ;
        stm << n ;
        return stm.str() ;
    }
}

// implementing split function, which is analogous to the boost split function
template <typename Split>
void split(const string &s, char delim, Split result) {
    std::istringstream iss(s);
    string item;
    while (std::getline(iss, item, delim)) {
        *result++ = item;
    }
}

std::vector<string> split(const string &s, char delim) {
    std::vector<string> elems;
    split(s, delim, std::back_inserter(elems));
    return elems;
}

// Object to store the malloc/ calloc/ realloc information per allocation
class MallocMap
{
  ADDRINT size;
  bool check;
public:
  MallocMap(ADDRINT size, bool check){this->size = size; this->check=check;}
  void setsize(ADDRINT size) {this->size = size;}
  void setcheck(ADDRINT check) {this->check = check;}
  ADDRINT getsize() {return this->size;}
  bool getcheck() {return this->check;}
};

// To hold each allocation
std::map<ADDRINT, MallocMap*> mallocmap;

// instruction addresses
std::unordered_map <ADDRINT, std::string> addresses;

// argv adress pointers
std::vector<int> argv_sizes;

// access bounds
class AccessBounds
{
private:
  uint64_t base;
  uint64_t bound;
  // actual location on stack
  // this helps in pointer bounds propagation
  uint64_t location;
public:
  AccessBounds(uint64_t base, uint64_t bound, uint64_t location){this->base = base; this->bound = bound;
  this->location = location;}
  void set_base(uint64_t base){this->base = base;}
  void set_bound(uint64_t bound){this->bound = bound;}
  void set_bounds(uint64_t base, uint64_t bound){this->base = base; this->bound = bound;}
  void set_bounds(uint64_t base, uint64_t bound, uint64_t location){this->base = base; this->bound = bound;
  this->location = location;}
  uint64_t get_base(){return this->base;}
  uint64_t get_bound(){return this->bound;}
  void set_location(uint64_t location){this->location = location;}
  uint64_t get_location(){return this->location;}
};

// Map to store all bound information globally
// key: owner
std::unordered_map <std::string, AccessBounds*> accessboundsmap;

// to track dynamic pointers
// std::unordered_map <std::string, std::unordered_map <std::string, AccessBounds*>> pointermap;
std::vector<std::string> pointermap;

// contains the information of all the global objects (like data of bss section)
// no need to create a separate namespace for each variable, as the
// variables are represented as funname_variable
class GlobObjInfo
{
private:
  // Location from the base pointer and the upper bound
  int64_t ub;
  // Object Type
  std::string obj;
  // Object name
  std::string owner;
  // Object size
  int64_t obj_size;
  // lower bound
  int64_t lb;
public:
  GlobObjInfo(int64_t lb, std::string obj, string owner, int64_t obj_size)
  {
    this->lb = lb + obj_size;
    this->obj = obj;
    this->owner = owner;
    this->obj_size = obj_size;
    // Lower bounds calculated here
    this->ub = lb;
  }
  int64_t get_ub() {return ub;}
  std::string get_obj() {return obj;}
  std::string get_owner() {return owner;}
  int64_t get_obj_size() {return obj_size;}
  int64_t get_lb() {return lb;}
};

// A stack to store all the global variables
std::unordered_map <std::string, GlobObjInfo*> globalobjinfostack;

// Contains the information of all the objects
class ObjInfo
{
private:
  // Location from the base pointer and the upper bound
  int64_t ub;
  // Object Type
  std::string obj;
  // Object name
  std::string owner;
  // Object size
  int64_t obj_size;
  // lower bound
  int64_t lb;
public:
  ObjInfo(int64_t ub, std::string obj, string owner, int64_t obj_size)
  {
    this->ub = ub;
    this->obj = obj;
    this->owner = owner;
    this->obj_size = obj_size;
    // Lower bounds calculated here
    this->lb = ub + obj_size;
  }
  int64_t get_ub() {return ub;}
  std::string get_obj() {return obj;}
  std::string get_owner() {return owner;}
  int64_t get_obj_size() {return obj_size;}
  int64_t get_lb() {return lb;}
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

// A structure to store all the file related information
struct Block
{
  // Block name
  std::string name;
  // Set the rbp value for the particular block
  uint64_t rbp_value;
  // Set the rsp value for the particular block
  uint64_t rsp_value;
  // check if rbp relative addressing is used
  bool adjust_off;
  // function entry address
  ADDRINT fun_entry;
  // function exit address
  ADDRINT fun_exit;
  // a global flag to check if rsp relative addressing is used
  bool rsp_set_flag = adjust_off;
  // Object information hash map
  std::unordered_map <std::string, ObjInfo*> objinfostack;
  // static code locations hash map
  std::unordered_map <ADDRINT, InsInfo*> inscodestack;
};

// Map containing Blocks
// The keys are function name and the values are blocks per function
// std::list<struct Block> Blocks;
std::unordered_map <std::string, struct Block*> blocks;

// set rbp
VOID rbp_val_set(uint64_t addr, CONTEXT * ctxt, Block &i, std::string disassins)
{
  // set the rbp value -- This value will stay same throughout the function
  i.rbp_value = PIN_GetContextReg(ctxt, REG_RBP);
  // std::cout << "rbp: " << i.rbp_value << '\n';
  for(std::unordered_map<std::string, ObjInfo*>::iterator iter = i.objinfostack.begin(); iter != i.objinfostack.end(); ++iter)
  {
    std::string k = iter->first;
    // std::cout << "k: " << k << '\n';
    ObjInfo* v = iter->second;
    if(accessboundsmap.find(k) == accessboundsmap.end())
    {
      std::cout << "object: " << k << '\n';
      std::cout << "lb: " << v->get_lb() + i.rbp_value << '\n';
      std::cout << "ub: " << v->get_ub() + i.rbp_value << '\n';
      accessboundsmap.insert(std::make_pair(k, new AccessBounds(v->get_lb() +
        i.rbp_value, v->get_ub() + i.rbp_value, v->get_ub() + i.rbp_value)));
      // accessboundsmap.set_location(v->get_lb() + i.rbp_value);
    }
    else
    {
      accessboundsmap[k]->set_bounds(v->get_lb() + i.rbp_value,
        v->get_ub() + i.rbp_value, v->get_ub() + i.rbp_value);
    }
  }
}

// set rsp
VOID rsp_val_set(CONTEXT * ctxt, Block &i)
{
  // set the rsp value -- This value will stay same throughout the function
  i.rsp_value = PIN_GetContextReg(ctxt, REG_RSP);
  // Assign respective owners per stack location
  for(std::unordered_map<std::string, ObjInfo*>::iterator iter = i.objinfostack.begin(); iter != i.objinfostack.end(); ++iter)
  {
    std::string k = iter->first;
    ObjInfo* v = iter->second;
    if(accessboundsmap.find(k) == accessboundsmap.end())
      {
      accessboundsmap.insert(std::make_pair(k, new AccessBounds(v->get_lb() +
        i.rsp_value, v->get_ub() + i.rsp_value, v->get_ub() + i.rsp_value)));
      // accessboundsmap.set_location(v->get_lb() + i.rsp_value);
      }
  }
}

// mov  DWORD PTR [rbp-0x20],0x1
VOID mov_immediate(uint64_t addr, CONTEXT * ctxt, Block &i, std::string disassins,
std::string owner, int64_t displacement, int64_t scale, REG index_reg, REG base_reg,
int64_t ins_size, ADDRINT imm)
{
  // effective address the instruction is referring to
  // Effective address = Displacement + BaseReg + IndexReg * Scale
  std::cout << "dissss: " << disassins << " add: " << addr << '\n';
  // std::cout << "imm: " << imm << '\n';
  // std::cout << "reg: " << REG_StringShort(REG_FullRegName(base_reg)) << '\n';
  std::cout << "owner: " << owner << '\n';
  uint64_t effective_dispacement = 0;
  if (i.objinfostack.find(owner) != i.objinfostack.end())
  {
    if (REG_valid(index_reg))
    {
      // if index register is present, add it
      effective_dispacement = displacement + PIN_GetContextReg(ctxt, base_reg)
      + (PIN_GetContextReg(ctxt, index_reg) * scale);
    }
    else
    {
      // if index register is not present
      effective_dispacement = PIN_GetContextReg(ctxt, base_reg) + displacement;
      // std::cout << "eff: " << effective_dispacement << '\n';
    }
    std::cout << "effective_dispacement: " << effective_dispacement << '\n';
    std::cout << "Upper bounds: " << accessboundsmap[owner]->get_bound() << '\n';
    std::cout << "Lower bounds: " << accessboundsmap[owner]->get_base() << '\n';
    // If the type is array and the access is not within the bounds
    if ((effective_dispacement >= accessboundsmap[owner]->get_base() ||
    effective_dispacement < accessboundsmap[owner]->get_bound()))
    {
      // if (accessboundsmap.get_location)
      std::cout << "Location: " << accessboundsmap[owner]->get_location() << '\n';
      // if the location is used itself
      // if (accessboundsmap[owner]->get_location() == effective_dispacement);
      // else
      // {
        std::cout << "Boundover accessed by " << owner << " in mov_immediate, at "
        << addr << '\n';
        std::exit(1);
      // }
    }

    // support mov address instructions
    for(std::unordered_map<std::string, AccessBounds*>::iterator iter = accessboundsmap.begin(); iter != accessboundsmap.end(); ++iter)
    {
      // if it is a dynamic structure element, then ignore
      // this is to ignore allocations to in structure elements
      if (std::find(pointermap.begin(), pointermap.end(), owner) == pointermap.end())
      {
        std::string k = iter->first;
        AccessBounds* v = iter->second;
        if (imm == v->get_bound())
        {
          // std::cout << "ub: " << v->get_base() << '\n';
          // std::cout << "lb: " << v->get_bound() << '\n';
          // std::cout << "k:" << k << '\n';
          accessboundsmap[owner]->set_bounds(accessboundsmap[k]->get_base(),
            accessboundsmap[k]->get_bound());
        }
      }
    }
  }
  /*todo: support static or global array as well*/
  else if (globalobjinfostack.find(owner) != globalobjinfostack.end())
  {
    // instruction size is needed for rip relative addressing
    if (REG_valid(index_reg))
    { // if index register is present, add it
      if (PIN_GetContextReg(ctxt, base_reg) == REG_RIP)
      effective_dispacement = displacement + PIN_GetContextReg(ctxt, base_reg)
      + (PIN_GetContextReg(ctxt, index_reg) * scale) + ins_size;
      else
      effective_dispacement = displacement + PIN_GetContextReg(ctxt, base_reg)
      + (PIN_GetContextReg(ctxt, index_reg) * scale);
    }
    else
    { // if index register is not present
      effective_dispacement = PIN_GetContextReg(ctxt, base_reg) + displacement + ins_size;// + ins_size;
    }
    // std::cout << "global Base: " << accessboundsmap[owner]->get_base() << '\n';
    // std::cout << "global Bound: " << accessboundsmap[owner]->get_bound() << '\n';
    // std::cout << "effective_dispacement: " << effective_dispacement << '\n';
    if ((effective_dispacement >= accessboundsmap[owner]->get_base() ||
    effective_dispacement < accessboundsmap[owner]->get_bound()))
      {
        if (accessboundsmap[owner]->get_location() == effective_dispacement);
        else
        {
          // std::cout << "Boundover accessed by " << owner << " in mov_immediate, at "
          // << addr << '\n';
          std::exit(1);
        }
      }
  }
  else
  {
    // std::cout << "check your input!" << '\n';
  }
}

// // this case deal with struct elements and array accesses through
// // base registers other than rbp and rsp
// VOID mov_reg_2(uint64_t addr, CONTEXT * ctxt, Block &i, std::string disassins,
// std::string owner, int64_t displacement,  int64_t scale, REG index_reg, REG base_reg,
// REG reg, int64_t ins_size)
// {
//   uint64_t effective_dispacement = 0;
//   std::cout << "dissss: " << disassins << " add: " << addr << '\n';
//   std::cout << "owner: " << owner << '\n';
//   std::cout << "size: " << ins_size << '\n';
//   if (i.objinfostack.find(owner) != i.objinfostack.end())
//   {
//     {
//       // if index register is not present
//       effective_dispacement = PIN_GetContextReg(ctxt, base_reg) + displacement;
//       // std::cout << "eff: " << effective_dispacement << '\n';
//     }
//     std::cout << "effective_dispacement: " << effective_dispacement << '\n';
//     if ((effective_dispacement < accessboundsmap[owner]->get_base() ||
//     effective_dispacement >= accessboundsmap[owner]->get_bound()))
//     {
//       if (mallocmap.find(PIN_GetContextReg(ctxt, reg)) != mallocmap.end())
//       {
//         std::cout << "mallocmap find" << '\n';
//         pointermap[owner].insert(std::make_pair(patch::to_string(effective_dispacement),new AccessBounds(PIN_GetContextReg(ctxt, reg)+
//         mallocmap[PIN_GetContextReg(ctxt, reg)]->getsize(), PIN_GetContextReg(ctxt, reg),
//         effective_dispacement)));
//       }
//     }
//   }
// }

// mov  QWORD PTR [rbp-0x8],rax
VOID mov_reg(uint64_t addr, CONTEXT * ctxt, Block &i, std::string disassins,
std::string owner, int64_t displacement,  int64_t scale, REG index_reg, REG base_reg,
REG reg, int64_t ins_size)
{
  // effective address the instruction is referring to
  // uint64_t effective_dispacement = 0;
  if (i.objinfostack.find(owner) != i.objinfostack.end())
  {
      std::cout << "dissss: " << disassins << " add: " << addr << '\n';
      std::cout << "owner: " << owner << '\n';
      // std::cout << "reg: " << PIN_GetContextReg(ctxt, reg) << '\n';
      for(std::unordered_map<std::string, AccessBounds*>::iterator iter = accessboundsmap.begin(); iter != accessboundsmap.end(); ++iter)
      {
        std::string k = iter->first;
        AccessBounds* v = iter->second;
        if (PIN_GetContextReg(ctxt, reg) < v->get_base() && PIN_GetContextReg(ctxt, reg) >= v->get_bound())
        {
          // std::cout << "ub: " << v->get_base() << '\n';
          // std::cout << "lb: " << v->get_bound() << '\n';
          // std::cout << "k:" << k << '\n';
          accessboundsmap[owner]->set_bounds(accessboundsmap[k]->get_base(),
            accessboundsmap[k]->get_bound());
          break;
        }
        else if (PIN_GetContextReg(ctxt, reg) == v->get_location())
        {
          // std::cout << "location: " << v->get_location() << '\n';
          // std::cout << "k:" << k << '\n';
          accessboundsmap[owner]->set_bounds(
          v->get_location()+i.objinfostack[owner]->get_obj_size(), v->get_location());
          break;
        }
      }
      if (mallocmap.find(PIN_GetContextReg(ctxt, reg)) != mallocmap.end())
      {
        // std::cout << "mallocmap find" << '\n';
        accessboundsmap[owner]->set_bounds(
          PIN_GetContextReg(ctxt, reg)+mallocmap[PIN_GetContextReg(ctxt, reg)]->getsize(),
          PIN_GetContextReg(ctxt, reg));
        // save the owner in the map if it is allocated dynamically
        pointermap.push_back(owner);
      }
  }
  else if (globalobjinfostack.find(owner) != globalobjinfostack.end())
  {
    // std::cout << "dissss: " << disassins << " add: " << addr << '\n';
    // std::cout << "Global!!!!!!!!!!!" << '\n';
    for(std::unordered_map<std::string, AccessBounds*>::iterator iter = accessboundsmap.begin(); iter != accessboundsmap.end(); ++iter)
    {
      std::string k = iter->first;
      AccessBounds* v = iter->second;
      if (PIN_GetContextReg(ctxt, reg) < v->get_base() && PIN_GetContextReg(ctxt, reg) >= v->get_bound())
      {
        accessboundsmap[owner]->set_bounds(accessboundsmap[k]->get_base(),
          accessboundsmap[k]->get_bound());
      }
    }
  }
}

// mov  eax,DWORD PTR [rax+0x28]
VOID mov_mem_reg(uint64_t addr, CONTEXT * ctxt, Block &i, std::string disassins,
std::string owner, int64_t displacement, int64_t scale, REG index_reg, REG base_reg, int64_t ins_size)
{
  // initialize the effective displacement
  uint64_t effective_dispacement = 0;
  if (i.objinfostack.find(owner) != i.objinfostack.end())
  {
    if (REG_valid(index_reg))
    {
      effective_dispacement = displacement + (PIN_GetContextReg(ctxt, base_reg))
      + (PIN_GetContextReg(ctxt, index_reg) * scale);
    }
    else
    {
      effective_dispacement = displacement + PIN_GetContextReg(ctxt, base_reg);
    }
    std::cout << "dissss: " << disassins << " add: " << addr << '\n';
    std::cout << "owner: " << owner << '\n';
    // std::cout << "Base: " << accessboundsmap[owner]->get_base() << '\n';
    // std::cout << "Bound: " << accessboundsmap[owner]->get_bound() << '\n';
    // std::cout << "effective_dispacement: " << effective_dispacement << '\n';
    if (effective_dispacement >= accessboundsmap[owner]->get_base() ||
    effective_dispacement < accessboundsmap[owner]->get_bound())
    {
      // std::cout << "Boundover access detected. By " << owner << " in mov_mem_reg, at "
      // << addr << '\n';
      std::exit(1);
    }
  }
  else if (globalobjinfostack.find(owner) != globalobjinfostack.end())
  {
    if (REG_valid(index_reg))
    { // if index register is present, add it
      if (PIN_GetContextReg(ctxt, base_reg) == REG_RIP)
      effective_dispacement = displacement + PIN_GetContextReg(ctxt, base_reg)
      + (PIN_GetContextReg(ctxt, index_reg) * scale) + ins_size;
      else
      effective_dispacement = displacement + PIN_GetContextReg(ctxt, base_reg)
      + (PIN_GetContextReg(ctxt, index_reg) * scale);
    }
    else
    { // if index register is not present
      effective_dispacement = PIN_GetContextReg(ctxt, base_reg) + displacement;// + ins_size;
    }
    // std::cout << "ins size: " << ins_size << '\n';
    std::cout << "dissss: " << disassins << " add: " << addr << '\n';
    // std::cout << "global Base: " << accessboundsmap[owner]->get_base() << '\n';
    // std::cout << "global Bound: " << accessboundsmap[owner]->get_bound() << '\n';
    // std::cout << "effective_dispacement: " << effective_dispacement << '\n';
    // std::cout << "reg: " << PIN_GetContextReg(ctxt, base_reg) << '\n';
    // std::cout << "reg: " << PIN_GetContextReg(ctxt, index_reg) << '\n';
    // std::cout << "dispacement: " << displacement << '\n';
    if (effective_dispacement >= accessboundsmap[owner]->get_base() ||
    effective_dispacement < accessboundsmap[owner]->get_bound())
    {
      // std::cout << "Boundover access detected. By " << owner << " in mov_mem_reg, at "
      // << addr << '\n';
      std::exit(1);
    }
  }
}

VOID mov_reg_rsi(uint64_t addr, CONTEXT * ctxt, Block &i, std::string disassins,
std::string owner, int64_t displacement, int64_t scale, REG index_reg, REG base_reg,
REG reg, int64_t ins_size)
{
  std::cout << "dissss: " << disassins << " add: " << addr << '\n';
  std::cout << "owner: " << owner << '\n';
  // effective address the instruction is referring to
  uint64_t effective_dispacement = 0;
  if (i.objinfostack.find(owner) != i.objinfostack.end())
  {
      effective_dispacement =  PIN_GetContextReg(ctxt, reg);
      accessboundsmap[owner]->set_bounds(
        effective_dispacement + PIN_GetContextReg(ctxt, REG_RDI) * 8, effective_dispacement);
      // std::cout << "lb: " << effective_dispacement << '\n';
      // std::cout << "ub:" << effective_dispacement + PIN_GetContextReg(ctxt, REG_RDI) * 8 << '\n';
  }
  // std::cout << "number of args: " << PIN_GetContextReg(ctxt, REG_RDI) << '\n';
  for (ADDRINT j=0; j<PIN_GetContextReg(ctxt, REG_RDI);++j)
  {
    // std::cout << "i: " << j << '\n';
    // std::cout << "pointer: " << effective_dispacement+j*sizeof(ADDRINT) << '\n';
    ADDRINT * addr_ptr = (ADDRINT*)effective_dispacement+j;
    ADDRINT value;
    PIN_SafeCopy(&value,addr_ptr, sizeof(ADDRINT));
    // std::cout << "value: " << value << '\n';
    if(accessboundsmap.find("argv_"+patch::to_string(j)) == accessboundsmap.end())
    {
      // std::cout << "object: " << "argv_"+patch::to_string(j) << '\n';
      // std::cout << "size: " << argv_sizes[j]+1 << '\n';
      accessboundsmap.insert(std::make_pair("argv_"+patch::to_string(j), new AccessBounds(
        value+argv_sizes[j]+1, value, effective_dispacement+j*sizeof(ADDRINT))));
    }
  }
}

// Pin calls this function every time a new instruction is encountered
VOID Instruction(INS ins, VOID *v)
{
  // First check if the routine is valid
  if (!RTN_Valid(RTN_FindByAddress(INS_Address(ins))))
    return;
  // skip if the address is over 0x700000000000
  if (INS_Address(ins) > 0x700000000000)
    return;
  // if(addresses.find(INS_Address(ins)) == addresses.end())
  //   return;
  // struct Block *i = blocks[addresses[INS_Address(ins)]];
  if ( blocks.find(RTN_Name(RTN_FindByAddress(INS_Address(ins)))) == blocks.end())
    return;
  struct Block *i = blocks[RTN_Name(RTN_FindByAddress(INS_Address(ins)))];
  if ((INS_Address(ins) < i->fun_entry) || (INS_Address(ins) > i->fun_exit))
    return;
  // std::cout << "fun_entry: " << i->fun_entry << '\n';
  // std::cout << string(INS_Disassemble(ins)) << " :" << INS_Address(ins) << '\n';
  // std::cout << "fun_exit: " << i->fun_exit << '\n';
  // std::cout << "i " << i->name << '\n';
  // if rbp relative addressing is used
  if (i->adjust_off)
  {
    if (INS_Opcode(ins) == XED_ICLASS_MOV && (INS_OperandReg(ins,0) == REG_RBP)
    && (INS_OperandReg(ins,1) == REG_RSP))
    {
      INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)rbp_val_set, IARG_ADDRINT,
      INS_Address(ins), IARG_CONTEXT, IARG_PTR, &(*i), IARG_PTR, new string(INS_Disassemble(ins)), IARG_END);
    }
  }
  else
  {
    if (!i->rsp_set_flag)
    {
      // std::cout << "rsp relative!" << '\n';
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)rsp_val_set, IARG_CONTEXT, IARG_PTR, &(*i), IARG_END);
      i->rsp_set_flag = true;
    }
  }
  // check if the owner is assigned to an instruction
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

  // don't instrument if scalar
  std::string obj;
  if (i->objinfostack.find(owner) != i->objinfostack.end())
  {
    obj = i->objinfostack[owner]->get_obj();
  }
  else if(globalobjinfostack.find(owner) != globalobjinfostack.end())
  {
    obj = globalobjinfostack[owner]->get_obj();
  }
  if (obj == "scalar")
    return;
  /**** analysis per instruction starts here ****/
  std::cout << "dis: " << string(INS_Disassemble(ins)) << " :" << std::hex << INS_Address(ins) << '\n';
  // std::cout << "cat: " << INS_Category(ins) << '\n';
  // detect all mov instructions
  if ((INS_Category(ins) == 30) || (INS_Category(ins) == 93))
  {
    // ignore fld instruction with a direct pointer argument
    if ((INS_Opcode(ins) == XED_ICLASS_FLD) &&
    ((REG_StringShort(REG_FullRegName(INS_OperandMemoryBaseReg(ins, 1))) == "rbp")
    || REG_StringShort(REG_FullRegName(INS_OperandMemoryBaseReg(ins, 1))) == "rsp"))
    {
      return;
    }

    if (INS_OperandIsMemory(ins, 0))
    {
      if (INS_OperandIsImmediate(ins, 1))
      {
        UINT32 imm = INS_OperandImmediate(ins, 1);
        INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)mov_immediate, IARG_ADDRINT,
        INS_Address(ins), IARG_CONTEXT, IARG_PTR, &(*i), IARG_PTR, new string(INS_Disassemble(ins)),
        IARG_PTR, new string(owner), IARG_ADDRINT, INS_OperandMemoryDisplacement(ins, 0),
        IARG_ADDRINT, INS_OperandMemoryScale(ins, 0), IARG_UINT32, REG(INS_OperandMemoryIndexReg(ins, 0)),
        IARG_UINT32, REG(INS_OperandMemoryBaseReg(ins, 0)),
        IARG_UINT32, INS_Size(ins), IARG_ADDRINT, imm, IARG_END);
      }
      else if (INS_OperandIsReg(ins, 1))
      {
        // if the instruction is of type
        if ((INS_OperandWidth(ins, 0) == 64) && !REG_is_fr(REG(INS_OperandReg(ins, 1))))
        {
          if (REG_StringShort(REG_FullRegName(INS_OperandReg(ins, 1))) != "rsi")
          {
            if ((REG_StringShort(REG_FullRegName(INS_OperandMemoryBaseReg(ins, 0))) == "rbp")
            || REG_StringShort(REG_FullRegName(INS_OperandMemoryBaseReg(ins, 0))) == "rsp")
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)mov_reg, IARG_ADDRINT,
            INS_Address(ins), IARG_CONTEXT, IARG_PTR, &(*i), IARG_PTR, new string(INS_Disassemble(ins)),
            IARG_PTR, new string(owner), IARG_ADDRINT, INS_OperandMemoryDisplacement(ins, 0),
            IARG_ADDRINT, INS_OperandMemoryScale(ins, 0), IARG_UINT32, REG(INS_OperandMemoryIndexReg(ins, 0)),
            IARG_UINT32, REG(INS_OperandMemoryBaseReg(ins, 0)),
            IARG_UINT32, REG(INS_OperandReg(ins, 1)),
            IARG_UINT32, INS_Size(ins), IARG_END);
            // for globals, where rip relative addressing is used
            else if (INS_OperandMemoryBaseReg(ins, 0) == REG_RIP)
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)mov_reg, IARG_ADDRINT,
            INS_Address(ins), IARG_CONTEXT, IARG_PTR, &(*i), IARG_PTR, new string(INS_Disassemble(ins)),
            IARG_PTR, new string(owner), IARG_ADDRINT, INS_OperandMemoryDisplacement(ins, 0),
            IARG_ADDRINT, INS_OperandMemoryScale(ins, 0), IARG_UINT32, REG(INS_OperandMemoryIndexReg(ins, 0)),
            IARG_UINT32, REG(INS_OperandMemoryBaseReg(ins, 0)),
            IARG_UINT32, REG(INS_OperandReg(ins, 1)),
            IARG_UINT32, INS_Size(ins), IARG_END);
            // else if immediate through register
            else
            {
              // if (INS_Size(ins) <= 4)
              // INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)mov_reg_2, IARG_ADDRINT,
              // INS_Address(ins), IARG_CONTEXT, IARG_PTR, &(*i), IARG_PTR, new string(INS_Disassemble(ins)),
              // IARG_PTR, new string(owner), IARG_ADDRINT, INS_OperandMemoryDisplacement(ins, 0),
              // IARG_ADDRINT, INS_OperandMemoryScale(ins, 0), IARG_UINT32, REG(INS_OperandMemoryIndexReg(ins, 0)),
              // IARG_UINT32, REG(INS_OperandMemoryBaseReg(ins, 0)),
              // IARG_UINT32, REG(INS_OperandReg(ins, 1)),
              // IARG_UINT32, INS_Size(ins), IARG_END);
              // else
              INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)mov_immediate, IARG_ADDRINT,
              INS_Address(ins), IARG_CONTEXT, IARG_PTR, &(*i), IARG_PTR, new string(INS_Disassemble(ins)),
              IARG_PTR, new string(owner), IARG_ADDRINT, INS_OperandMemoryDisplacement(ins, 0),
              IARG_ADDRINT, INS_OperandMemoryScale(ins, 0),
              IARG_UINT32, REG(INS_OperandMemoryIndexReg(ins, 0)),
              IARG_UINT32, REG(INS_OperandMemoryBaseReg(ins, 0)),
              IARG_UINT32, INS_Size(ins), IARG_ADDRINT, 0, IARG_END);
            }
          }
          else
          {
            // handle fun arguments
            if (((REG_StringShort(REG_FullRegName(INS_OperandMemoryBaseReg(ins, 0))) == "rbp")
            || REG_StringShort(REG_FullRegName(INS_OperandMemoryBaseReg(ins, 0))) == "rsp")
            && (i->name == "main"))
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)mov_reg_rsi, IARG_ADDRINT,
            INS_Address(ins), IARG_CONTEXT, IARG_PTR, &(*i), IARG_PTR, new string(INS_Disassemble(ins)),
            IARG_PTR, new string(owner), IARG_ADDRINT, INS_OperandMemoryDisplacement(ins, 0),
            IARG_ADDRINT, INS_OperandMemoryScale(ins, 0), IARG_UINT32, REG(INS_OperandMemoryIndexReg(ins, 0)),
            IARG_UINT32, REG(INS_OperandMemoryBaseReg(ins, 0)),
            IARG_UINT32, REG(INS_OperandReg(ins, 1)),
            IARG_UINT32, INS_Size(ins), IARG_END);
            // else if immediate through register
            else
            INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)mov_reg, IARG_ADDRINT,
            INS_Address(ins), IARG_CONTEXT, IARG_PTR, &(*i), IARG_PTR, new string(INS_Disassemble(ins)),
            IARG_PTR, new string(owner), IARG_ADDRINT, INS_OperandMemoryDisplacement(ins, 0),
            IARG_ADDRINT, INS_OperandMemoryScale(ins, 0), IARG_UINT32, REG(INS_OperandMemoryIndexReg(ins, 0)),
            IARG_UINT32, REG(INS_OperandMemoryBaseReg(ins, 0)),
            IARG_UINT32, REG(INS_OperandReg(ins, 1)),
            IARG_UINT32, INS_Size(ins), IARG_END);
          }
        }
        else if (INS_OperandWidth(ins, 0) < 64 || REG_is_fr(REG(INS_OperandReg(ins, 1))))
        {
          INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)mov_immediate, IARG_ADDRINT,
          INS_Address(ins), IARG_CONTEXT, IARG_PTR, &(*i), IARG_PTR, new string(INS_Disassemble(ins)),
          IARG_PTR, new string(owner), IARG_ADDRINT, INS_OperandMemoryDisplacement(ins, 0),
          IARG_ADDRINT, INS_OperandMemoryScale(ins, 0),
          IARG_UINT32, REG(INS_OperandMemoryIndexReg(ins, 0)),
          IARG_UINT32, REG(INS_OperandMemoryBaseReg(ins, 0)),
          IARG_UINT32, INS_Size(ins), IARG_ADDRINT, 0, IARG_END);
        }
      }
    }
    else if (INS_OperandIsMemory(ins, 1))
    {
      // this is because instructions like reg64, mem generally move addresses
      // if (INS_OperandWidth(ins, 0) != 64)
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)mov_mem_reg, IARG_ADDRINT,
      INS_Address(ins), IARG_CONTEXT, IARG_PTR, &(*i), IARG_PTR, new string(INS_Disassemble(ins)),
      IARG_PTR, new string(owner), IARG_ADDRINT, INS_OperandMemoryDisplacement(ins, 1),
      IARG_ADDRINT, INS_OperandMemoryScale(ins, 1), IARG_UINT32, REG(INS_OperandMemoryIndexReg(ins, 1)),
      IARG_UINT32, REG(INS_OperandMemoryBaseReg(ins, 1)),
      IARG_UINT32, INS_Size(ins),
      IARG_END);
    }
  }
}

// Lazy size allocation
ADDRINT lazyallocatedsize = 0;

VOID MallocBefore(char *name, ADDRINT size)
{
  // if (addrs == '\0')
  // {
  //   cerr << "Heap full!\n";
  //   return;
  // }
  // std::cout << name << "(" << size << ")" << '\n';
  // Lazy size allocation
  lazyallocatedsize = size;
}

VOID MallocAfter(ADDRINT addrs)
{
  if (addrs == '\0')
  {
    cerr << "Heap full!\n";
    return;
  }
  // std::cout << "malloc: " << addrs << " : " << lazyallocatedsize << "\n";
  // Check if it is already present in the map
  if (mallocmap.find(addrs) == mallocmap.end())
  {
    mallocmap.insert(std::make_pair(addrs, new MallocMap(lazyallocatedsize, true)));
  }
  else
  {
    mallocmap[addrs]->setsize(lazyallocatedsize);
  }
  lazyallocatedsize = 0;
}
/**************End of Malloc routines******************/

/******************Calloc routines******************/
VOID CallocBefore(CHAR * name, ADDRINT count, ADDRINT size, ADDRINT return_ip)
{
  lazyallocatedsize = count * size;
}

VOID CallocAfter(char *name, ADDRINT addrs, ADDRINT size)
{
  if (mallocmap.find(addrs) == mallocmap.end())
  {
    mallocmap.insert(std::make_pair(addrs, new MallocMap(lazyallocatedsize, true)));
  }
  else
  {
    mallocmap[addrs]->setsize(lazyallocatedsize);
  }
}
/**************End of Calloc routines******************/
/*******************Realloc routines******************/
VOID ReallocBefore(CHAR * name, ADDRINT addr, ADDRINT size, ADDRINT return_ip)
{
  // std::cout << name << " : " << addr << "(" << size << ")" << " : " << return_ip << endl;
  // Check if it is already present in the map
  if (!lazyallocatedsize)
    lazyallocatedsize = size;
}

VOID ReallocAfter(ADDRINT ret)
{
  if (ret == '\0')
  {
    cerr << "Heap full!\n";
    return;
  }
  // std::cout << "realloc: " << ret << " : " << lazyallocatedsize << "\n";
  if (mallocmap.find(ret) == mallocmap.end())
  {
    mallocmap.insert(std::make_pair(ret, new MallocMap(lazyallocatedsize, true)));
  }
  else
  {
    // std::cout << "size:" << lazyallocatedsize << '\n';
    mallocmap[ret]->setsize(lazyallocatedsize);
  }
  lazyallocatedsize = 0;
}
/**************End of Realloc routines******************/

VOID FreeBefore(ADDRINT ret)
{
  // std::cout << "returns: " <<  ret << '\n';
}

void Image(IMG img, VOID *v)
{
  // instrument main image only
  if (IMG_IsMainExecutable(img))
  {
    for(std::unordered_map<std::string, struct Block*>::iterator iter = blocks.begin(); iter != blocks.end(); ++iter)
    {
      std::string k = iter->first;
      struct Block* v = iter->second;
      RTN_CreateAt(v->fun_entry, v->name);
    }
  }
  // set library path accordingly
  // if (IMG_Name(img) == "/lib/x86_64-linux-gnu/libc.so.6")
  if (IMG_Name(img).find("libc") != std::string::npos)
  {
    RTN mallocRtn = RTN_FindByName(img, "malloc");
    if (RTN_Valid(mallocRtn))
    {
      RTN_Open(mallocRtn);
      // Instrument malloc() to print the input argument value and the return value.
      RTN_InsertCall(mallocRtn, IPOINT_BEFORE, (AFUNPTR)MallocBefore,
                    IARG_ADDRINT, "malloc",
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                    IARG_END);
      RTN_InsertCall(mallocRtn, IPOINT_AFTER, (AFUNPTR)MallocAfter,
                    IARG_FUNCRET_EXITPOINT_VALUE,
                    IARG_END);
      RTN_Close(mallocRtn);
    }
    RTN callocRtn = RTN_FindByName(img, "calloc");
    if (RTN_Valid(callocRtn))
    {
      RTN_Open(callocRtn);
      // Instrument malloc() to print the input argument value and the return value.
      RTN_InsertCall(callocRtn, IPOINT_BEFORE, (AFUNPTR)CallocBefore,
                    IARG_ADDRINT, "calloc",
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                    IARG_END);
      RTN_InsertCall(callocRtn, IPOINT_AFTER, (AFUNPTR)CallocAfter,
                    IARG_ADDRINT, "calloc",
                    IARG_FUNCRET_EXITPOINT_VALUE,
                    IARG_END);
      RTN_Close(callocRtn);
    }
    RTN reallocRtn = RTN_FindByName(img, "realloc");
    if (RTN_Valid(reallocRtn))
    {
      RTN_Open(reallocRtn);
      // Instrument malloc() to print the input argument value and the return value.
      RTN_InsertCall(reallocRtn, IPOINT_BEFORE, (AFUNPTR)ReallocBefore,
                    IARG_ADDRINT, "realloc",
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                    IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                    IARG_END);
      RTN_InsertCall(reallocRtn, IPOINT_AFTER, (AFUNPTR)ReallocAfter,
                    IARG_FUNCRET_EXITPOINT_VALUE,
                    IARG_END);
      RTN_Close(reallocRtn);
    }
    RTN freeRtn = RTN_FindByName(img, "free");
    if (RTN_Valid(freeRtn))
    {
      RTN_Open(freeRtn);
      // Instrument malloc() to print the input argument value and the return value.
      RTN_InsertCall(freeRtn, IPOINT_BEFORE, (AFUNPTR)FreeBefore,
                     IARG_FUNCRET_EXITPOINT_VALUE,
                     IARG_END);
      RTN_Close(freeRtn);
    }
  }
}

void readInput(const char *filename)
{
  std::string line;
  std::ifstream myfile(filename);
  if (myfile.is_open())
  {
    // Get total number of functions or blocks
    getline (myfile,line);
    int64_t count = atoi(line.c_str());
    while (count)
    {
      // Initialize the structure
      struct Block *block = new Block;
      // for the function name
      getline (myfile,line);
      block->name = line;
      block->rbp_value = 0;
      block->rsp_value = 0;
      getline (myfile,line);
      if (line == "8")
        block->adjust_off = true;
      else if (line == "0")
        block->adjust_off = false;
      getline(myfile,line);
      block->fun_entry = strtol(line.c_str(), NULL, 16);
      getline(myfile,line);
      block->fun_exit = strtol(line.c_str(), NULL, 16);
      // RTN_CreateAt(block->fun_entry, block->name);
      getline (myfile,line);
      if (line == "addresses")
      {
        while (getline(myfile,line))
        {
          if (line.empty())
          {
              break;
          }
          else
          {
            std::vector<std::string> temp;
            // boost::split(temp, line, boost::is_any_of("\t "));
            temp = split(line, ' ');
            block->inscodestack.insert(std::make_pair(strtol(temp[0].c_str(), NULL, 16), new InsInfo(strtol(temp[0].c_str(), NULL, 16), temp[1])));
            addresses.insert(std::make_pair(strtol(temp[0].c_str(), NULL, 16), block->name));
          }
        }
      }
      getline (myfile,line);
      if (line == "locals")
      {
        while (getline(myfile,line))
        {
          if (line.empty())
          {
              break;
          }
          else
          {
            std::vector<std::string> temp;
            //boost::split(temp, line, boost::is_any_of("\t "));
            temp = split(line, ' ');
            block->objinfostack.insert(std::make_pair(temp[2], new ObjInfo(atoi(temp[0].c_str()), temp[1], temp[2], atoi(temp[3].c_str()))));
          }
        }
      }
      // Todo: make a new structure for namespaces
      getline (myfile,line);
      if (line == "namespace")
      {
        while (getline(myfile,line))
        {
          if (line.empty())
          {
              break;
          }
          else
          {
            std::vector<std::string> temp;
            //boost::split(temp, line, boost::is_any_of("\t "));
            temp = split(line, ' ');
            //ObjInfo *objinfo = new ObjInfo {atoi(temp[0].c_str()), temp[1], temp[2], temp[3], atoi(temp[4].c_str())};
            globalobjinfostack.insert(std::make_pair(temp[2], new GlobObjInfo(atoi(temp[0].c_str()), temp[1], temp[2], atoi(temp[3].c_str()))));
          }
        }
      }
      // // make every location zero upon initialization
      // for (uint64_t i = 0; i <= block.size; ++i)
      //   block.relPosStack.insert(std::make_pair(i, new RelPos(0)));
      blocks.insert(std::make_pair(block->name, block));
      --count;
    }
    //global variables must be handled here
    getline (myfile,line);
    if (line == ".global")
    {
      while (getline(myfile,line))
      {
        if (line.empty())
        {
            break;
        }
        else
        {
          std::vector<std::string> temp;
          //boost::split(temp, line, boost::is_any_of("\t "));
          temp = split(line, ' ');
          globalobjinfostack.insert(std::make_pair(temp[2], new GlobObjInfo(atoi(temp[0].c_str()), temp[1], temp[2], atoi(temp[3].c_str()))));
        }
      }
    }
    myfile.close();
    // Assign respective owners per global or static location
    for(std::unordered_map<std::string, GlobObjInfo*>::iterator iter = globalobjinfostack.begin(); iter != globalobjinfostack.end(); ++iter)
    {
      std::string k = iter->first;
      GlobObjInfo* v = iter->second;
      if(accessboundsmap.find(k) == accessboundsmap.end())
        accessboundsmap.insert(std::make_pair(k, new AccessBounds(v->get_lb(), v->get_ub(), v->get_ub())));
    }
  }
  else std::cout << "Unable to open file\n";
}

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
    "i", "pintool", "specify input file name");

// This function is called when the application exits
VOID Fini(INT32 code, VOID *v)
{
  std::cout << "Application exit" << '\n';
}

INT32 Usage()
{
    cerr << "This tool counts the number of dynamic instructions executed" << endl;
    cerr << endl << KNOB_BASE::StringKnobSummary() << endl;
    return -1;
}

int main(int argc, char * argv[])
{
    // Symbols
    PIN_InitSymbols();
    if (PIN_Init(argc, argv)) return Usage();
    // Argv[6] is the program image
    ProgramImage = argv[6];
    for (int i=8; i<argc; ++i)
    {
      // std::cout << "arg :" << i << " : " << strlen(argv[i]) << '\n';
      argv_sizes.push_back(strlen(argv[i]));
    }
    // Argv[7] is the name of the input file
    readInput(KnobOutputFile.Value().c_str());
    // std::cout << "Total args: " << argc << '\n';
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
