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

// To detect malloc, calloc and realloc
#define MALLOC "malloc"
#define CALLOC "calloc"
#define REALLOC "realloc"
#define FREE "free"
#define FGETS "fgets"
#define GETS "gets"

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
map<ADDRINT, MallocMap*> mallocmap;
string ProgramImage;
// Lazy size allocation
ADDRINT lazyallocatedsize = 0;
// Number of input parameters or command line arguments - it is the value in rdi
int64_t in_args = 0;
// rdi and rsi check
std::string main_local = "main_local";

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
  void set_base(uint64_t base){this->base = base;}
  void set_bound(uint64_t bound){this->bound = bound;}
  void set_bounds(uint64_t base, uint64_t bound){this->base = base; this->bound = bound;}
  uint64_t get_base(){return this->base;}
  uint64_t get_bound(){return this->bound;}
};

// Map to store all bound information globally
// key: owner
std::unordered_map <std::string, AccessBounds*> accessboundsmap;
// Actual stack (positions related to rbp) hash map
std::unordered_map <uint64_t, std::string> relPosStack;


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

// A structure to store all the file related information
struct Block
{
  // Block name
  std::string name;
  // Set the rbp value for the particular block
  uint64_t rbp_value;
  // Set the rsp value for the particular block
  uint64_t rsp_value;
  // Object information hash map
  std::unordered_map <std::string, ObjInfo*> objinfostack;
  // static code locations hash map
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

// This sets up rbp and rsp values and sets the size of the stack for the corresponding block
VOID reg_val_set(uint64_t addr, CONTEXT * ctxt, Block &i, std::string disassins)
{
  // set the rbp value -- This value will stay same throughout the function
  i.rbp_value = PIN_GetContextReg(ctxt, REG_RBP);
  // set the rsp value -- This value will stay same throughout the function
  i.rsp_value = PIN_GetContextReg(ctxt, REG_RSP);

  // Assign respective owners per stack location
  for(std::unordered_map<std::string, ObjInfo*>::iterator iter = i.objinfostack.begin(); iter != i.objinfostack.end(); ++iter)
  {
    std::string k = iter->first;
    ObjInfo* v = iter->second;
    for (auto j = i.rbp_value + v->get_ub(); j < i.rbp_value + v->get_lb(); ++j)
    {
      if(relPosStack.find(j) == relPosStack.end())
      {
        relPosStack.insert(std::make_pair(j, k));
      }
    }
  }
}

// This is needed to check the array bounds
// mov  DWORD PTR [rbp-0x20],0x1
// mov  DWORD PTR [rbp-0xc],eax
VOID mov_immediate(uint64_t addr, CONTEXT * ctxt, Block &i, std::string disassins,
  std::string owner, int64_t displacement, int64_t scale, REG index_reg, REG base_reg)
{
  // effective address the instruction is referring to
  uint64_t effective_dispacement = 0;

  if (i.objinfostack.find(owner) != i.objinfostack.end())
  {
    // Effective address = Displacement + BaseReg + IndexReg * Scale
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
    }

    // std::cout << i.objinfostack[owner] << '\n';
    if (i.objinfostack[owner]->get_obj() == "array" ||
      i.objinfostack[owner]->get_obj() == "scalar")
    {
      // Save the upper and lower bounds
      // For example, it can be an array or a scalar
      if(accessboundsmap.find(owner) == accessboundsmap.end())
        accessboundsmap.insert(std::make_pair(owner, new AccessBounds(i.objinfostack[owner]->get_lb() +
      i.rbp_value, i.objinfostack[owner]->get_ub() + i.rbp_value)));

      // std::cout << "effective_dispacement: " << effective_dispacement << '\n';
      // std::cout << "Upper bounds: " << accessboundsmap[owner]->get_bound() << '\n';
      // std::cout << "Lower bounds: " << accessboundsmap[owner]->get_base() << '\n';

      // If the type is array and the access is not within the bounds
      // If rsp is to be detected and rsp + x is equivalent to ebp - (rsp + x)
      if ((effective_dispacement >= accessboundsmap[owner]->get_base() ||
      effective_dispacement < accessboundsmap[owner]->get_bound()) &&
      (i.objinfostack[owner]->get_obj() == "array"))
      {
        // std::cout << "Boundover accessed by " << owner << '\n';
        std::exit(1);
      }
    }
  }
  else
  std::cout << "check your input!" << '\n';
}

// mov  DWORD PTR [rax],edi
// mov immediate without rbp
// mov  DWORD PTR [rax],0x4
// This is needed for the heap_pointer
VOID mov_immediate2(uint64_t addr, CONTEXT * ctxt, Block &i, std::string disassins,
  std::string owner, int64_t displacement, REG base_reg, REG index_reg, int64_t scale, int64_t ins_size)
{
  uint64_t effective_dispacement;
  if (i.objinfostack.find(owner) != i.objinfostack.end())
  {
    if (REG_valid(index_reg))
    { // if index register is present, add it
      effective_dispacement = displacement + PIN_GetContextReg(ctxt, base_reg)
      + (PIN_GetContextReg(ctxt, index_reg) * scale);
    }
    else
    { // if index register is not present
      effective_dispacement = PIN_GetContextReg(ctxt, base_reg) + displacement;
    }
    // std::cout << "effective_dispacement: " << effective_dispacement << '\n';
    if (i.objinfostack[owner]->get_obj() == "pointer")
    {
      if(accessboundsmap.find(owner) == accessboundsmap.end())
        accessboundsmap.insert(std::make_pair(owner, new AccessBounds(i.objinfostack[owner]->get_lb() +
      i.rbp_value, i.objinfostack[owner]->get_ub() + i.rbp_value)));
      // std::cout << "Base: " << accessboundsmap[owner]->get_base() << '\n';
      // std::cout << "Bound: " << accessboundsmap[owner]->get_bound() << '\n';
      // std::cout << "effective_dispacement: " << effective_dispacement << '\n';
      if (effective_dispacement >= accessboundsmap[owner]->get_base() ||
      effective_dispacement < accessboundsmap[owner]->get_bound())
      {
        // std::cout << "Boundover access detected. By " << owner << '\n';
        std::exit(1);
      }
    }
    else if (globalobjinfostack[owner]->get_obj() == "scalar" || globalobjinfostack[owner]->get_obj() == "array")
    {
      if(accessboundsmap.find(owner) == accessboundsmap.end())
        accessboundsmap.insert(std::make_pair(owner, new AccessBounds(i.objinfostack[owner]->get_lb() +
      i.rbp_value, i.objinfostack[owner]->get_ub() + i.rbp_value)));
    }
  }
  // for rip addressing mode
  else if (globalobjinfostack.find(owner) != globalobjinfostack.end())
  {
    // instruction size is needed for rip relative addressing
    if (REG_valid(index_reg))
    { // if index register is present, add it
      effective_dispacement = displacement + PIN_GetContextReg(ctxt, base_reg)
      + (PIN_GetContextReg(ctxt, index_reg) * scale) + ins_size;
    }
    else
    { // if index register is not present
      effective_dispacement = PIN_GetContextReg(ctxt, base_reg) + displacement + ins_size;
    }
    if (globalobjinfostack[owner]->get_obj() == "pointer")
    {
      if (accessboundsmap.find(owner) != accessboundsmap.end())
      {
        if ((effective_dispacement >= accessboundsmap[owner]->get_base() ||
        effective_dispacement < accessboundsmap[owner]->get_bound()))
        {
          // std::cout << "Boundover accessed by " << owner << '\n';
          std::exit(1);
        }
      }
      else
      {
        accessboundsmap.insert(std::make_pair(owner, new AccessBounds(globalobjinfostack[owner]->get_lb(),
        globalobjinfostack[owner]->get_ub())));
      }
    }
    else if (globalobjinfostack[owner]->get_obj() == "scalar" || globalobjinfostack[owner]->get_obj() == "array")
    {
      if (accessboundsmap.find(owner) == accessboundsmap.end())
        accessboundsmap.insert(std::make_pair(owner, new AccessBounds(globalobjinfostack[owner]->get_lb(),
        globalobjinfostack[owner]->get_ub())));
      if ((effective_dispacement >= accessboundsmap[owner]->get_base() ||
      effective_dispacement < accessboundsmap[owner]->get_bound()) &&
      (globalobjinfostack[owner]->get_obj() == "array"))
      {
        // std::cout << "Boundover accessed by " << owner << '\n';
        std::exit(1);
      }
    }
  }
}

VOID rsi_check(uint64_t addr, CONTEXT * ctxt, Block &i, std::string disassins,
  std::string owner, int64_t displacement,  int64_t scale, REG index_reg, REG base_reg,
  REG reg, int64_t ins_size)
{
    // std::cout << "rsi: " <<  PIN_GetContextReg(ctxt, reg) << '\n';
    // std::cout << "in !!!!!!!!!!!!!!!" << '\n';
    // std::cout << "owner: " << owner << '\n';
    uint64_t effective_dispacement = 0;
    if (i.objinfostack.find(owner) != i.objinfostack.end())
    {
      // Effective address = Displacement + BaseReg + IndexReg * Scale
      if (REG_valid(index_reg))
      { // if index register is present, add it
        effective_dispacement = displacement + PIN_GetContextReg(ctxt, base_reg)
        + (PIN_GetContextReg(ctxt, index_reg) * scale);
      }
      else
      { // if index register is not present
        effective_dispacement = PIN_GetContextReg(ctxt, base_reg) + displacement;
      }
      if (i.objinfostack[owner]->get_obj() == "pointer")
      {
        if (relPosStack.find(PIN_GetContextReg(ctxt, reg)) == relPosStack.end())
        {
          // This is different from effective_dispacement
          effective_dispacement = PIN_GetContextReg(ctxt, reg);
          if (accessboundsmap.find(owner) == accessboundsmap.end())
          {
            accessboundsmap.insert(std::make_pair(owner,
              new AccessBounds(effective_dispacement + in_args * 8,
              effective_dispacement)));
            // std::cout << "in!" << in_args << '\n';
            // std::cout << "Malloc Upper bounds: " << accessboundsmap[owner]->get_bound() << '\n';
            // std::cout << "Malloc Lower bounds: " << accessboundsmap[owner]->get_base() << '\n';
          }
        }
      }
    }
}

VOID rdi_check(uint64_t addr, CONTEXT * ctxt, Block &i, std::string disassins,
  std::string owner, int64_t displacement,  int64_t scale, REG index_reg, REG base_reg,
  REG reg, int64_t ins_size)
{
  in_args = PIN_GetContextReg(ctxt, reg);
}

// mov  QWORD PTR [rbp-0x8],rax
// mov  DWORD PTR [rbp-0x40],rsi
VOID mov_reg(uint64_t addr, CONTEXT * ctxt, Block &i, std::string disassins,
  std::string owner, int64_t displacement,  int64_t scale, REG index_reg, REG base_reg,
  REG reg, int64_t ins_size)
{
  // effective address the instruction is referring to
  uint64_t effective_dispacement = 0;

  if (i.objinfostack.find(owner) != i.objinfostack.end())
  {
    // Effective address = Displacement + BaseReg + IndexReg * Scale
    if (REG_valid(index_reg))
    { // if index register is present, add it
      effective_dispacement = displacement + PIN_GetContextReg(ctxt, base_reg)
      + (PIN_GetContextReg(ctxt, index_reg) * scale);
    }
    else
    { // if index register is not present
      effective_dispacement = PIN_GetContextReg(ctxt, base_reg) + displacement;
    }
    // Check to see if the owner is a pointer
    if (i.objinfostack[owner]->get_obj() == "pointer")
    {
      // get the Register value
      // pointer is getting the address of owner_prop and hence its bounds
      // std::cout << PIN_GetContextReg(ctxt, reg) << '\n';
      if (relPosStack.find(PIN_GetContextReg(ctxt, reg)) == relPosStack.end())
      {
        // This is different from effective_dispacement
        effective_dispacement = PIN_GetContextReg(ctxt, reg);
        if(mallocmap.find(effective_dispacement) != mallocmap.end())
        {
          if (accessboundsmap.find(owner) == accessboundsmap.end())
          {
            accessboundsmap.insert(std::make_pair(owner,
              new AccessBounds(mallocmap[effective_dispacement]->getsize() + effective_dispacement,
              effective_dispacement)));
            // std::cout << "Malloc Upper bounds: " << accessboundsmap[owner]->get_bound() << '\n';
            // std::cout << "Malloc Lower bounds: " << accessboundsmap[owner]->get_base() << '\n';
          }
          else
          {
            accessboundsmap[owner]->set_bounds(mallocmap[effective_dispacement]->getsize()
            + effective_dispacement, effective_dispacement);
          }
        }
        else
        {
          // TODO:: remove if not required
          relPosStack.insert(std::make_pair(effective_dispacement, owner));
        }
      }
      else
      {
        std::string owner_prop = relPosStack[PIN_GetContextReg(ctxt, reg)];
        // std::cout << "owner_prop: " << owner_prop << '\n';
        if(accessboundsmap.find(owner) == accessboundsmap.end())
          accessboundsmap.insert(std::make_pair(owner, new AccessBounds(accessboundsmap[owner_prop]->get_base(),
          accessboundsmap[owner_prop]->get_bound())));
        else
          accessboundsmap[owner]->set_bounds(accessboundsmap[owner_prop]->get_base(),
          accessboundsmap[owner_prop]->get_bound());
        // std::cout << "lower bounds: " << accessboundsmap[owner]->get_base() <<'\n';
        // std::cout << "Upper bounds: " << accessboundsmap[owner]->get_bound() <<'\n';
      }
    }
    // Only if the owner is an array
    if (i.objinfostack[owner]->get_obj() == "array")
    {
      // first check if the bounds have already been set
      // if not, then set the bounds
      if(accessboundsmap.find(owner) == accessboundsmap.end())
        accessboundsmap.insert(std::make_pair(owner, new AccessBounds(i.objinfostack[owner]->get_lb() +
      i.rbp_value, i.objinfostack[owner]->get_ub() + i.rbp_value)));
      // Check if the access is within the bounds
      if (effective_dispacement >= accessboundsmap[owner]->get_base() ||
      effective_dispacement < accessboundsmap[owner]->get_bound())
      {
        // std::cout << "Boundover accessed by " << owner << '\n';
        std::exit(1);
      }
    }
  }
  else if (globalobjinfostack.find(owner) != globalobjinfostack.end())
  {
    if (REG_valid(index_reg))
    { // if index register is present, add it
      effective_dispacement = displacement + PIN_GetContextReg(ctxt, base_reg)
      + (PIN_GetContextReg(ctxt, index_reg) * scale) + ins_size;
    }
    else
    { // if index register is not present
      effective_dispacement = PIN_GetContextReg(ctxt, base_reg) + displacement + ins_size;
    }
    if (globalobjinfostack[owner]->get_obj() == "pointer")
    {
      // get the Register value
      // pointer is getting the address of owner_prop and hence its bounds
      if (relPosStack.find(PIN_GetContextReg(ctxt, reg)) == relPosStack.end())
      {
        // This is different from effective_dispacement
        effective_dispacement = PIN_GetContextReg(ctxt, reg);
        if(mallocmap.find(effective_dispacement) != mallocmap.end())
        {
          if (accessboundsmap.find(owner) == accessboundsmap.end())
          {
            accessboundsmap.insert(std::make_pair(owner,
              new AccessBounds(mallocmap[effective_dispacement]->getsize() + effective_dispacement,
              effective_dispacement)));
            // std::cout << "Malloc Upper bounds: " << accessboundsmap[owner]->get_bound() << '\n';
            // std::cout << "Malloc Lower bounds: " << accessboundsmap[owner]->get_base() << '\n';
          }
          else
          {
            accessboundsmap[owner]->set_bounds(mallocmap[effective_dispacement]->getsize()
            + effective_dispacement, effective_dispacement);
          }
        }
        else
        {
          // TODO:: remove if not required
          relPosStack.insert(std::make_pair(effective_dispacement, owner));
        }
      }
      else
      {
        std::string owner_prop = relPosStack[PIN_GetContextReg(ctxt, reg)];
        if(accessboundsmap.find(owner) == accessboundsmap.end())
          accessboundsmap.insert(std::make_pair(owner, new AccessBounds(accessboundsmap[owner_prop]->get_base(),
          accessboundsmap[owner_prop]->get_bound())));
        else
          accessboundsmap[owner]->set_bounds(accessboundsmap[owner_prop]->get_base(),
          accessboundsmap[owner_prop]->get_bound());
        // std::cout << "lower bounds: " << accessboundsmap[owner]->get_base() <<'\n';
        // std::cout << "Upper bounds: " << accessboundsmap[owner]->get_bound() <<'\n';
      }
    }
    // Only if the owner is an array
    if (globalobjinfostack[owner]->get_obj() == "array")
    {
      // first check if the bounds have already been set
      // if not, then set the bounds
      if(accessboundsmap.find(owner) == accessboundsmap.end())
        accessboundsmap.insert(std::make_pair(owner, new AccessBounds(globalobjinfostack[owner]->get_lb(),
        globalobjinfostack[owner]->get_ub())));
      // Check if the access is within the bounds
      if (effective_dispacement >= accessboundsmap[owner]->get_base() ||
      effective_dispacement < accessboundsmap[owner]->get_bound())
      {
        // std::cout << "Boundover accessed by " << owner << '\n';
        std::exit(1);
      }
    }
  }
}

// mov  eax,DWORD PTR [rax+0x28]
// mov  eax,DWORD PTR [rbp+0x0]
VOID mov_mem_reg(uint64_t addr, CONTEXT * ctxt, Block &i, std::string disassins,
  std::string owner, int64_t displacement, int64_t scale, REG index_reg, REG base_reg, int64_t ins_size)
{
  // set the effective displacement
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

    if (i.objinfostack[owner]->get_obj() == "pointer"
      || i.objinfostack[owner]->get_obj() == "array")
    {
      if(accessboundsmap.find(owner) == accessboundsmap.end())
        accessboundsmap.insert(std::make_pair(owner, new AccessBounds(i.objinfostack[owner]->get_lb() +
      i.rbp_value, i.objinfostack[owner]->get_ub() + i.rbp_value)));
      // std::cout << "Base: " << accessboundsmap[owner]->get_base() << '\n';
      // std::cout << "Bound: " << accessboundsmap[owner]->get_bound() << '\n';
      // std::cout << "effective_dispacement: " << effective_dispacement << '\n';
      if (effective_dispacement >= accessboundsmap[owner]->get_base() ||
      effective_dispacement < accessboundsmap[owner]->get_bound())
      {
        // std::cout << "Boundover access detected. By " << owner << '\n';
        std::exit(1);
      }
    }
  }
  else if (globalobjinfostack.find(owner) != globalobjinfostack.end())
  {
    if (REG_valid(index_reg))
    { // if index register is present, add it
      effective_dispacement = displacement + PIN_GetContextReg(ctxt, base_reg)
      + (PIN_GetContextReg(ctxt, index_reg) * scale) + ins_size;
    }
    else
    { // if index register is not present
      effective_dispacement = PIN_GetContextReg(ctxt, base_reg) + displacement + ins_size;
    }
    if (globalobjinfostack[owner]->get_obj() == "pointer"
      || globalobjinfostack[owner]->get_obj() == "array")
    {
      if(accessboundsmap.find(owner) == accessboundsmap.end())
        accessboundsmap.insert(std::make_pair(owner, new AccessBounds(globalobjinfostack[owner]->get_lb(),
        globalobjinfostack[owner]->get_ub())));
      // std::cout << "Base: " << accessboundsmap[owner]->get_base() << '\n';
      // std::cout << "Bound: " << accessboundsmap[owner]->get_bound() << '\n';
      if (effective_dispacement >= accessboundsmap[owner]->get_base() ||
      effective_dispacement < accessboundsmap[owner]->get_bound())
      {
        // std::cout << "Boundover access detected. By " << owner << '\n';
        std::exit(1);
      }
    }
  }
}

VOID lea_arr(uint64_t addr, CONTEXT * ctxt, Block &i, std::string disassins,
  std::string owner, REG reg, int64_t ins_size)
{
  if (i.objinfostack.find(owner) != i.objinfostack.end())
  {
    if (i.objinfostack[owner]->get_obj() == "array")
    {
      if(accessboundsmap.find(owner) == accessboundsmap.end())
        accessboundsmap.insert(std::make_pair(owner, new AccessBounds(i.objinfostack[owner]->get_lb() +
      i.rbp_value, i.objinfostack[owner]->get_ub() + i.rbp_value)));
    }
  }
  else if (globalobjinfostack.find(owner) != globalobjinfostack.end())
  {
    if (globalobjinfostack[owner]->get_obj() == "array")
    {
      if(accessboundsmap.find(owner) == accessboundsmap.end())
        accessboundsmap.insert(std::make_pair(owner, new AccessBounds(globalobjinfostack[owner]->get_lb(),
        globalobjinfostack[owner]->get_ub())));
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
  // std::cout << hex << "rbp set: " << i.rbp_value << dec << '\n';
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
  // if (INS_IsCall(ins))
  //   std::cout << "disas: " << INS_Disassemble(ins) << '\n';

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
    // std::cout << "owner: " << owner << '\n';
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
  if (((INS_Opcode(ins) == XED_ICLASS_MOV) || (INS_Opcode(ins) == XED_ICLASS_MOVSS))
  && INS_OperandIsMemory(ins, 0)
  && ((INS_OperandWidth(ins, 0) == 8)
    || (INS_OperandWidth(ins, 0) == 16)
    || (INS_OperandWidth(ins, 0) == 32)
    || (INS_OperandWidth(ins, 0) == 64))
  && INS_OperandIsImmediate(ins, 1))
  {
    // Check if the rbp is not changed
    #ifdef RBP_DETECTION
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)rpb_check, IARG_ADDRINT,
    INS_Address(ins), IARG_CONTEXT, IARG_PTR, &(*i), IARG_PTR, new string(INS_Disassemble(ins)),
    IARG_END);
    #endif
    if (REG_StringShort(REG_FullRegName(INS_OperandMemoryBaseReg(ins, 0))) == "rbp")
    {
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)mov_immediate, IARG_ADDRINT,
      INS_Address(ins), IARG_CONTEXT, IARG_PTR, &(*i), IARG_PTR, new string(INS_Disassemble(ins)),
        IARG_PTR, new string(owner), IARG_ADDRINT, INS_OperandMemoryDisplacement(ins, 0),
        IARG_ADDRINT, INS_OperandMemoryScale(ins, 0),
        IARG_UINT32, REG(INS_OperandMemoryIndexReg(ins, 0)),
        IARG_UINT32, REG(INS_OperandMemoryBaseReg(ins, 0)), IARG_END);
    }
    else
    {
      // DWORD PTR [rax],0x4
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)mov_immediate2, IARG_ADDRINT,
      INS_Address(ins), IARG_CONTEXT, IARG_PTR, &(*i), IARG_PTR, new string(INS_Disassemble(ins)),
        IARG_PTR, new string(owner),
        IARG_ADDRINT, INS_OperandMemoryDisplacement(ins, 0),
        IARG_UINT32, REG(INS_OperandMemoryBaseReg(ins, 0)),
        IARG_UINT32, REG(INS_OperandMemoryIndexReg(ins, 0)),
        IARG_ADDRINT, INS_OperandMemoryScale(ins, 0),
        IARG_UINT32, INS_Size(ins),
        IARG_END);
    }
  }

  // mov  QWORD PTR [rbp-0x8],rax
  // mov  DWORD PTR [rax],rax
  // If operand is a register and operand width is 64
  if (((INS_Opcode(ins) == XED_ICLASS_MOV) || (INS_Opcode(ins) == XED_ICLASS_MOVSS))
  && INS_OperandIsMemory(ins, 0)
  && (INS_OperandWidth(ins, 0) == 64)
  && INS_OperandIsReg(ins, 1)
  && REG_StringShort(REG_FullRegName(INS_OperandReg(ins, 1))) != "rsi")
  {
    if (REG_StringShort(REG_FullRegName(INS_OperandMemoryBaseReg(ins, 0))) == "rbp")
    {
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)mov_reg, IARG_ADDRINT,
      INS_Address(ins), IARG_CONTEXT, IARG_PTR, &(*i), IARG_PTR, new string(INS_Disassemble(ins)),
        IARG_PTR, new string(owner), IARG_ADDRINT, INS_OperandMemoryDisplacement(ins, 0),
        IARG_ADDRINT, INS_OperandMemoryScale(ins, 0), IARG_UINT32, REG(INS_OperandMemoryIndexReg(ins, 0)),
        IARG_UINT32, REG(INS_OperandMemoryBaseReg(ins, 0)),
        IARG_UINT32, REG(INS_OperandReg(ins, 1)),
        IARG_UINT32, INS_Size(ins),
        IARG_END);
    }
    else
    {
      // mov  DWORD PTR [rax],eax
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)mov_reg, IARG_ADDRINT,
      INS_Address(ins), IARG_CONTEXT, IARG_PTR, &(*i), IARG_PTR, new string(INS_Disassemble(ins)),
        IARG_PTR, new string(owner), IARG_ADDRINT, INS_OperandMemoryDisplacement(ins, 0),
        IARG_ADDRINT, INS_OperandMemoryScale(ins, 0), IARG_UINT32, REG(INS_OperandMemoryIndexReg(ins, 0)),
        IARG_UINT32, REG(INS_OperandMemoryBaseReg(ins, 0)),
        IARG_UINT32, REG(INS_OperandReg(ins, 1)),
        IARG_UINT32, INS_Size(ins),
        IARG_END);
    }
  }

  // checks for rsi
  if (((INS_Opcode(ins) == XED_ICLASS_MOV) || (INS_Opcode(ins) == XED_ICLASS_MOVSS))
  && INS_OperandIsMemory(ins, 0)
  && (INS_OperandWidth(ins, 0) == 64)
  && INS_OperandIsReg(ins, 1)
  && REG_StringShort(REG_FullRegName(INS_OperandReg(ins, 1))) == "rsi")
  {
    if (owner.find(main_local) == std::string::npos)
    {
      return;
    }
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)rsi_check, IARG_ADDRINT,
    INS_Address(ins), IARG_CONTEXT, IARG_PTR, &(*i), IARG_PTR, new string(INS_Disassemble(ins)),
      IARG_PTR, new string(owner), IARG_ADDRINT, INS_OperandMemoryDisplacement(ins, 0),
      IARG_ADDRINT, INS_OperandMemoryScale(ins, 0), IARG_UINT32, REG(INS_OperandMemoryIndexReg(ins, 0)),
      IARG_UINT32, REG(INS_OperandMemoryBaseReg(ins, 0)),
      IARG_UINT32, REG(INS_OperandReg(ins, 1)),
      IARG_UINT32, INS_Size(ins),
      IARG_END);
  }

  // checks for rdi
  // mov  DWORD PTR [rbp-0xc],eax
  // mov  DWORD PTR [rax],eax
  if (((INS_Opcode(ins) == XED_ICLASS_MOV) || (INS_Opcode(ins) == XED_ICLASS_MOVSS))
  && INS_OperandIsMemory(ins, 0)
  && ((INS_OperandWidth(ins, 0) == 8) || (INS_OperandWidth(ins, 0) == 16)
      || (INS_OperandWidth(ins, 0) == 32))
  && INS_OperandIsReg(ins, 1)
  && REG_StringShort(REG_FullRegName(INS_OperandReg(ins, 1))) == "rdi")
  {
    if (owner.find(main_local) == std::string::npos)
    {
      return;
    }
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)rdi_check, IARG_ADDRINT,
    INS_Address(ins), IARG_CONTEXT, IARG_PTR, &(*i), IARG_PTR, new string(INS_Disassemble(ins)),
      IARG_PTR, new string(owner), IARG_ADDRINT, INS_OperandMemoryDisplacement(ins, 0),
      IARG_ADDRINT, INS_OperandMemoryScale(ins, 0), IARG_UINT32, REG(INS_OperandMemoryIndexReg(ins, 0)),
      IARG_UINT32, REG(INS_OperandMemoryBaseReg(ins, 0)),
      IARG_UINT32, REG_FullRegName(REG(INS_OperandReg(ins, 1))),
      IARG_UINT32, INS_Size(ins),
      IARG_END);
  }

  // mov  DWORD PTR [rbp-0xc],eax
  // mov  DWORD PTR [rax],eax
  if (((INS_Opcode(ins) == XED_ICLASS_MOV) || (INS_Opcode(ins) == XED_ICLASS_MOVSS))
  && INS_OperandIsMemory(ins, 0)
  && ((INS_OperandWidth(ins, 0) == 8) || (INS_OperandWidth(ins, 0) == 16)
      || (INS_OperandWidth(ins, 0) == 32))
  && INS_OperandIsReg(ins, 1)
  && REG_StringShort(REG_FullRegName(INS_OperandReg(ins, 1))) != "rdi")
  {
    if (REG_StringShort(REG_FullRegName(INS_OperandMemoryBaseReg(ins, 0))) == "rbp")
    {
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)mov_immediate, IARG_ADDRINT,
      INS_Address(ins), IARG_CONTEXT, IARG_PTR, &(*i), IARG_PTR, new string(INS_Disassemble(ins)),
        IARG_PTR, new string(owner), IARG_ADDRINT, INS_OperandMemoryDisplacement(ins, 0),
        IARG_ADDRINT, INS_OperandMemoryScale(ins, 0),
        IARG_UINT32, REG(INS_OperandMemoryIndexReg(ins, 0)),
        IARG_UINT32, REG(INS_OperandMemoryBaseReg(ins, 0)), IARG_END);
    }
    else
    {
      // DWORD PTR [rax],0x4
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)mov_immediate2, IARG_ADDRINT,
      INS_Address(ins), IARG_CONTEXT, IARG_PTR, &(*i), IARG_PTR, new string(INS_Disassemble(ins)),
        IARG_PTR, new string(owner),
        IARG_ADDRINT, INS_OperandMemoryDisplacement(ins, 0),
        IARG_UINT32, REG(INS_OperandMemoryBaseReg(ins, 0)),
        IARG_UINT32, REG(INS_OperandMemoryIndexReg(ins, 0)),
        IARG_ADDRINT, INS_OperandMemoryScale(ins, 0),
        IARG_UINT32, INS_Size(ins),
        IARG_END);
    }
  }

  // This is the actual pointer dereference
  // If the owner is an array, then the instruction would generally be like
  // mov eax,DWORD PTR [rbp+0x0]
  if (((INS_Opcode(ins) == XED_ICLASS_MOV) || (INS_Opcode(ins) == XED_ICLASS_MOVZX))
   && INS_OperandIsMemory(ins, 1)
  && ((INS_OperandWidth(ins, 1) == 8) || (INS_OperandWidth(ins, 1) == 16)
      || (INS_OperandWidth(ins, 1) == 32) || (INS_OperandWidth(ins, 1) == 64)))
  {
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)mov_mem_reg, IARG_ADDRINT,
    INS_Address(ins), IARG_CONTEXT, IARG_PTR, &(*i), IARG_PTR, new string(INS_Disassemble(ins)),
      IARG_PTR, new string(owner), IARG_ADDRINT, INS_OperandMemoryDisplacement(ins, 1),
      IARG_ADDRINT, INS_OperandMemoryScale(ins, 1), IARG_UINT32, REG(INS_OperandMemoryIndexReg(ins, 1)),
      IARG_UINT32, REG(INS_OperandMemoryBaseReg(ins, 1)),
      IARG_UINT32, INS_Size(ins),
      IARG_END);
  }

  // TODO: let's see if this instruction has any variations
  // mov  edi,0x4
  // if ((INS_Opcode(ins) == XED_ICLASS_MOV) &&
  // REG_FullRegName(INS_OperandReg(ins, 0)) == REG_RDI)
  // {
  //   INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)mov_mal_size, IARG_ADDRINT,
  //   INS_Address(ins), IARG_CONTEXT, IARG_PTR, &(*i), IARG_PTR, new string(INS_Disassemble(ins)),
  //     IARG_PTR, new string(owner),
  //     IARG_ADDRINT, INS_OperandImmediate(ins, 1),
  //     IARG_UINT32, REG(INS_OperandReg(ins, 1)), IARG_END);
  // }

  if (INS_Opcode(ins) == XED_ICLASS_LEA)
  {
    INS_InsertCall(ins, IPOINT_AFTER, (AFUNPTR)lea_arr, IARG_ADDRINT,
    INS_Address(ins), IARG_CONTEXT, IARG_PTR, &(*i), IARG_PTR, new string(INS_Disassemble(ins)),
      IARG_PTR, new string(owner), IARG_UINT32, REG(INS_OperandReg(ins, 0)),
      IARG_UINT32, INS_Size(ins),
      IARG_END);
  }
  // // mov  esi,0x2c
  // if ((INS_Opcode(ins) == XED_ICLASS_MOV) &&
  // REG_FullRegName(INS_OperandReg(ins, 0)) == REG_RSI &&
  //   i->objinfostack[owner]->get_obj() == "heap_pointer")
  // {
  //   return;
  //   INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)mov_mal_size, IARG_ADDRINT,
  //   INS_Address(ins), IARG_CONTEXT, IARG_PTR, &(*i), IARG_PTR, new string(INS_Disassemble(ins)),
  //     IARG_PTR, new string(owner),
  //     IARG_ADDRINT, INS_OperandImmediate(ins, 1),
  //     IARG_UINT32, REG(INS_OperandReg(ins, 1)), IARG_END);
  // }

  // std::cout << "disas: " << INS_Disassemble(ins) << '\n';

  // Detect the instructions like
  // mov  DWORD PTR [rbp-0xc],eax |or| mov  esi,eax
  // if ((INS_Opcode(ins) == XED_ICLASS_MOV)
  // && (INS_OperandIsMemory(ins, 0)
  // || (REG_StringShort(REG_FullRegName(INS_OperandReg(ins, 0))) == "rsi")
  // || (REG_StringShort(REG_FullRegName(INS_OperandReg(ins, 0))) == "rdi"))
  // && (INS_OperandIsReg(ins, 1)))
  // {
  //   INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)mov_mem_reg_3, IARG_ADDRINT,
  //   INS_Address(ins), IARG_CONTEXT, IARG_PTR, &(*i), IARG_PTR, new string(INS_Disassemble(ins)),
  //     IARG_PTR, new string(owner), IARG_ADDRINT, INS_MemoryDisplacement(ins), IARG_UINT32, REG(INS_OperandReg(ins, 1)), IARG_END);
  // }
  // if (i->objinfostack[owner]->get_obj() == "pointer")
  // {
  //   std::cout << hex << INS_Disassemble(ins) << dec << '\n';
  //   // if ((INS_Opcode(ins) == XED_ICLASS_MOV) && (INS_OperandIsReg(ins, 1)))
  // }
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
    while (count)
    {
      // Initialize the structure
      struct Block *block = new Block;
      // for the function name
      getline (myfile,line);
      block->name = line;
      block->rbp_value = 0;
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
            boost::split(temp, line, boost::is_any_of("\t "));
            block->inscodestack.insert(std::make_pair(strtol(temp[0].c_str(), NULL, 16), new InsInfo(strtol(temp[0].c_str(), NULL, 16), temp[1])));
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
            boost::split(temp, line, boost::is_any_of("\t "));
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
            boost::split(temp, line, boost::is_any_of("\t "));
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
          boost::split(temp, line, boost::is_any_of("\t "));
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
      for (auto j = v->get_ub(); j < v->get_lb(); ++j)
      {
        if(relPosStack.find(j) == relPosStack.end())
        {
          relPosStack.insert(std::make_pair(j, k));
        }
      }
    }
  }
  else std::cout << "Unable to open file\n";
}

// Lock Routines
void mutex_lock()
{
  key = 1;
  //std::cout<<"out\n";
}
void mutex_unlock()
{
	key = 0;
	//std::cout<<"in\n";
}

/********************Malloc routines**********************/

VOID MallocBefore(char *name, ADDRINT size, ADDRINT addrs)
{
  if (!key) return;
  if (addrs == '\0')
  {
    cerr << "Heap full!\n";
    return;
  }
  // Lazy size allocation
  // std::cout << "sizeof malloc: " << size << '\n';
  // std::cout << "lazyallocatedsize: " << lazyallocatedsize << '\n';
  lazyallocatedsize = size;
}

VOID MallocAfter(char *name, ADDRINT size, ADDRINT addrs)
{
  if (!key) return;
  if (addrs == '\0')
  {
    cerr << "Heap full!\n";
    return;
  }
  // cout << "malloc: " << addrs << " : " << lazyallocatedsize << "\n";
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
/**************End of Calloc routines******************/
/*******************Realloc routines******************/
VOID ReallocBefore(CHAR * name, ADDRINT addr, ADDRINT size, ADDRINT return_ip)
{
  if (!key) return;
  // std::cout << name << " : " << addr << "(" << size << ")" << " : " << return_ip << endl;
  // Check if it is already present in the map
  if (!lazyallocatedsize)
    lazyallocatedsize = size;
}

VOID ReallocAfter(ADDRINT ret)
{
  if (!key) return;
  if (ret == '\0')
  {
    cerr << "Heap full!\n";
    return;
  }
  // cout << "realloc: " << ret << " : " << lazyallocatedsize << "\n";
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
  if (!key) return;
  // std::cout << "returns: " <<  ret << '\n';
}

VOID FgetsBefore(CHAR * name, ADDRINT addr, ADDRINT size)
{
  if (!key) return;
  // check if the bounds are correct
  if(relPosStack.find(addr) != relPosStack.end())
  {
    std::string owner = relPosStack[addr];
    // std::cout << "size: " << accessboundsmap[owner]->get_base() << '\n';
    if (size > accessboundsmap[owner]->get_base() -
     accessboundsmap[owner]->get_bound())
    {
      // std::cout << "Boundover accessed by " << owner << '\n';
      std::exit(1);
    }
  }
  else
  {
    // std::cout << "Array/buffer bounds are not set" << '\n';
  }
}

VOID GetsBefore(CHAR * name, ADDRINT addr, ADDRINT size)
{
  if (!key) return;
  // check if the bounds are correct
  if(relPosStack.find(addr) != relPosStack.end())
  {
    std::string owner = relPosStack[addr];
    // std::cout << "size: " << accessboundsmap[owner]->get_base() << '\n';
    if (size > accessboundsmap[owner]->get_base() -
     accessboundsmap[owner]->get_bound())
    {
      // std::cout << "Boundover accessed by " << owner << '\n';
      std::exit(1);
    }
  }
  else
  {
    // std::cout << "Array/buffer bounds are not set" << '\n';
  }
}

void Image(IMG img, VOID *v)
{
  RTN mainrtn = RTN_FindByName(img, "main");
  if (RTN_Valid(mainrtn))
    {
        // std::cout << "Routine " << RTN_Name(mainrtn)<< '\n';
        RTN_Open(mainrtn);
        // Apply the locks to the main routine
        RTN_InsertCall(mainrtn, IPOINT_BEFORE, (AFUNPTR)mutex_lock, IARG_END);
        RTN_InsertCall(mainrtn, IPOINT_AFTER, (AFUNPTR)mutex_unlock, IARG_END);
        RTN_Close(mainrtn);
    }
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
                      IARG_ADDRINT, "malloc",
                      IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
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
  RTN freeRtn = RTN_FindByName(img, FREE);
  if (RTN_Valid(freeRtn))
    {
        RTN_Open(freeRtn);
        // Instrument malloc() to print the input argument value and the return value.
        RTN_InsertCall(freeRtn, IPOINT_BEFORE, (AFUNPTR)FreeBefore,
                       IARG_FUNCRET_EXITPOINT_VALUE,
                       IARG_END);
        RTN_Close(freeRtn);
    }
    // fgets
    RTN fgetsRtn = RTN_FindByName(img, FGETS);
    if (RTN_Valid(fgetsRtn))
      {
          RTN_Open(fgetsRtn);
          // Apply the locks to the main routine
          RTN_InsertCall(fgetsRtn, IPOINT_BEFORE, (AFUNPTR)FgetsBefore,
                        IARG_ADDRINT, "fgets",
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                        IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                        IARG_END);
          RTN_Close(fgetsRtn);
      }
      // gets
      RTN getsRtn = RTN_FindByName(img, GETS);
      if (RTN_Valid(getsRtn))
        {
            RTN_Open(getsRtn);
            // Apply the locks to the main routine
            RTN_InsertCall(getsRtn, IPOINT_BEFORE, (AFUNPTR)GetsBefore,
                          IARG_ADDRINT, "gets",
                          IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                          IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
                          IARG_END);
            RTN_Close(getsRtn);
        }
}

int main(int argc, char * argv[])
{
    // Initialize pin
    PIN_InitSymbols();
    if (PIN_Init(argc, argv)) return Usage();
    // Argv[6] is the program image
    ProgramImage = argv[6];
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
