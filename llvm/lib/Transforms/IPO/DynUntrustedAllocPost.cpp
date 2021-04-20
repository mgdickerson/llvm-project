
//===-- UntrustedAlloc.cpp - UntrustedAlloc Infrastructure ---------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines the common initialization infrastructure for the
// DynUntrustedAlloc library.
//
//===----------------------------------------------------------------------===//

#include "llvm/Transforms/IPO/DynUntrustedAllocPost.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/PostOrderIterator.h"
#include "llvm/ADT/SCCIterator.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Analysis/CallGraph.h"
#include "llvm/Analysis/LazyCallGraph.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/CallSite.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Type.h"
#include "llvm/Support/ErrorOr.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/JSON.h"
#include "llvm/Support/MemoryBuffer.h"
#include "llvm/Support/Path.h"
#include "llvm/Transforms/Utils/Local.h"

#include <fstream>
#include <map>
#include <string>
#include <utility>
#include <vector>

#define DEBUG_TYPE "dyn-untrusted"
#define MPK_STATS

using namespace llvm;

static cl::opt<std::string>
    MPKTestProfilePath("mpk-test-profile-path", cl::init(""), cl::Hidden,
                       cl::value_desc("filename"),
                       cl::desc("Specify the path of profile data file. This is"
                                "mainly for test purpose."));

static cl::opt<bool>
    MPKTestRemoveHooks("mpk-test-remove-hooks", cl::init(false), cl::Hidden,
                       cl::desc("Remove hook instructions. This is mainly"
                                "for test purpose."));

namespace {
#ifdef MPK_STATS
// Ensure we assign a unique ID to the same number of hooks as we made in the
// Pre pass.
uint64_t total_hooks = 0;
// Count the number of modified Alloc instructions
uint64_t modified_inst_count = 0;
#endif

/// A mapping between hook function and the position of the UniqueID argument.
const static std::map<std::string, int> patchArgIndexMap = {
    {"allocHook", 2}, {"reallocHook", 4}, {"deallocHook", 2}};

// Currently only patching __rust_alloc and __rust_alloc_zeroed
const static std::map<std::string, std::string> AllocReplacementMap = {
    {"__rust_alloc", "__rust_untrusted_alloc"},
    {"__rust_alloc_zeroed", "__rust_untrusted_alloc_zeroed"},
    {"__rust_realloc", "__rust_untrusted_realloc"},
};

std::vector<Instruction *> hookList;

class IDGenerator {
  uint64_t id;

public:
  IDGenerator() : id(0) {}

  ConstantInt *getConstID(Module &M) {
    return llvm::ConstantInt::get(IntegerType::getInt64Ty(M.getContext()),
                                  id++);
  }

  ConstantInt *getConstIntCount(Module &M) {
    return llvm::ConstantInt::get(IntegerType::getInt64Ty(M.getContext()), id);
  }
};

static IDGenerator IDG;

struct FaultingSite {
  uint64_t uniqueID;
  uint32_t pkey;
};

class DynUntrustedAllocPost : public ModulePass {
public:
  static char ID;
  std::string mpk_profile_path;
  bool remove_hooks;

  DynUntrustedAllocPost(std::string mpk_profile_path = "",
                        bool remove_hooks = false)
      : ModulePass(ID), mpk_profile_path(mpk_profile_path),
        remove_hooks(remove_hooks) {
    initializeDynUntrustedAllocPostPass(*PassRegistry::getPassRegistry());
  }
  virtual ~DynUntrustedAllocPost() = default;

  bool runOnModule(Module &M) override {
    /*if (!M.getFunction("allocHook") && !M.getFunction("reallocHook") && !M.getFunction("deallocHook")) {
      // It is likely at this stage that if none of the above are present, DynUntrustedAllocPre did not run.
      // Thus, we should skip this pass as well.
      return true;
    }*/
    // Additional flags for easier testing with opt.
    if (mpk_profile_path.empty() && !MPKTestProfilePath.empty())
      mpk_profile_path = MPKTestProfilePath;
    if (MPKTestRemoveHooks)
      remove_hooks = MPKTestRemoveHooks;

    // Post inliner pass, iterate over all functions and find hook CallSites.
    // Assign a unique ID in a deterministic pattern to ensure UniqueID is
    // consistent between runs.
    assignUniqueIDs(M);

    if (remove_hooks)
      removeHooks(M);

    removeInlineAttr(M);

#ifdef MPK_STATS
    printStats(M);

    // If MPK_STATS is enables, then we create a global containing the value of
    // the total number of allocation sites
    GlobalVariable *AllocSiteTotal = cast<GlobalVariable>(M.getOrInsertGlobal(
        "AllocSiteTotal", IntegerType::getInt64Ty(M.getContext())));
    AllocSiteTotal->setInitializer(IDG.getConstIntCount(M));
#endif

    return true;
  }

  bool fromJSON(const llvm::json::Value &Alloc, FaultingSite &F) {
    llvm::json::ObjectMapper O(Alloc);

    int64_t temp_id;
    bool temp_id_result = O.map("id", temp_id);
    if (temp_id < 0)
      return false;

    int64_t temp_pkey;
    bool temp_pkey_result = O.map("pkey", temp_pkey);
    if (temp_pkey < 0)
      return false;

    F.uniqueID = static_cast<uint64_t>(temp_id);
    F.pkey = static_cast<uint32_t>(temp_pkey);

    return O && temp_id_result && temp_pkey_result;
  }

  std::vector<std::string> getFaultPaths() {
    std::vector<std::string> fault_files;
    if (llvm::sys::fs::is_directory(mpk_profile_path)) {
      std::error_code EC;
      for (llvm::sys::fs::directory_iterator F(mpk_profile_path, EC), E;
           F != E && !EC; F.increment(EC)) {
        auto file_extension = llvm::sys::path::extension(F->path());
        if (StringSwitch<bool>(file_extension.lower())
                .Case(".json", true)
                .Default(false)) {
          fault_files.push_back(F->path());
        }
      }
    } else {
      fault_files.push_back(mpk_profile_path);
    }

    return fault_files;
  }

  Optional<json::Array> parseJSONArrayFile(llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>> File) {
    std::error_code ec = File.getError();
    if (ec) {
      LLVM_DEBUG(errs() << "File could not be read: " << ec.message()
                        << "\n");
      return None;
    }

    Expected<json::Value> ParseResult =
        json::parse(File.get().get()->getBuffer());
    if (Error E = ParseResult.takeError()) {
      LLVM_DEBUG(errs() << "Failed to Parse JSON array: " << E << "\n");
      consumeError(std::move(E));
      return None;
    }

    if (!ParseResult->getAsArray()) {
      LLVM_DEBUG(errs() << "Failed to get JSON Value as JSON array.\n");
      return None;
    }

    return *ParseResult->getAsArray();
  }

  std::map<uint64_t, FaultingSite> getFaultingAllocMap() {
    std::map<uint64_t, FaultingSite> fault_map;
    // If no path provided, return empty set.
    if (mpk_profile_path.empty())
      return fault_map;

    for (std::string path : getFaultPaths()) {
      auto ParseResult = parseJSONArrayFile(MemoryBuffer::getFile(path));
      if (!ParseResult)
        continue;

      for (const auto &Alloc : ParseResult.getValue()) {
        FaultingSite FS;
        if (fromJSON(Alloc, FS))
          fault_map.insert(std::pair<uint64_t, FaultingSite>(FS.uniqueID, FS));
      }
    }

    LLVM_DEBUG(errs() << "Returning successful fault_set.\n");
    return fault_map;
  }

  static bool funcSort(Function *F1, Function *F2) {
    return F1->getName().str() > F2->getName().str();
  }

  void assignUniqueIDs(Module &M) {
    std::vector<Function *> WorkList;
    for (Function &F : M) {
      if (!F.isDeclaration())
        WorkList.push_back(&F);
    }

    std::sort(WorkList.begin(), WorkList.end(), funcSort);

    LLVM_DEBUG(errs() << "Search for modified functions!\n");

    auto fault_map = getFaultingAllocMap();

    for (Function *F : WorkList) {
      ReversePostOrderTraversal<Function *> RPOT(F);

      for (BasicBlock *BB : RPOT) {
        for (Instruction &I : *BB) {
          CallSite CS(&I);
          if (!CS) {
            continue;
          }

          Function *hook = CS.getCalledFunction();
          if (!hook)
            continue;

          // Get patch index from map.
          auto index_iter = patchArgIndexMap.find(hook->getName().str());
          if (index_iter == patchArgIndexMap.end())
            continue;

          auto index = index_iter->second;

          // Set UniqueID for hook function
          auto callInst = CS.getInstruction();
          auto id = IDG.getConstID(M);
          CS.setArgument(index, id);

#ifdef MPK_STATS
          ++total_hooks;
#endif

          if (remove_hooks)
            hookList.push_back(callInst);

          // If provided a valid path, modify given instruction
          if (!mpk_profile_path.empty()) {
            assert(!fault_map.empty() && "No Faulting Allocation to patch!");
            // Get Call Instr that hook references
            auto allocFunc = CS.getArgument(0);
            if (auto *allocInst = dyn_cast<CallBase>(allocFunc)) {

              // Check to see if ID is in fault set for patching
              auto map_iter = fault_map.find(id->getZExtValue());
              if (map_iter == fault_map.end())
                continue;

              LLVM_DEBUG(errs() << "modified callsite:\n");
              LLVM_DEBUG(errs() << *CS.getInstruction() << "\n");

              patchInstruction(M, allocInst);
            }
          }
        }
      }
    }
  }

  void patchInstruction(Module &M, CallBase *inst) {
    auto calledFuncName = inst->getCalledFunction()->getName().str();
    auto repl_iter = AllocReplacementMap.find(calledFuncName);
    if (repl_iter == AllocReplacementMap.end())
      return;

    auto replacementFunctionName = repl_iter->second;

    Function *repl_func = M.getFunction(replacementFunctionName);
    if (!repl_func) {
      LLVM_DEBUG(
          errs() << "ERROR while creating patch: Could not find replacement: "
                 << replacementFunctionName << "\n");
      return;
    }

    inst->setCalledFunction(repl_func);
    LLVM_DEBUG(errs() << "Modified CallInstruction: " << *inst << "\n");
#ifdef MPK_STATS
    ++modified_inst_count;
#endif
  }

  void removeHooks(Module &M) {
    for (auto inst : hookList) {
      salvageDebugInfo(*inst);
      inst->eraseFromParent();
    }

    auto allocHook = M.getFunction("allocHook");
    //assert(allocHook != nullptr && "Cannot find allocHook for removal!");
    auto reallocHook = M.getFunction("reallocHook");
    auto deallocHook = M.getFunction("deallocHook");

    allocHook->setLinkage(GlobalValue::LinkageTypes::InternalLinkage);
    allocHook->eraseFromParent();


    reallocHook->setLinkage(GlobalValue::LinkageTypes::InternalLinkage);
    reallocHook->eraseFromParent();

    deallocHook->setLinkage(GlobalValue::LinkageTypes::InternalLinkage);
    deallocHook->eraseFromParent();
  }

  /// Iterate all Functions of Module M, remove NoInline attribute from
  /// Functions with RustAllocator attribute.
  void removeInlineAttr(Module &M) {
    for (Function &F : M) {
      if (F.hasFnAttribute(Attribute::RustAllocator)) {
        F.removeFnAttr(Attribute::NoInline);
        F.addFnAttr(Attribute::AlwaysInline);
      }
    }
  }

#ifdef MPK_STATS
  void printStats(Module &M) {
    std::string TestDirectory = "TestResults";
    if (!llvm::sys::fs::is_directory(TestDirectory))
      llvm::sys::fs::create_directory(TestDirectory);

    llvm::Expected<llvm::sys::fs::TempFile> PreStats =
        llvm::sys::fs::TempFile::create(TestDirectory +
                                        "/static-post-%%%%%%%.stat");
    if (!PreStats) {
      LLVM_DEBUG(errs() << "Error making unique filename: "
                        << llvm::toString(PreStats.takeError()) << "\n");
      return;
    }

    llvm::raw_fd_ostream OS(PreStats->FD, /* shouldClose */ false);
    OS << "Number of alloc instructions modified to unsafe: "
       << modified_inst_count << "\n"
       << "Total number hooks given a UniqueID: " << total_hooks << "\n";
    OS.flush();

    if (auto E = PreStats->keep()) {
      LLVM_DEBUG(errs() << "Error keeping pre-stats file: "
                        << llvm::toString(std::move(E)) << "\n");
      return;
    }
  }
#endif

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    AU.addRequired<CallGraphWrapperPass>();
  }
};

char DynUntrustedAllocPost::ID = 0;

} // namespace

INITIALIZE_PASS_BEGIN(DynUntrustedAllocPost, "dyn-untrusted-post",
                      "DynUntrustedAlloc: Patch allocation sites with dynamic "
                      "function hooks for tracking allocation IDs.",
                      false, false)
INITIALIZE_PASS_DEPENDENCY(CallGraphWrapperPass)
INITIALIZE_PASS_END(DynUntrustedAllocPost, "dyn-untrusted-post",
                    "DynUntrustedAlloc: Patch allocation sites with dynamic "
                    "function hooks for tracking allocation IDs.",
                    false, false)

ModulePass *
llvm::createDynUntrustedAllocPostPass(std::string mpk_profile_path = "",
                                      bool remove_hooks = false) {
  return new DynUntrustedAllocPost(mpk_profile_path, remove_hooks);
}

PreservedAnalyses DynUntrustedAllocPostPass::run(Module &M,
                                                 ModuleAnalysisManager &AM) {
  DynUntrustedAllocPost dyn(MPKProfilePath, RemoveHooks);
  if (!dyn.runOnModule(M)) {
    return PreservedAnalyses::all();
  }

  return PreservedAnalyses::none();
}
