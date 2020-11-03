
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
#include "llvm/Support/raw_ostream.h"
#include "llvm/Support/JSON.h"

#include <utility>
#include <map>
#include <set>
#include <string>

#define DEBUG_TYPE "dyn-untrusted"

using namespace llvm;

namespace {
class IDGenerator {
  unsigned int id;

public:
  IDGenerator() : id(0) {}

  ConstantInt *getConstID(Module &M) {
    return llvm::ConstantInt::get(IntegerType::getInt64Ty(M.getContext()),
                                  id++);
  }

  ConstantInt *getDummyID(Module &M) {
    return llvm::ConstantInt::get(IntegerType::getInt64Ty(M.getContext()), -1);
  }
};

static IDGenerator IDG;

struct FaultingSite {
  uint64_t uniqueID;
  int64_t pkey;
};

class DynUntrustedAllocPost : public ModulePass {
public:
  static char ID;

  DynUntrustedAllocPost() : ModulePass(ID) {
    initializeDynUntrustedAllocPostPass(*PassRegistry::getPassRegistry());
  }
  virtual ~DynUntrustedAllocPost() = default;

  bool runOnModule(Module &M) override {
    // Post inliner pass, iterate over all functions and find hook CallSites.
    // Assign a unique ID in a deterministic pattern to ensure UniqueID is
    // consistent between runs.
    assignUniqueIDs(M);
    fixFaultedAllocations(M, getFaultingAllocList());

    return true;
  }

  bool fromJSON(const llvm::json::Value Alloc, FaultingSite &F) {
    llvm::json::ObjectMapper O(Alloc);
    int64_t temp;
    bool temp_result = O.map("id", temp);
    if (temp < 0) {
      return false;
    }
    F.uniqueID = static_cast<uint64_t>(temp);
    return O && temp_result && O.map("pkey", F.pkey);
  }

  std::set<FaultingSite> getFaultingAllocList() {
    // TODO : Somehow we need to get the path to the .json file containing faults.
    std::set<FaultingSite> fault_set;

    return fault_set;
  }

  int getArgIndexForPatch(Function *hook) {
    assert(hook && "Nullptr: Invalid function to hook");
    auto hookFns = getHookFuncs(*hook->getParent());
    if (hook == hookFns[0]) {
      return 2;
      // allocHook
    } else if (hook == hookFns[1]) {
      return 4;
      // mallocHook
    } else if (hook == hookFns[2]) {
      // deallocHook
      return 2;
    }
    return -1;
  }

  SmallVector<Function *, 3> getHookFuncs(Module &M) {
    std::string hookFuncNames[3] = {"allocHook", "reallocHook", "deallocHook"};
    SmallVector<Function *, 3> hookFns;
    for (auto hookName : hookFuncNames) {
      Function *F = M.getFunction(hookName);
      if (!F)
        continue;

      hookFns.push_back(F);
    }
    return hookFns;
  }

  static bool funcSort(Function *F1, Function *F2) {
    return F1->getName().data() > F2->getName().data();
  }

  void assignUniqueIDs(Module &M) {
    std::vector<Function *> WorkList;
    for (Function &FRef : M) {
      Function *F = &FRef;
      if (!F)
        continue;

      if (F->isDeclaration())
        continue;

      WorkList.push_back(F);
    }

    std::sort(WorkList.begin(), WorkList.end(), funcSort);

    LLVM_DEBUG(errs() << "Search for modified functions!\n");

    for (auto *F : llvm::reverse(WorkList)) {
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

          auto index = getArgIndexForPatch(hook);
          if (index == -1) {
            continue;
          }

          BasicBlock::iterator iter(CS.getInstruction());
          auto prev_inst = BB->getInstList().getPrevNode(*CS.getInstruction());
          auto id = IDG.getConstID(M);

          CS.setArgument(index, id);
          LLVM_DEBUG(errs() << "modified callsite:\n");
          LLVM_DEBUG(errs() << *CS.getInstruction() << "\n");

          if (!prev_inst)
            continue;

          CallSite CSPrev(prev_inst);
          if (!CSPrev)
            continue;

          LLVM_DEBUG(errs() << "Adding: " << CSPrev.getCalledFunction()->getName().data() << " callsite for allocID: " << id->getZExtValue() << "\n");
          alloc_map.insert(std::pair<uint64_t, Instruction *>(id->getZExtValue(), prev_inst));
        }
      }
    }
  }

  void fixFaultedAllocations(Module &M, std::set<FaultingSite> FS) {
    if (FS.empty()) {
      return;
    }

    for (auto fsite : FS) { 
      auto map_iter = alloc_map.find(fsite.uniqueID);
      if (map_iter == alloc_map.end()) {
        LLVM_DEBUG(errs() << "Cannot find unique allocation id: " << fsite.uniqueID << "\n");
        continue;
      }

      Instruction *I = map_iter->second;
      // TODO : We need to alter this instruction somehow.
    }
  }

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    AU.addRequired<CallGraphWrapperPass>();
  }

private:
  std::map<uint64_t, Instruction *> alloc_map;
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

ModulePass *llvm::createDynUntrustedAllocPostPass() {
  return new DynUntrustedAllocPost();
}

PreservedAnalyses DynUntrustedAllocPostPass::run(Module &M,
                                                 ModuleAnalysisManager &AM) {
  DynUntrustedAllocPost dyn;
  if (!dyn.runOnModule(M)) {
    return PreservedAnalyses::all();
  }

  return PreservedAnalyses::none();
}
