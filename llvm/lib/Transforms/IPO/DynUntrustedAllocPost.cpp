
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
#include "llvm/Support/JSON.h"
#include "llvm/Support/MemoryBuffer.h"

#include <map>
#include <set>
#include <string>
#include <utility>

#define DEBUG_TYPE "dyn-untrusted"

using namespace llvm;

namespace {
/// A mapping between hook function and the position of the UniqueID argument.
const static std::map<std::string, int> patchArgIndexMap = {
    {"allocHook", 2}, {"reallocHook", 4}, {"deallocHook", 2}};

class IDGenerator {
  uint64_t id;

public:
  IDGenerator() : id(0) {}

  ConstantInt *getConstID(Module &M) {
    return llvm::ConstantInt::get(IntegerType::getInt64Ty(M.getContext()),
                                  id++);
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
  std::string filename;

  DynUntrustedAllocPost(std::string fault_path = "")
      : ModulePass(ID), filename(fault_path) {
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

  std::vector<FaultingSite> getFaultingAllocList() {
    std::vector<FaultingSite> fault_set;
    // If no path provided, return empty set.
    if (filename.empty())
      return fault_set;

    llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>> File =
        MemoryBuffer::getFile(filename);
    std::error_code ec = File.getError();

    if (ec) {
      LLVM_DEBUG(errs() << "File could not be read: " << ec.message() << "\n");
      return fault_set;
    }

    Expected<json::Value> ParseResult =
        json::parse(File.get().get()->getBuffer());
    if (Error E = ParseResult.takeError()) {
      LLVM_DEBUG(errs() << "Failed to Parse JSON array: " << E << "\n");
      consumeError(std::move(E));
      return fault_set;
    }

    if (!ParseResult->getAsArray()) {
      LLVM_DEBUG(errs() << "Failed to get JSON Value as JSON array.\n");
      return fault_set;
    }

    for (const auto &Alloc : *ParseResult->getAsArray()) {
      FaultingSite FS;
      if (fromJSON(Alloc, FS))
        fault_set.push_back(FS);
    }

    return fault_set;
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

          LLVM_DEBUG(errs() << "Adding: "
                            << CSPrev.getCalledFunction()->getName().data()
                            << " callsite for allocID: " << id->getZExtValue()
                            << "\n");
          alloc_map.insert(std::pair<uint64_t, Instruction *>(
              id->getZExtValue(), prev_inst));
        }
      }
    }
  }

  void fixFaultedAllocations(Module &M, std::vector<FaultingSite> FS) {
    if (FS.empty()) {
      return;
    }

    for (auto fsite : FS) {
      auto map_iter = alloc_map.find(fsite.uniqueID);
      if (map_iter == alloc_map.end()) {
        LLVM_DEBUG(errs() << "Cannot find unique allocation id: "
                          << fsite.uniqueID << "\n");
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

ModulePass *llvm::createDynUntrustedAllocPostPass(std::string fault_path) {
  return new DynUntrustedAllocPost(fault_path);
}

PreservedAnalyses DynUntrustedAllocPostPass::run(Module &M,
                                                 ModuleAnalysisManager &AM) {
  DynUntrustedAllocPost dyn(FaultPath);
  if (!dyn.runOnModule(M)) {
    return PreservedAnalyses::all();
  }

  return PreservedAnalyses::none();
}
