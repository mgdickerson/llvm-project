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

#include "llvm/Transforms/IPO/DynUntrustedAllocPre.h"
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

class DynUntrustedAllocPre : public ModulePass {
public:
  static char ID;

  DynUntrustedAllocPre() : ModulePass(ID) {
    initializeDynUntrustedAllocPassPre(*PassRegistry::getPassRegistry());
  }
  virtual ~DynUntrustedAllocPre() = default;

  bool runOnModule(Module &M) override {
    // Pre-inline pass:
    // Adds function hooks with dummy UniqueIDs immediately after calls
    // to __rust_alloc* functions. Additionally, we must remove the
    // NoInline attribute from RustAlloc functions.

    // Make function hook to add to all functions we wish to track
    Constant *allocHookFunc =
        M.getOrInsertFunction("allocHook", Type::getVoidTy(M.getContext()),
                              Type::getInt8PtrTy(M.getContext()),
                              IntegerType::get(M.getContext(), 64),
                              IntegerType::getInt64Ty(M.getContext()));
    allocHook = cast<Function>(allocHookFunc);

    Constant *reallocHookFunc =
        M.getOrInsertFunction("reallocHook", Type::getVoidTy(M.getContext()),
                              Type::getInt8PtrTy(M.getContext()),
                              IntegerType::get(M.getContext(), 64),
                              Type::getInt8PtrTy(M.getContext()),
                              IntegerType::get(M.getContext(), 64),
                              IntegerType::getInt64Ty(M.getContext()));
    reallocHook = cast<Function>(reallocHookFunc);

    Constant *deallocHookFunc =
        M.getOrInsertFunction("deallocHook", Type::getVoidTy(M.getContext()),
                              Type::getInt8PtrTy(M.getContext()),
                              IntegerType::get(M.getContext(), 64),
                              IntegerType::getInt64Ty(M.getContext()));
    deallocHook = cast<Function>(deallocHookFunc);

    hookAllocFunctions(M);

    // Remove inline attribute from functions for inlining.
    removeInlineAttr(M);
    return true;
  }

  /// Iterate over all functions we are looking for, and instrument them with
  /// hooks accordingly
  void hookAllocFunctions(Module &M) {
    hookFunction(M, "__rust_alloc", allocHook);
    hookFunction(M, "__rust_alloc_zeroed", allocHook);
    hookFunction(M, "__rust_realloc", reallocHook);
    hookFunction(M, "__rust_dealloc", deallocHook);
  }

  void hookFunction(Module &M, std::string Name, Function *Hook) {
    Function *F = M.getFunction(Name);
    if(!F)
      return;

    for (auto caller : F->users()) {
      CallSite CS(caller);
      if (!CS) {
        continue;
      }

      addFunctionHooks(M, &CS, Hook);
    }
  }

  /// Add function hook after call site instruction. Initially place a dummy
  /// UUID, to be replaced in structured ascent later. Additional information
  /// required for hook: Size of allocation, and return address.
  void addFunctionHooks(Module &M, CallSite *CS, Function *hookInst) {
    // Get CallSite instruction and containing BasicBlock
    Instruction *CSInst = CS->getInstruction();
    BasicBlock *BB = CS->getParent();

    Instruction *newHookInst;
    if (hookInst == allocHook) {
      newHookInst = CallInst::Create(
        (Function *)hookInst, {CSInst, CS->getArgument(0), IDG.getDummyID(M)});
    } else if (hookInst == reallocHook) {
      newHookInst = CallInst::Create(
        (Function *)hookInst, {CSInst, CS->getArgument(3), CS->getArgument(0), CS->getArgument(1), IDG.getDummyID(M)}
      );
    } else if (hookInst == deallocHook) {
      newHookInst = CallInst::Create(
        (Function *)hookInst, {CS->getArgument(0), CS->getArgument(1), IDG.getDummyID(M)}
      );
    } else {
      LLVM_DEBUG(errs() << "Attempted to add hook to non-hook function!\n");
    }
    // Insert hook call after call site instruction
    BasicBlock::iterator bbIter((Instruction *)CSInst);
    bbIter++;
    BB->getInstList().insert(bbIter, (Instruction *)newHookInst);
  }

  /// Iterate all Functions of Module M, remove NoInline attribute from
  /// Functions with RustAllocator attribute.
  void removeInlineAttr(Module &M) {
    for (Function &F : M) {
      if (F.hasFnAttribute(Attribute::RustAllocator)) {
        F.removeFnAttr(Attribute::NoInline);
      }
    }
  }

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    AU.addRequired<CallGraphWrapperPass>();
  }

private:
  Function *allocHook;
  Function *reallocHook;
  Function *deallocHook;
};

char DynUntrustedAllocPre::ID = 0;
} // namespace

INITIALIZE_PASS_BEGIN(DynUntrustedAllocPre, "dyn-untrusted-pre",
                      "DynUntrustedAlloc: Patch allocation sites with dynamic "
                      "function hooks for tracking allocation IDs.",
                      false, false)
INITIALIZE_PASS_DEPENDENCY(CallGraphWrapperPass)
INITIALIZE_PASS_END(DynUntrustedAllocPre, "dyn-untrusted-pre",
                    "DynUntrustedAlloc: Patch allocation sites with dynamic "
                    "function hooks for tracking allocation IDs.",
                    false, false)

ModulePass *llvm::createDynUntrustedAllocPrePass() {
  return new DynUntrustedAllocPre();
}

PreservedAnalyses DynUntrustedAllocPrePass::run(Module &M,
                                             ModuleAnalysisManager &AM) {
  DynUntrustedAllocPre dyn;
  if (!dyn.runOnModule(M)) {
    return PreservedAnalyses::all();
  }

  return PreservedAnalyses::none();
}
