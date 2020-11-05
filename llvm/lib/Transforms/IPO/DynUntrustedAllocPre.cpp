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
ConstantInt *getDummyID(Module &M) {
  return llvm::ConstantInt::get(IntegerType::getInt64Ty(M.getContext()), -1);
}

class DynUntrustedAllocPre : public ModulePass {
public:
  static char ID;

  DynUntrustedAllocPre() : ModulePass(ID) {
    initializeDynUntrustedAllocPrePass(*PassRegistry::getPassRegistry());
  }
  virtual ~DynUntrustedAllocPre() = default;

  bool runOnModule(Module &M) override {
    // Pre-inline pass:
    // Adds function hooks with dummy UniqueIDs immediately after calls
    // to __rust_alloc* functions. Additionally, we must remove the
    // NoInline attribute from RustAlloc functions.

    AttrBuilder attrBldr;
    attrBldr.addAttribute(Attribute::NoUnwind);
    attrBldr.addAttribute(Attribute::ArgMemOnly);

    AttributeList fnAttrs = AttributeList::get(
        M.getContext(), AttributeList::FunctionIndex, attrBldr);

    // Make function hook to add to all functions we wish to track
    Constant *allocHookFunc = M.getOrInsertFunction(
        "allocHook", fnAttrs, Type::getVoidTy(M.getContext()),
        Type::getInt8PtrTy(M.getContext()),
        IntegerType::get(M.getContext(), 64),
        IntegerType::getInt64Ty(M.getContext()));
    allocHook = cast<Function>(allocHookFunc);
    // set its linkage
    allocHook->setLinkage(GlobalValue::LinkageTypes::ExternalLinkage);

    Constant *reallocHookFunc = M.getOrInsertFunction(
        "reallocHook", fnAttrs, Type::getVoidTy(M.getContext()),
        Type::getInt8PtrTy(M.getContext()),
        IntegerType::get(M.getContext(), 64),
        Type::getInt8PtrTy(M.getContext()),
        IntegerType::get(M.getContext(), 64),
        IntegerType::getInt64Ty(M.getContext()));
    reallocHook = cast<Function>(reallocHookFunc);
    reallocHook->setLinkage(GlobalValue::LinkageTypes::ExternalLinkage);

    Constant *deallocHookFunc = M.getOrInsertFunction(
        "deallocHook", fnAttrs, Type::getVoidTy(M.getContext()),
        Type::getInt8PtrTy(M.getContext()),
        IntegerType::get(M.getContext(), 64),
        IntegerType::getInt64Ty(M.getContext()));
    deallocHook = cast<Function>(deallocHookFunc);
    deallocHook->setLinkage(GlobalValue::LinkageTypes::ExternalLinkage);

    hookFunctions(M);

    // Remove inline attribute from functions for inlining.
    removeInlineAttr(M);
    return true;
  }

  Instruction *getHookInst(Module &M, CallSite *CS) {
    Function *F = CS->getCalledFunction();
    if (!F)
      return nullptr;

    if (F == M.getFunction("__rust_alloc") || F == M.getFunction("__rust_alloc_zeroed")) {
      return CallInst::Create((Function *)allocHook,
        {CS->getInstruction(), CS->getArgument(0), getDummyID(M)});
    } else if (F == M.getFunction("__rust_realloc")) {
      return CallInst::Create(
          (Function *)reallocHook, {CS->getInstruction(), CS->getArgument(3), CS->getArgument(0),
            CS->getArgument(1), getDummyID(M)});
    } else if (F == M.getFunction("__rust_dealloc")) {
      return CallInst::Create(
          (Function *)deallocHook,
          {CS->getArgument(0), CS->getArgument(1), getDummyID(M)});
    } else {
      return nullptr;
    }
  }

  void hookFunctions(Module &M) {
    for (Function &FRef : M) {
      Function *F = &FRef;
      if (!F)
        continue;
      
      if (F->isDeclaration())
        continue;

      ReversePostOrderTraversal<Function *> RPOT(F);

      for (BasicBlock *BB : RPOT) {
        for (Instruction &I : *BB) {
          CallSite CS(&I);
          if (!CS) {
            continue;
          }

          Instruction *newHook = getHookInst(M, &CS);
          // Check to make sure new hook is not void
          if (!newHook)
            continue;

          BasicBlock::iterator bbIter((Instruction *)CS.getInstruction());
          bbIter++;
          BB->getInstList().insert(bbIter, newHook);
        }
      }

    }
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
