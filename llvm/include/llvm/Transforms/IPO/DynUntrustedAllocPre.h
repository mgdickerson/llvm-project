//===- Transforms/UntrustedAlloc.h - UntrustedAlloc passes
//--------------------*- C++
//-*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file defines the constructor for the Dynamic Untrusted Allocation passes.
//
//===----------------------------------------------------------------------===//

#include "llvm/ADT/StringRef.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Pass.h"

namespace llvm {
class ModulePass;

class DynUntrustedAllocPrePass : public PassInfoMixin<DynUntrustedAllocPrePass> {
    public:
        DynUntrustedAllocPrePass(){}
        PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM);
};

ModulePass *createDynUntrustedAllocPrePass();

void initializeDynUntrustedAllocPrePass(PassRegistry &Registry);
}