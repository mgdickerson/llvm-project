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
// This file defines constructor functions for UntrustedAlloc passes.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_TRANSFORMS_SYRINGE_H
#define LLVM_TRANSFORMS_SYRINGE_H

#include "llvm/ADT/StringRef.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/PassManager.h"
#include "llvm/Pass.h"

namespace llvm {
class ModulePass;

/// Pass to change Untrusted Allocation sites.
class UntrustedAllocPass : public PassInfoMixin<UntrustedAllocPass> {
public:
  UntrustedAllocPass(){}
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM);
};

ModulePass *createUntrustedAllocPass();

//void initializeUntrustedAllocPass(PassRegistry &Registry);
} // namespace llvm

#endif // Include Guard
