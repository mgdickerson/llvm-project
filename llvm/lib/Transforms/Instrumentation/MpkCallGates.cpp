#include "llvm/IR/Function.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Instructions.h"
#include "llvm/InitializePasses.h"
#include "llvm/Pass.h"
#include "llvm/Transforms/Instrumentation.h"

using namespace llvm;

#define DEBUG_TYPE "mpk-call-gates"

namespace {

class MpkCallGatesLegacyPass : public ModulePass {
public:
  static char ID;

  explicit MpkCallGatesLegacyPass() : ModulePass(ID) {
    initializeMpkCallGatesLegacyPassPass(*PassRegistry::getPassRegistry());
  }

  StringRef getPassName() const override { return "MpkCallGates"; }
  bool runOnModule(Module &M) override;

private:
};

bool MpkCallGatesLegacyPass::runOnModule(Module &M) {
  std::vector<Function *> rust_functions;
  for (auto &F : M.functions()) {
    if (F.isDeclaration())
      continue;

    // only instrument rust apis
    if (!F.hasFnAttribute("rust_api"))
      continue;

    // and only if they may be called from outside of rust code
    // i.e., externally available or are address taken functions
    if (!(F.hasAddressTaken() || F.hasLinkOnceLinkage() ||
        F.hasAvailableExternallyLinkage() || !F.hasLocalLinkage()))
      continue;

    // ignore our APIs
    if (F.getName() == "__untrusted_gate_enter" ||
        F.getName() == "__untrusted_gate_exit") {
      F.removeFnAttr("rust_api");
      continue;
    }
    rust_functions.push_back(&F);
  }

  if (rust_functions.empty()) {
    return false;
  }

  IRBuilder<> IRB(M.getContext());
  /* scope */ {
    auto Callee =
        M.getOrInsertFunction("__untrusted_gate_enter", IRB.getVoidTy());
    auto *Fn = cast<Function>(Callee); // die on sig mismatch
    Fn->addFnAttr(Attribute::NoUnwind);
  }
  /* scope */ {
    auto Callee =
        M.getOrInsertFunction("__untrusted_gate_exit", IRB.getVoidTy());
    auto *Fn = cast<Function>(Callee); // die on sig mismatch
    Fn->addFnAttr(Attribute::NoUnwind);
  }

  auto PushFn =
      M.getOrInsertFunction("__untrusted_gate_enter", IRB.getVoidTy());

  auto PopFn = M.getOrInsertFunction("__untrusted_gate_exit", IRB.getVoidTy());

  for (auto *F : rust_functions) {
    F->removeFnAttr("rust_api");

    auto *NewF = Function::Create(F->getFunctionType(), F->getLinkage(),
                                  F->getAddressSpace(), "", F->getParent());
    NewF->setComdat(F->getComdat());
    NewF->copyAttributesFrom(F);
    NewF->takeName(F);
    NewF->setSection("mpk_call_gates");
    F->setName("__mpk_impl_" + NewF->getName());
    F->replaceAllUsesWith(NewF);

    auto *BB = BasicBlock::Create(F->getContext(), "", NewF);
    IRBuilder<> Builder(BB);
    Builder.CreateCall(PushFn);

    SmallVector<Value *, 16> Args;
    for (Argument &AI : NewF->args()) {
      Args.push_back(&AI);
    }
    CallInst *CI = Builder.CreateCall(F, Args);

    CI->setTailCall();
    CI->setCallingConv(F->getCallingConv());
    CI->setAttributes(F->getAttributes());
    if (F->getReturnType()->isVoidTy()) {
      Builder.CreateRetVoid();
    } else {
      Builder.CreateRet(CI);
    }

    // Insert a call to __untrusted_gate_exit before every return
    for (auto &BB : *F) {
      auto *RI = dyn_cast<ReturnInst>(BB.getTerminator());
      if (RI) {
        IRBuilder<> Builder(RI);
        Builder.CreateCall(PopFn);
      }
    }
  }
  return true;
}

} // namespace

char MpkCallGatesLegacyPass::ID = 0;
INITIALIZE_PASS(MpkCallGatesLegacyPass, "mpk-call-gates",
                "Insert MPK call gates."
                "ModulePass",
                false, false)

ModulePass *llvm::createMpkCallGatesLegacyPassPass() {
  return new MpkCallGatesLegacyPass();
}
