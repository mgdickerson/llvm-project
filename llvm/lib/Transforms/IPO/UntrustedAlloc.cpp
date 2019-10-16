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
// UntrustedAlloc library.
//
//===----------------------------------------------------------------------===//

#include "llvm/Transforms/IPO/UntrustedAlloc.h"
#include "llvm-c/Initialization.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/ADT/BreadthFirstIterator.h"
#include "llvm/ADT/DepthFirstIterator.h"
#include "llvm/ADT/GraphTraits.h"
#include "llvm/ADT/SCCIterator.h"
#include "llvm/ADT/STLExtras.h"
#include "llvm/ADT/SetVector.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Statistic.h"
#include "llvm/ADT/StringRef.h"
#include "llvm/Analysis/AliasAnalysis.h"
#include "llvm/Analysis/AliasSetTracker.h"
#include "llvm/Analysis/AssumptionCache.h"
#include "llvm/Analysis/BasicAliasAnalysis.h"
#include "llvm/Analysis/BlockFrequencyInfo.h"
#include "llvm/Analysis/CFLAliasAnalysisUtils.h"
#include "llvm/Analysis/CFLAndersAliasAnalysis.h"
#include "llvm/Analysis/CFLSteensAliasAnalysis.h"
#include "llvm/Analysis/CGSCCPassManager.h"
#include "llvm/Analysis/CallGraph.h"
#include "llvm/Analysis/InlineCost.h"
#include "llvm/Analysis/InstructionSimplify.h"
#include "llvm/Analysis/LazyCallGraph.h"
#include "llvm/Analysis/OptimizationRemarkEmitter.h"
#include "llvm/Analysis/ProfileSummaryInfo.h"
#include "llvm/Analysis/TargetLibraryInfo.h"
#include "llvm/Analysis/TargetTransformInfo.h"
#include "llvm/ExecutionEngine/Orc/IndirectionUtils.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/CallSite.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/Dominators.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalAlias.h"
#include "llvm/IR/GlobalIFunc.h"
#include "llvm/IR/GlobalValue.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Instruction.h"
#include "llvm/IR/IntrinsicInst.h"
#include "llvm/IR/Module.h"
#include "llvm/InitializePasses.h"
#include "llvm/Pass.h"
#include "llvm/PassRegistry.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h"
#include "llvm/Transforms/Utils/Cloning.h"
#include "llvm/Transforms/Utils/ModuleUtils.h"
#include "llvm/Transforms/Utils/UnifyFunctionExitNodes.h"

#include <cstring>
#include <string>

using namespace llvm;

// Strings for UntrustedAlloc names and Suffix
static const char *const UntrustedAllocatorName = "__rust_untrusted_alloc";
static const char *const TrustedAllocatorName = "__rust_alloc";
static const char *const ExchangeMallocName =
    "_ZN5alloc5alloc15exchange_malloc";
static const char *const UseArcTestName = "_ZN8mpk_test12use_arc_test";

namespace {

// Finds untrusted callsites and populates the untrustedCallSites list
bool doAllocUpdateForModule(Module &M) {
  llvm::errs() << "UntrustedAlloc Pass Diagnostics\n";
  for (Function &F : M) {
    // Check if the function is 'untrusted'
    if (F.hasFnAttribute("untrusted")) {
      llvm::errs() << "Untrusted APIs found in module\n";
      return true;
    }
  }
  llvm::errs() << "No untrusted APIs in Module\n";
  return false;
} // namespace

bool isRustAlloc(Function *F) {
  auto name = F->getName().data();
  return 0 ==
         std::strncmp(name, TrustedAllocatorName, strlen(TrustedAllocatorName));
}

bool isExchangeMalloc(Function *F) {
  auto name = F->getName().data();
  return 0 ==
         std::strncmp(name, ExchangeMallocName, strlen(ExchangeMallocName));
}

bool isUseArcTest(const Function *F) {
  assert(F && "Passed Null Pointer to IsUseArcTest");
  auto name = F->getName().data();
  return 0 == std::strncmp(name, UseArcTestName, strlen(UseArcTestName));
}

class UntrustedAlloc : public ModulePass {

  enum IsReachable { None, NotReachable, Reachable };

  using CallSiteKey = std::pair<CallSite, const Instruction *>;
  using QueryKey = std::pair<Function *, const Argument *>;
  // using Query = std::pair<PathKey, IsReachable>;
  // using CallSiteKey = std::pair<Function *, const Argument *>;
  using WorkList = SmallSet<CallSite, 16>;
  using PropList = SmallSet<CallSite, 16>;
  using QueryCache = DenseMap<QueryKey, IsReachable>;
  using VisitedStat = DenseMap<Function *, int>;
  using CheckedFunMap = DenseMap<CallGraphNode *, bool>;

  bool debug = true;

public:
  /// pass identification
  static char ID;

  UntrustedAlloc() : ModulePass(ID) {
    initializeUntrustedAllocPass(*PassRegistry::getPassRegistry());
  }
  virtual ~UntrustedAlloc() = default;

  /// Specify pass name for debug output
  // StringRef getPassName() const override;

  /// run module pass

  void modifyAllocationSite(CallSite *CS);

  /// run module pass
  bool runOnModule(Module &M) override {
    if (skipModule(M)) {
      return false;
    }

    return doAllocUpdateForModule(M);
  }

  // main function for syringe
  bool doAllocUpdateForModule(Module &M) {
    llvm::errs() << "-- UntrustedAlloc Pass begin -- \n";
    if (!findUntrustedCallSites(M)) {
      llvm::errs() << "No Untrusted CallSites in Module\n";
      return false;
    }
    llvm::errs() << "UntrustedAlloc Pass found " << UntrustedCallSites.size()
                 << " CallSites to check\n";

    bool hasEM = findExchangeMallocCallSites(M);
    bool hasRA = findRustAllocCallSites(M);
    bool found = hasEM || hasRA;
    if (found) {
      llvm::errs() << "UntrustedAlloc Pass found "
                   << ExchangeMallocCallSites.size()
                   << " exchange_malloc() CallSites\n";
      llvm::errs() << "UntrustedAlloc Pass found " << RustAllocCallSites.size()
                   << " __rust_alloc() call sites\n";
    }

    scanCG(M);

    bool MultipleVisits = false;
    for (auto &F : M) {
      int i = Visited[&F];
      if (i > 1) {
        errs() << F.getName() << " Visited " << i << " Times\n";
        MultipleVisits = true;
      }
    }
    if (!MultipleVisits)
      errs() << "No Function Visited Multiple Times\n";

    // initializeCacheFromCallGraph();

    // for (auto &F : M) {
    // if (maybeReachesUntrusted(&F)) {

    // errs() << "\n##########################################\n";
    // errs() << F.getName() << " May Reach Untrusted Call\n";
    // errs() << "\n##########################################\n";
    //}
    //}

    // handleExchangeMalloc();
    // handleRustAlloc();
    return found;
  }

  void handleExchangeMalloc() {
    CFLAndersAAResult &AA = getAnalysis<CFLAndersAAWrapperPass>().getResult();
    // CFLSteensAAResult &AA =
    // getAnalysis<CFLSteensAAWrapperPass>().getResult();
    // auto &TLI = getAnalysis<TargetLibraryInfoWrapperPass>().getTLI();

    // for (auto alloc : ExchangeMallocCallSites) {
    // bool patched = false;
    // if (patched) {
    // continue;
    //}

    // for (auto CS : UntrustedCallSites) {
    for (auto CS : ExchangeMallocCallSites) {
      // CallInst *CI = dyn_cast<CallInst>(CS.getInstruction());
      // check if  the allocation may alias any of the function parameters
      // int num_args = CS->getNumArgOperands();
      // for (auto i = 0; i < num_args; ++i) {
      // for(auto Arg : CS.args())
      ////auto Arg = CI->getArgOperand(i);
      // if (!(Arg->getType()->isPointerTy()))
      // continue;
      // auto ArgInst = dyn_cast<Instruction>(Arg);
      // if (!ArgInst)
      // continue;

      auto RetVal = CS.getInstruction();
      Function *F = CS.getCaller();
      bool IsEscaped = doesValEscape(RetVal, F, AA);
      auto msg = IsEscaped ? " Does " : " Does Not ";
      errs() << "\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n";
      errs() << "Value in Function: " << F->getName() << msg << " Escape\n";
      RetVal->dump();

      errs() << "\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n";

      if (IsEscaped) {
        auto aliases = findLocalAliases(RetVal, F, AA);

        errs() << "\n==========================================\n";
        errs() << "Alias list for : " << *RetVal << "\n";
        for (auto A : aliases) {
          A->dump();
        }
        errs() << "\n==========================================\n\n";
      } else if (debug) {
        errs() << "\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n";
        errs() << " Display Bad Function\n";
        errs() << " Function IR: " << F->getName() << "\n";
        F->dump();
        errs() << "\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n";
      }

      // auto insertion = CheckedCallSites.insert(std::make_pair(CS,
      // ArgInst)); if (!insertion.second) continue;

      // check_value(Arg, CS.getCaller());
      // simpleQuery(ArgInst, CS.getCaller());
    }
    //}
    // for (auto CS : CheckedCallSites) {
    // VisitedFunctions.insert(CS.first.getCalledFunction());
    //}
  }

  void scanCG(Module &M) {
    CallGraph &CG = getAnalysis<CallGraphWrapperPass>().getCallGraph();
    // auto ExtNode = CG.getCallsExternalNode();
    auto ExtNode = CG.getExternalCallingNode();
    auto it_scc_begin = scc_begin(&CG);
    // auto it_scc_end = scc_end(CG);
    // for (auto scc_it = it_scc_begin; scc_it != it_scc_end; ++scc_it) {
    // for (auto scc_it = it_scc_begin; !scc_it.isAtEnd(); ++scc_it) {
    auto scc_it = it_scc_begin;
    scc_iterator<CallGraph *> CGI = scc_begin(&CG);

    CallGraphSCC CurSCC(CG, &CGI);
    while (!CGI.isAtEnd()) {
      // Copy the current SCC and increment past it so that the pass can hack
      // on the SCC if it wants to without invalidating our iterator.
      const std::vector<CallGraphNode *> &NodeVec = *CGI;
      CurSCC.initialize(NodeVec);
      ++CGI;
      if (!CurSCC.isSingular()) {
        for (CallGraphNode *SCCNode : CurSCC) {
          //SCCNode->dump();
        }
        return;
      }
      if (false)
        for (CallGraphNode *CGNode : *scc_it) {
          Function *Func = CGNode->getFunction();
          // if (Func && isUseArcTest(Func)) {
          // if (!scc_it.isSingular()) {
          // for (CallGraphNode *SCCNode : *scc_it) {
          // SCCNode->dump();
          //}
          // return;
          //} else {
          // continue;
          //}

          // auto CGNode = CG[&Func];

          std::set<CallGraphNode *> visited_nodes;
          std::set<CallGraphNode *> external_nodes;
          sadDFS(CGNode, visited_nodes, ExtNode);
          // if (ExtNode != nullptr)
          // sadDFS(ExtNode, external_nodes, ExtNode);
          if (debug && Func) {
            errs() << "\n##########################################\n";
            errs() << CGNode->getFunction()->getName() << " Calls:\n";
            for (auto *Node : visited_nodes) {
              if(!Node)continue;
              auto F = Node->getFunction();
              if(!F)continue;
              errs() << F->getName() << " \n";
            }
            errs() << "\n##########################################\n";
          } // end debug
          if (debug && Func) {
            errs() << "\n##########################################\n";
            errs() << CGNode->getFunction()->getName() << " Calls:\n";
            for (auto *Node : external_nodes) {
              if(!Node)continue;
              auto F = Node->getFunction();
              if(!F)continue;
              errs() << F->getName() << " \n";
            }
            errs() << "\n#################  external_nodes  "
                      "#########################\n";
          }
        } // end for Func in scc
    }     // scc iteration
    // printExternalCalls(ExtNode);

  } // end scanCG()

  void incrementVisited(Function *F) {
    if (F)
      Visited[F] = Visited[F] + 1;
  }

  void setCheckedEntry(CallGraphNode *Node, bool reaches) {
    // do not set table entries for nodes w/o functions
    // We always want to check indirect calls
    // This may need some fine tuning to be certain we dont check all potential
    // indirect calls
    if (Node && Node->getFunction())
      Checked[Node] = reaches;
  }

  bool sadDFS(CallGraphNode *Node, std::set<CallGraphNode *> &DFVisited,
              CallGraphNode *BadNode) {
    Function *F = Node->getFunction();

    // assert(F != nullptr &&
    //"CallGraphNode was NULL in DFS -- Audit search invariants");

    // if (F) {
    // look up cached value
    // auto check = Checked.find(F);
    auto check = Checked.find(Node);
    if (check != Checked.end()) {
      return check->second;
    }
    //}

    if (Node != BadNode) {

      // shouldn't need this, but check with some debug statements
      if (DFVisited.insert(Node).second == false) {
        errs() << "\n##########################################\n";
        errs() << "Node could not be inserted, but was not checked!?\n";
        Node->dump();
        errs() << "\n##########################################\n";
        return maybeReachesUntrusted(F);
      }
    }
    incrementVisited(F);

    // errs() << "\n##########################################\n";
    // errs() << CGN->getFunction()->getName() << " Calls:\n";
    // if (!isUseArcTest(F))
    // continue;

    bool found = false;
    for (auto &CR : *Node) {
      auto CalledNode = CR.second;
      if (!CalledNode)
        continue;

      auto Called = CalledNode->getFunction();
      if (Called == nullptr) {
        // try to check indirect call sites? not sure this works right
        if (CalledNode != BadNode) {
          errs()
              << "Found an external Node that isn't the Global External Node\n";
          // found |= sadDFS(CalledNode, DFVisited, BadNode);
          CalledNode->dump();
        }
        continue;
      }

      // errs() << Called->getName() << "\n";
      if (Called->hasFnAttribute(Attribute::Untrusted)) {
        found |= true;
        // break;
      } // if is untrusted
      else {
        found |= sadDFS(CalledNode, DFVisited, BadNode);
      }
    } // for all callrecords

    // setCheckedEntry(F, found);
    setCheckedEntry(Node, found);
    updateFunctionCacheEntry(F, found);
    return found;
  }

  void updateFunctionCacheEntry(Function *F, bool found) {
    if (!F)
      return;
    IsReachable reach = found ? IsReachable::None : IsReachable::NotReachable;
    for (auto &A : F->args()) {
      QueryKey key = std::make_pair(F, &A);
      QCache[key] = reach;
    }
  }

  void printExternalCalls(CallGraphNode *CGN) {
    if (!CGN)
      return;

    errs() << "\n##########################################\n";
    errs() << "The External Node has " << CGN->size() << " Edges\n";
    // if (!isUseArcTest(F))
    // continue;

    for (auto &CR : *CGN) {
      auto Called = CR.second->getFunction();
      if (Called == nullptr)
        continue;
      errs() << Called->getName() << "\n";
    } // for all callrecords

    CGN->dump();
    errs() << "\n##########################################\n";
  }

  void initializeCacheFromCallGraph() {

    CallGraph &CG = getAnalysis<CallGraphWrapperPass>().getCallGraph();
    for (auto &FMap : CG) {
      auto CGN = FMap.second.get(); // great get a raw pointer out of a unique
                                    // ... nothing ever bad happens this way :(
      if (CGN == nullptr)
        continue;

      Function *F = CGN->getFunction();
      if (F == nullptr)
        continue;

      errs() << "\n##########################################\n";
      errs() << CGN->getFunction()->getName() << " Calls:\n";
      // if (!isUseArcTest(F))
      // continue;

      bool found = false;
      for (auto &CR : *CGN) {
        auto Called = CR.second->getFunction();
        if (Called == nullptr)
          continue;

        errs() << Called->getName() << "\n";
        if (Called->hasFnAttribute(Attribute::Untrusted)) {
          found = true;
          break;
        } // if is untrusted
      }   // for all callrecords

      IsReachable reach = found ? IsReachable::None : IsReachable::NotReachable;
      for (auto &A : F->args()) {
        QueryKey key = std::make_pair(F, &A);
        QCache[key] = reach;
      }
      errs() << "\n##########################################\n";
    }
  }

  bool maybeReachesUntrusted(Function *F) {
    for (auto &A : F->args()) {
      QueryKey key = std::make_pair(F, &A);
      if (QCache[key] != IsReachable::NotReachable)
        return true;
    }
    return false;
  }

  void debugPrintArgAliases(MemoryLocation &ValLoc, Function *F,
                            CFLAndersAAResult &AA) {
    errs() << "\n##########################################\n";
    errs() << "Checking all instructions for sret";
    for (auto &BB : *F) {
      for (auto &I : BB) {
        for (Argument &Arg : F->args()) {
          MemoryLocation RetLoc(&Arg, LocationSize::unknown());
          // MemoryLocation RetLoc = MemoryLocation::get(RetVal);
          // errs() << "Created Memory location for Return Value\n";
          if (AA.alias(ValLoc, RetLoc)) {
            errs() << "Arg: " << Arg;
            errs() << "--Alias: " << I;
          }
        }
      }
    }
    errs() << "\n###########################################\n";
  }

  // find if value escapes current function
  bool doesValEscape(Value *V, Function *F, CFLAndersAAResult &AA) {
    MemoryLocation ValLoc(V, LocationSize::unknown());
    // TODO: Figure out if there are other possible return paths/values
    if (F->returnDoesNotAlias() || F->hasStructRetAttr()) {
      for (Argument &Arg : F->args()) {
        MemoryLocation RetLoc(&Arg, LocationSize::unknown());
        // MemoryLocation RetLoc = MemoryLocation::get(RetVal);
        // errs() << "Created Memory location for Return Value\n";
        if (AA.alias(ValLoc, RetLoc))
          return true;
      }
      // if we got here there may be an issue
      if (debug)
        debugPrintArgAliases(ValLoc, F, AA);
    } // end ret parameter check

    // errs() << "Created Memory location for target value\n";
    for (auto &BB : *F) {
      if (ReturnInst *RI = dyn_cast<ReturnInst>(BB.getTerminator())) {
        if (auto RetVal = RI->getReturnValue()) {

          // M.getDataLayout()
          MemoryLocation RetLoc(RetVal, LocationSize::unknown());
          // MemoryLocation RetLoc = MemoryLocation::get(RetVal);
          // errs() << "Created Memory location for Return Value\n";
          if (AA.alias(ValLoc, RetLoc))
            return true;
        } // end if RetVal
      }   // end if RetInst
    }     // end forloop

    return false;
  }

  // find all aliases in current function
  std::set<Instruction *> findLocalAliases(Instruction *Inst, Function *F,
                                           CFLAndersAAResult &AA) {
    std::set<Instruction *> Aliases;
    auto curBlock = Inst->getParent();
    if (curBlock)
      searchBB(Inst, curBlock, AA, Aliases);
    for (auto *BB : predecessors(curBlock))
      searchBB(Inst, BB, AA, Aliases);
    return Aliases;
  }

  void searchBB(Instruction *Inst, BasicBlock *BB,
                // what
                // AAResults &AA,
                CFLAndersAAResult &AA,
                // stuff
                std::set<Instruction *> &Aliases) {
    for (auto &I : *BB) {

      auto TargetMemory = MemoryLocation(Inst, LocationSize::unknown());
      auto InstMemory = MemoryLocation(&I, LocationSize::unknown());
      if (AA.alias(TargetMemory, InstMemory)) {

        Aliases.insert(&I);
        continue;
      }
    }
  }

  // check if alias is untrusted call

  // check if call graph has path to untrusted call from here

  void printInfo() {
    for (auto F : VisitedFunctions) {
      errs() << "\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n";
      errs() << " Function IR: " << F->getName() << "\n";
      F->dump();
      if (isUseArcTest(F)) {
        CFLAndersAAResult &AA =
            getAnalysis<CFLAndersAAWrapperPass>().getResult();
        for (auto V : CheckedValues) {
          errs() << "\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n";
          errs() << " Value: " << *V << " Aliases:\n";
          for (auto &BB : *F) {
            for (auto &I : BB) {
              auto TargetMemory = MemoryLocation(V, LocationSize::unknown());
              auto InstMemory = MemoryLocation(&I, LocationSize::unknown());
              if (AA.alias(TargetMemory, InstMemory)) {
                I.dump();
              } // end if alias
            }   // for I in BB
          }     // for BB in F
          errs() << "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n";
        } // for checked values
      }   // if this is use_arc_test
      errs() << "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n";

      if (isUseArcTest(F)) {
        errs() << "\n##########################################\n";
        for (auto CSK : CheckedCallSites) {
          CallSite CS = CSK.first;
          auto Inst = CSK.second;
          Function *Func = CS.getCaller();
          if (isUseArcTest(Func)) {

            errs() << "-- CallSite: " << *CS.getInstruction()
                   << "\n---- Arg: " << *Inst << "\n\n";
          }
        } // for callsites
        errs() << "\n##########################################\n";
      }
    }
  }

  void patchExchangeMalloc(CallSite alloc) {
    llvm::errs() << "Patching ExchangeMalloc Call Site\n";
    Value *arg = alloc.getArgument(2);
    auto isBool = arg->getType()->isIntegerTy(1);
    if (isBool) {
      llvm::errs() << "Boolean Parameter Found...";
      // ConstantInt::get(arg->getType(), 0, SignExtend != 0);
      auto FalseVal = ConstantInt::getFalse(arg->getType());
      alloc.setArgument(2, FalseVal);
      llvm::errs() << "Patched call of " << alloc.getCalledFunction()->getName()
                   << " in " << alloc.getCaller()->getName() << "\n";
    } else {
      llvm::errs() << "Was not exchange_malloc() call\n";
      llvm::errs() << "Patch Failed in " << alloc.getCalledFunction()->getName()
                   << " in " << alloc.getCaller()->getName() << "\n";
    }
  }

  void simpleQuery(Instruction *Inst, Function *F) {
    VisitedFunctions.insert(F);

    errs() << "\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n";
    errs() << "Starting Simple Alias Query for Function: " << F->getName()
           << "\n";
    errs() << "Target Value: " << *Inst << "\n";
    errs() << "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n";
    if (isUseArcTest(F)) {
      CheckedValues.insert(Inst);
    }
    std::set<Instruction *> aliases;
    CFLAndersAAResult &AA = getAnalysis<CFLAndersAAWrapperPass>().getResult();
    // AAResults &AA = getAnalysis<AAResultsWrapperPass>(*F).getAAResults();
    auto curBlock = Inst->getParent();
    if (curBlock)
      queryBB(Inst, curBlock, AA, aliases);
    for (auto *BB : predecessors(curBlock))
      queryBB(Inst, BB, AA, aliases);

    queryArguments(Inst, F, AA);

    for (auto A : aliases) {
      errs() << "\n==========================================\n";
      errs() << " Value: " << *Inst << " Aliases:\n";
      A->dump();
      errs() << "==========================================\n\n";
    }
    errs() << "\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n";
    errs() << "Alias Query Finished for: " << F->getName() << "\n";
    errs() << "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n";
    // F->dump();
    // errs() << "\nAlias Query Finished\n\n";
  }

  void queryBB(Instruction *Inst, BasicBlock *BB,
               // what
               // AAResults &AA,
               CFLAndersAAResult &AA,
               // stuff
               std::set<Instruction *> &Aliases) {
    for (auto &I : *BB) {

      auto TargetMemory = MemoryLocation(Inst, LocationSize::unknown());
      auto InstMemory = MemoryLocation(&I, LocationSize::unknown());
      if (AA.alias(TargetMemory, InstMemory)) {

        Aliases.insert(&I);
        continue;

        if (&I == Inst || I.isIdenticalTo(Inst))
          continue;

        errs() << "Value can alias instruction:\n";
        Inst->dump();
        I.dump();
        CallSite CS(&I);
        if (CS) {
          // CallSiteKey key = std::make_pair(CS, Inst);
          // if (CheckedCallSites.find(key) != CheckedCallSites.end()) {
          // continue;
          //} else {
          // CheckedCallSites.insert(key);
          //}
          // if we have a call site, check it
          if (isExchangeMalloc(CS.getCalledFunction())) {
            // if it is, then patch that call
            patchExchangeMalloc(CS);
            // otherwise check if its __rust_alloc
          } else if (isRustAlloc(CS.getCalledFunction())) {
            // if it is, then patch that call
            errs() << "Patching Rust Alloc not handled yet!\n";
          } else if (Function *Callee = CS.getCalledFunction()) {
            queryCallee(Callee);
          }
        }
        Function *F = BB->getParent();
        queryArguments(&I, F, AA);
      }
    }
  }

  void queryArguments(Instruction *Inst, Function *F,
                      //
                      CFLAndersAAResult &AA) {
    // AAResults &AA) {
    if (!Inst)
      return;
    // CFLAndersAAResult &AA) {
    errs() << "-- Checking against Function Arguments in : " << F->getName()
           << " --\n";
    for (Argument &Arg : F->args()) {
      auto TargetMemory = MemoryLocation(Inst, LocationSize::unknown());
      auto ArgMemory = MemoryLocation(&Arg, LocationSize::unknown());

      // if (AA.alias(&Arg, Inst)) {
      if (AA.alias(TargetMemory, ArgMemory)) {
        errs()
            << "--- Found Argument Alias During Alias Checking for Function: "
            << F->getName() << "----\n";
        // Arg.dump();
        // Inst->dump();
        // get arg number
        auto ArgNum = Arg.getArgNo();
        checkParentCallSite(F, ArgNum);
      }
    }
  }

  void queryCallee(Function *F) {
    for (BasicBlock &BB : *F) {
      if (ReturnInst *RI = dyn_cast<ReturnInst>(BB.getTerminator())) {
        auto retVal = dyn_cast<Instruction>(RI->getReturnValue());
        // simpleQuery(RI->getReturnValue(), F);
        if (retVal)
          simpleQuery(retVal, F);
      }
    }
  }

  void check_value(const Value *val, Function *F) {
    errs() << "Entering check_value() for Function: " << F->getName() << "\n";
    // check that val is a pointer?

    // get alias set for value

    // CFLAndersAAResult &AA =
    // getAnalysis<CFLAndersAAWrapperPass>().getResult();

    AAResults &AA = getAnalysis<AAResultsWrapperPass>(*F).getAAResults();
    AliasSetTracker AST(AA);

    for (auto &BB : *F)
      for (auto &I : BB)
        AST.add(&I);

    // AST.add(val);
    auto UntrustedVal = MemoryLocation(val, LocationSize::unknown());
    auto &aliases = AST.getAliasSetFor(UntrustedVal);
    // auto &aliases = AST.findAliasSetForUnknownInst(val);
    aliases.dump();
    int i = 0;
    errs() << "Examining Alias set -- size: " << aliases.size() << "\n";
    for (auto inst : aliases) {
      // then for each may alias value check if its exchange
      // malloc
      errs() << "-- Examining Alias set item #" << ++i << "\n";

      auto ValInst = dyn_cast<Instruction>(val);
      // if it is another call, check the callee
      CallSite CS(inst.getValue());
      if (CS && ValInst) {
        CallSiteKey key = std::make_pair(CS, ValInst);

        if (CheckedCallSites.find(key) != CheckedCallSites.end()) {
          continue;
        } else {
          CheckedCallSites.insert(key);
        }

        // if we have a call site, check it
        if (isExchangeMalloc(CS.getCalledFunction())) {
          // if it is, then patch that call
          patchExchangeMalloc(CS);
          // otherwise check if its __rust_alloc
        } else if (isRustAlloc(CS.getCalledFunction())) {
          // if it is, then patch that call
          errs() << "Patching Rust Alloc not handled yet!\n";
        } else if (Function *Callee = CS.getCalledFunction()) {
          check_callee(Callee);
        }
      } else if (Argument *Arg = dyn_cast<Argument>(inst.getValue())) {
        errs() << "Found Alias with Argument\n";
        checkParentCallSite(F, Arg->getArgNo());

      } else {
        // errs() << "Try to check this value!\n";
        // check_value(inst.getValue(), F);
        errs() << "Not a call or an argument -- check all "
                  "aliases\n";
        inst.getValue()->dump(); //<< "\n";
        if (ValInst)
          check_aliases(ValInst, F, AA);

        F->dump();

        // for (auto &BB : *F)
        // for (auto &I : BB) {
        // if (dyn_cast<Value>(&I) == val)
        // break;
        // if (AA.alias(val, &I)) {
        // errs() << "Val aliases" << I << "\n";
        //// check_value(&I, F);
        //}
        //}

        continue;
      }
    }
  }

  void checkParentCallSite(Function *F, unsigned ArgNo) {
    // if the alias is an argument of the parent function
    // then find all callsites of the parent function
    for (auto calledParent : F->users()) {
      errs() << "Checking Potential Callsite ...";
      // and call check_value(param) on the operand at the
      // callsites }
      CallSite ParentCall(calledParent);
      if (!ParentCall) {
        errs() << "Not a Callsite\n";
        continue;
      }

      auto Arg = ParentCall.getArgOperand(ArgNo);
      auto val = dyn_cast<Instruction>(Arg);
      if (val) {
        auto key = std::make_pair(ParentCall, val);

        if (CheckedCallSites.find(key) != CheckedCallSites.end()) {
          continue;
        } else {
          CheckedCallSites.insert(key);
        }

        errs() << "Found: " << ParentCall.getCaller()->getName() << "\n";

        simpleQuery(val, ParentCall.getCaller());
      }
    }
  }

  void check_aliases(const Instruction *Inst, Function *F, AAResults &AA) {

    auto curBlock = Inst->getParent();
    if (curBlock)
      check_bb_for_aliases(curBlock, Inst, F, AA);
    for (auto *BB : predecessors(curBlock))
      check_bb_for_aliases(BB, Inst, F, AA);
  }

  void check_bb_for_aliases(const BasicBlock *BB, const Instruction *Inst,
                            Function *F, AAResults &AA) {
    for (auto &I : *BB) {
      if (&I == Inst) {
        errs() << "Reached target instruction" << I << "\n";
        for (Argument &Arg : F->args()) {
          if (AA.alias(&Arg, &I)) {
            errs() << "Found Argument Alias Durring Alias "
                      "Checking for "
                      "Function: "
                   << F->getName() << "----\n";
            Arg.dump();
            I.dump();
            // get arg number
            auto ArgNum = Arg.getArgNo();
            checkParentCallSite(F, ArgNum);
          }
        }
        return;
      }
      // if (AA.alias(Inst, &I) != NoAlias) {
      // errs() << "Val aliases" << I << "\n";
      // if (const Argument *Arg = dyn_cast<Argument>(&I)) {
      // errs() << "Found Argument Alias Durring Alias
      // Checking for Function:
      // "
      //<< F->getName() << "----\n";
      // Arg->dump();
      //}
      // check_aliases(&I, F, AA);
      //}
    }
  }

  void check_indirect() {
    // for all indirect calls check if they match our
    // untrusted functions If they can -- consider checking
    // if target func in address taken too call check value
    // on their operands
  }

  void check_callee(Function *F) {

    // CFLAndersAAResult &AA =
    // getAnalysis<CFLAndersAAWrapperPass>().getResult();
    // auto &AA =
    // getAnalysis<AAResultsWrapperPass>().getAAResults();
    // AliasSetTracker AST(AA);
    // std::vector<ReturnInst *> rets;
    for (BasicBlock &BB : *F) {
      if (ReturnInst *RI = dyn_cast<ReturnInst>(BB.getTerminator())) {
        // AST.add(RI);
        // rets.push_back(RI);
        check_value(RI->getReturnValue(), F);
      }
    }
    // for (auto *RI : rets) {
    // check_value(*RI);
    //}
  }

  // bool checkParamAliases(const MemoryLocation &Val,
  // Function *F, CFLAndersAAResult &AA) {
  //// CFLSteensAAResult &AA) {
  // llvm::errs() << "Checking value against Parameters...
  // \n";

  // for (Argument &A : F->args()) {
  // auto Op = MemoryLocation(&A, LocationSize::unknown());
  // if (!(AA.alias(Op, Val) == NoAlias))
  // llvm::errs() << "Actual parameter from Untrusted
  // CallSite may have "
  //"been passed into this function: "
  //<< F->getName() << "!\n";
  // return true;
  //}
  // llvm::errs() << "Call argument not passed in to calling
  // function ... \n"; return false;
  //}

  // bool searchParentFunctions(CallSite &UntrustedCS,
  // CallSite &AllocCall, CFLAndersAAResult &AA,
  // TargetLibraryInfo &TLI) {
  //// CFLSteensAAResult &AA, TargetLibraryInfo &TLI) {
  // bool hasAlias = false;
  // auto P = UntrustedCS.getCaller();
  // if (!P) {
  // llvm::errs() << "Parent Function Not Found!!!\n";
  // return false;
  //}
  // for (auto &A : P->args()) {
  // auto UntrustedVal = MemoryLocation(&A,
  // LocationSize::unknown()); if
  // (checkParamAliases(UntrustedVal, P, AA)) { hasAlias =
  // true; break;
  //}
  //}

  // if (!hasAlias)
  // return false;

  // for (auto U : P->users()) {

  // CallSite Call(U);

  // if (Call == UntrustedCS) {
  // continue;
  //}
  //// Technically this is wrong, we should see if the value
  /// is reachable, / and then make sure it can acutally flow
  /// through the correct / parameters.
  // if (checkFunc(Call, AllocCall, AA, TLI)) {
  // return true;
  //}
  //}
  // return false;
  //}

  // bool checkFunc(CallSite &CS, CallSite &AllocCall,
  // CFLAndersAAResult &AA,
  //// bool checkFunc(CallSite &CS, CallSite &AllocCall,
  //// CFLSteensAAResult &AA,
  // TargetLibraryInfo &TLI) {

  // auto UnParent = CS.getCaller();
  // auto AllocParent = AllocCall.getCaller();
  // if (!UnParent || !AllocParent)
  // return false;
  // llvm::errs() << " -- checkFunc from " <<
  // UnParent->getName() << "--\n";

  // if (UnParent != AllocParent) {
  // llvm::errs() << "Alloc not in same function Searching
  // parents\n";
  //// return false; // only search in a single function at
  /// a time for now
  // return searchParentFunctions(CS, AllocCall, AA, TLI);
  //}
  // llvm::errs() << "Alloc Function Found!\n";
  // auto AM =
  // MemoryLocation(AllocCall.getInstruction(),
  // LocationSize::unknown());

  // CallInst *CI = cast<CallInst>(CS.getInstruction());
  //// check if  the allocation may alias any of the
  /// function parameters
  // int num_args = CI->getNumArgOperands();
  // for (auto i = 0; i < num_args; ++i) {
  // auto Arg = CI->getArgOperand(i);
  // if (!(Arg->getType()->isPointerTy()))
  // continue;

  //// llvm::errs() << "Getting MemoryLocation for Untrusted
  /// API Argument, " / << i
  ////<< "\n";
  // auto Op = MemoryLocation::getForArgument(CI, i, TLI);

  // llvm::errs() << "Checking Alias ...";
  //// if (AA.alias(Op, AM) != NoAlias) {
  // if (AA.alias(Op, AM) != NoAlias) {
  // llvm::errs() << "Found!\n";
  //// patched = true;
  // patchExchangeMalloc(AllocCall);
  // return true;
  //}
  // llvm::errs() << "Not Found!\n";
  //}
  // return false;
  //}

  // Finds untrusted callsites and populates the
  // untrustedCallSites list
  bool findUntrustedCallSites(Module &M) {
    bool hasUntrustedCalls = false;
    for (Function &F : M) {
      Visited[&F] = 0;
      for (BasicBlock &BB : F)
        for (Instruction &I : BB) {
          CallSite CS(cast<Value>(&I));
          // If this isn't a call, or it is a call to an
          // intrinsic, it can never be inlined.
          if (!CS || isa<IntrinsicInst>(I))
            continue;

          // Check if the function is 'untrusted'
          if (Function *Callee = CS.getCalledFunction())
            if (Callee->hasFnAttribute(Attribute::Untrusted)) {
              hasUntrustedCalls = true;
              UntrustedCallSites.push_back(CS);
            }
        }
    }

    return hasUntrustedCalls;
  }

  bool findExchangeMallocCallSites(Module &M) {
    bool hasExchangeMallocCalls = false;
    for (Function &F : M) {
      for (BasicBlock &BB : F)
        for (Instruction &I : BB) {
          CallSite CS(cast<Value>(&I));
          // If this isn't a call, or it is a call to an
          // intrinsic, it can never be inlined.
          if (!CS || isa<IntrinsicInst>(I))
            continue;

          // Check if the function is 'untrusted'
          if (Function *Callee = CS.getCalledFunction())
            if (isExchangeMalloc(Callee)) {
              hasExchangeMallocCalls = true;
              ExchangeMallocCallSites.push_back(CS);
            }
        }
    }

    return hasExchangeMallocCalls;
  }

  bool findRustAllocCallSites(Module &M) {
    bool hasRustAllocCalls = false;
    for (Function &F : M) {
      for (BasicBlock &BB : F)
        for (Instruction &I : BB) {
          CallSite CS(cast<Value>(&I));
          // If this isn't a call, or it is a call to an
          // intrinsic, it can never be inlined.
          if (!CS || isa<IntrinsicInst>(I))
            continue;

          // Check if the function is 'untrusted'
          if (Function *Callee = CS.getCalledFunction())
            if (isRustAlloc(Callee)) {
              hasRustAllocCalls = true;
              RustAllocCallSites.push_back(CS);
            }
        }
    }

    return hasRustAllocCalls;
  }

  void getAnalysisUsage(AnalysisUsage &AU) const override {
    AU.addRequired<BasicAAWrapperPass>();
    AU.addRequired<AAResultsWrapperPass>();
    AU.addRequired<AssumptionCacheTracker>();
    AU.addRequired<CallGraphWrapperPass>();
    // AU.addRequired<ProfileSummaryInfoWrapperPass>();
    AU.addRequired<TargetLibraryInfoWrapperPass>();
    AU.addRequired<CFLAndersAAWrapperPass>();
    // AU.addRequired<CFLSteensAAWrapperPass>();
    // AU.addRequired<CFLSteensAAResultsWrapperPass>();
    // getAAResultsAnalysisUsage(AU);
    // ModulePass::getAnalysisUsage(AU);
  }

private:
  /* data */
  std::vector<CallSite> UntrustedCallSites;
  std::vector<CallSite> ExchangeMallocCallSites;
  std::vector<CallSite> RustAllocCallSites;

  std::set<CallSiteKey> CheckedCallSites;
  std::set<Function *> VisitedFunctions;
  std::set<Instruction *> CheckedValues;
  VisitedStat Visited;
  CheckedFunMap Checked;

  WorkList WList;
  PropList PList;
  QueryCache QCache;

  // using CallSiteKey = std::pair<CallSite, const Instruction *>;
  // using PathKey = std::pair<Function *, const Argument *>;
  // using UntrustedPathKey = std::pair<PathKey, IsReachable>;

}; // namespace

char UntrustedAlloc::ID = 0;

} // end anonymous namespace

INITIALIZE_PASS_BEGIN(
    UntrustedAlloc, "untrusted",
    "UntrustedAloc: Patch allocation site for untrusted data.", false, false)
INITIALIZE_PASS_DEPENDENCY(AssumptionCacheTracker)
INITIALIZE_PASS_DEPENDENCY(CallGraphWrapperPass)
// INITIALIZE_PASS_DEPENDENCY(ProfileSummaryInfoWrapperPass)
INITIALIZE_PASS_DEPENDENCY(TargetLibraryInfoWrapperPass)
// INITIALIZE_PASS_DEPENDENCY(CFLSteensAAResultsWrapperPass)
// INITIALIZE_PASS_DEPENDENCY(CFLAndersAAResultsWrapperPass)
INITIALIZE_PASS_DEPENDENCY(BasicAAWrapperPass)
INITIALIZE_PASS_DEPENDENCY(AAResultsWrapperPass)
INITIALIZE_PASS_END(UntrustedAlloc, "untrusted",
                    "UntrustedAloc: Patch allocation site for untrusted data.",
                    false, false)

ModulePass *llvm::createUntrustedAllocPass() { return new UntrustedAlloc(); }

// run the syringe pass
PreservedAnalyses UntrustedAllocPass::run(Module &M,
                                          ModuleAnalysisManager &AM) {
  if (!doAllocUpdateForModule(M))
    return PreservedAnalyses::all();

  return PreservedAnalyses::none();
}

///// initializeUntrustedAlloc - Initialize all passes in the UntrustedAlloc
///// library.
// void initializeUntrustedAllocPass(PassRegistry &Registry) {
// initializeUntrustedAllocPass(Registry);
//}

///// LLVMInitializeUntrustedAlloc - C binding for initializeUntrustedAlloc.
// void LLVMInitializeUntrustedAlloc(LLVMPassRegistryRef R) {
// initializeUntrustedAllocPass(*unwrap(R));
//}
