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

#include "llvm/Transforms/IPO/DynUntrustedAlloc.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/ADT/PostOrderIterator.h"
#include "llvm/Analysis/CallGraph.h"
#include "llvm/Analysis/LazyCallGraph.h"
#include "llvm/IR/Attributes.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/CallSite.h"
#include "llvm/IR/DebugInfo.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instruction.h"

#include <set>

using namespace llvm;

static const char *const TrustedAllocatorName = "__rust_alloc";

/*
    General Plan:
    1) Get Call Graph, traverse in reverse order (callee -> caller), tracking 
    visited nodes with visitor pattern.
    2) Check each function for __rust_alloc attribute, then check callee's parent 
    function to see if it is a Rust allocator. If it is, proceed to caller, and 
    repeat until top level function is found. Instrument there.
    3) Instrument top level function with book keeping calls to compiler-rt. 
    In essence we want to top level allocation function associated with a given
    memory allocation. (This could also double as a check for Rust allocations vs
    generic allocations if we remove book keeping information after function exit.)

    Book Keeping Info:
    - Allocation function name
    - (Some other unique identifier here...)
*/

namespace
{
    bool isRustAlloc(Function *F) {
        auto name = F->getName().data();
        return 0 == std::strncmp(name, TrustedAllocatorName, strlen(TrustedAllocatorName))
    }

    class IDGenerator {
        static unsigned long int id = 0;

        public:
            IDGenerator();

            unsigned long int getID() {
                return id++;
            }
    };

    static IDGenerator IDG;

    class UniqueID {
        public:
            const unsigned long int ID;
            Function *F;
            CallSite *CS;

            // At a minimum I want to track CallSite information together with the Unique ID,
            // but calling function F should be available as well and would provide useful debug info.
            UniqueID(CallSite *CS, Function *F = nullptr, ID = IDG.getID()) : F(F), CS(CS), ID(ID) {}
        private:
    };

    class DynUntrustedAlloc : public ModulePass {
        public:
            static char ID;

            DynUntrustedAlloc : ModulePass(ID) {
                initializeDynUntrustedAllocPass(*PassRegistry::getPassRegistry());
            }
            virtual ~DynUntrustedAlloc() = default;

            StringRef getPassName() const override {
                StringRef(const char * "DynUntrustedAllocPass")
            }

            bool runOnModule(Module &M) override {
                // Call Main functionality here?

                // Make function hook to add to all functions we wish to track
                Constant *hookFunc = M.getOrInsertFunction("allocHandlerHook", Type::getVoidTy(M.getContext()), string);
                hook = cast<Function>(hookFunc);
            }

            /// Adds function hook to beginning of a given Function* F
            void addFunctionHooks(Function *F) {
                BasicBlock *BB = F->getEntryBlock();
                // TODO : I think this gets overridden to (*Func, Args...)
                Instruction *callInst = CallInst::Create(hook, F->getName());
                BB->getInstList().insert(0, callInst);
            }

            void loadCallGraph(Module &M) {
                // Lazy Call Graph should contain functions for me to directly get reverse post order traversal from.
                &LCG = getAnalysis<LazyCallGraphAnalysis>().getGraph();
                &CG = getAnalysis<CallGraphWrapperPass>().getCallGraph();
            }

            void mapCSID() {
                ReversePostOrderTraversal<Function *> RPOT(CG);
                for (rpo_iterator I = RPOT.begin(); I != RPOT.end(); ++I) {
                    for (auto inst : *I) {
                        // TODO : Figure out what I should be doing here. What data type is inst?? or I for that matter.
                    }
                }
            }

            

            void scanPostOrderGraph() {
                for (auto GraphNode : post_order(&CG)) {
                    Function *F = GraphNode->getFunction();
                    if (!VisitedFunctions.insert(F).second) {
                        continue;
                    }
                    
                    if (F->hasFnAttribute(Attribute::RustAllocator)) {
                        // Functions has RustAllocator Attr, check for and collapse
                        // parent calls that also have the attribute.
                        std::set<Function *> sccCheck;
                        sccCheck.insert(F);
                    }
                }
            }

            std::vector<Function*> getFunctionRoot(Function *F) {
                std::vector<Function*> WorkingSet {F};
                std::vector<Function*> ReturnSet;

                // Loop over functions until last RustAllocator function is found.
                while (!WorkingSet.empty()) {
                    // Get Current Function, pop from WorkingSet
                    Function *CF = WorkingSet.back();
                    WorkingSet.pop_back();

                    auto FuncNode = CG[F];
                    for (auto CR : *FuncNode) {
                        auto ParentNode = CR.second;
                        if (!ParentNode) {
                            continue;
                        }

                        // Get Parent Function of Current Function, check to see if it has the Rust Allocator Attribute
                        Function *PF = ParentNode->getFunction();
                        if PF->hasFnAttribute(Attribute::RustAllocator) {
                            // PF has attribute, inline CF into parent and add PF to WorkingSet
                            CallSite CS = CR.first;
                            InlineFunctionInfo IFI(nullptr);

                            if (!CS) {
                                errs() << "Expected callsite for valid Parent Node Allocator.\n";
                            }

                            if (InlineFunction(CS, IFI).isSuccess()) {
                                errs() << "Successfully inlined: " << CS.getCaller()->getName() << "\n";
                            }

                            WorkingSet.push_back(PF);
                        } else {
                            // Parent Function does not have RustAllocator attribute, so we add instrumentation here. 
                            // Or we just add it to the ReturnSet and handle later.
                            // TODO : Instrumentation.
                        }
                    }
                }

                return ReturnSet;
            }

        private:
        CallGraph &CG = getAnalysis<CallGraphWrapperPass>().getCallGraph();
        LazyCallGraph &LCG = getAnalysis<LazyCallGraphAnalysis>().getGraph();
        std::set<Function *> VisitedFunctions;
        std::vector<Function *> GraphNodeVisitor;
        DenseMap<CallSite *, UniqueID> CSMap;
        Function *hook;
    };
}