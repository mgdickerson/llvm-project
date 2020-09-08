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
            }

            void loadCallGraph(Module &M) {
                // Lazy Call Graph should contain functions for me to directly get reverse post order traversal from.
                &LCG = getAnalysis<LazyCallGraphAnalysis>().getGraph();
                &CG = getAnalysis<CallGraphWrapperPass>().getCallGraph();
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

            std::vector<Function*> getFunctionCallers(Function *F) {
                std::vector<Function*> WorkingSet {F};
                // Loop over functions so long as 
                while (!VisitedFunctions.insert(F).second) {

                }
                auto FuncNode = CG[F];
                for (auto CR : *FuncNode) {
                    auto ParentNode = CR.second;
                    if (!ParentNode) {
                        continue;
                    }

                    auto ParentFunction = ParentNode->getFunction();
                    if ParentFunction->hasFnAttribute(Attribute::RustAllocator) {
                        return getAllocationRoot(ParentFunction);
                    }
                }
            }

            void dfs(CallGraphNode *Node) {

            }

        private:
        CallGraph &CG = getAnalysis<CallGraphWrapperPass>().getCallGraph();
        LazyCallGraph &LCG = getAnalysis<LazyCallGraphAnalysis>().getGraph();
        std::set<Function *> VisitedFunctions;
        std::vector<Function *> GraphNodeVisitor;
    }
}