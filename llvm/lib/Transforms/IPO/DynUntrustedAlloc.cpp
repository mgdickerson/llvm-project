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
#include "llvm/IR/Instruction.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Type.h"
#include "llvm/Support/raw_ostream.h"

#include <string>
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
    class IDGenerator {
        unsigned int id;

        public:
            IDGenerator() : id(0) {}

            ConstantInt* getConstID(Module &M) {
                return llvm::ConstantInt::get(IntegerType::getInt64Ty(M.getContext()), id++);
            }

            ConstantInt* getDummyID(Module &M) {
                return llvm::ConstantInt::get(IntegerType::getInt64Ty(M.getContext()), 0);
            }
    };

    static IDGenerator IDG;

    class DynUntrustedAlloc : public ModulePass {
        public:
            static char ID;
	    static IDGenerator IDG;

            DynUntrustedAlloc() : ModulePass(ID) {
                initializeDynUntrustedAllocPass(*PassRegistry::getPassRegistry());
            }
            virtual ~DynUntrustedAlloc() = default;

            // StringRef getPassName() const override {
            //     StringRef(const char * "DynUntrustedAllocPass")
            // }

            bool runOnModule(Module &M) override {
                // Pre-inline pass:
                // Adds function hooks with dummy UniqueIDs immediately after calls
                // to __rust_alloc* functions. Additionally, we must remove the 
                // NoInline attribute from RustAlloc functions.		

                // Make function hook to add to all functions we wish to track
                Constant *allocHookFunc = M.getOrInsertFunction("allocHook", 
                    Type::getVoidTy(M.getContext()), 
                    Type::getInt8PtrTy(M.getContext()), 
                    IntegerType::get(M.getContext(), 32), 
                    IntegerType::getInt64Ty(M.getContext()));
                allocHook = cast<Function>(allocHookFunc);

                Constant *mallocHookFunc = M.getOrInsertFunction("mallocHook", 
                    Type::getVoidTy(M.getContext()), 
                    Type::getInt8PtrTy(M.getContext()), 
                    IntegerType::get(M.getContext(), 32), 
                    Type::getInt8PtrTy(M.getContext()), 
                    IntegerType::get(M.getContext(), 32), 
                    IntegerType::getInt64Ty(M.getContext()));
                mallocHook = cast<Function>(mallocHookFunc);

                Constant *deallocHookFunc = M.getOrInsertFunction("deallocHook", 
                    Type::getVoidTy(M.getContext()), 
                    Type::getInt8PtrTy(M.getContext()), 
                    IntegerType::get(M.getContext(), 32), 
                    IntegerType::getInt64Ty(M.getContext()));
                deallocHook = cast<Function>(deallocHookFunc);

                hookAllocFunctions(M);
                removeInlineAttr(M);
                assignUniqueIDs(M);
                return true;
            }

            /// Iterate over all functions we are looking for, and instrument them with hooks accordingly
            void hookAllocFunctions(Module &M) {
                std::string allocFuncs[4] = { "__rust_alloc", "__rust_untrusted_alloc",
                                         "__rust_alloc_zeroed", "__rust_untrusted_alloc_zeroed" };
                for (auto allocName : allocFuncs) {
                    Function *F = M.getFunction(allocName);
                    if (!F) {
                        // errs() << allocName << " is an invalid pointer: " << F << "\n";
                        continue;
                    }

                    for (auto caller : F->users()) {
                        CallSite CS(caller);
                        if (!CS) {
                            // errs() << CS << " is not a callsite!\n";
                            continue;
                        }

                        // For each valid CallSite of the given allocation function,
                        // we want to add function hooks.
                        addFunctionHooks(M, &CS, allocHook);
                    }
                }
            }

            /// Add function hook after call site instruction. Initially place a dummy UUID, to be replaced in structured ascent later.
            /// Additional information required for hook: Size of allocation, and return address.
            void addFunctionHooks(Module &M, CallSite *CS, Function* hookInst) {
                // Get CallSite instruction and containing BasicBlock
                Instruction *CSInst = CS->getInstruction();
                BasicBlock *BB = CS->getParent();
                
                // Create Dummy UniqueID
                // ConstantInt *UUID_dummy = llvm::ConstantInt::get(IntegerType::getInt64Ty(M.getContext()), 0);

                // Create hook call instruction (hookInst, return_ptr, ptr_size, UUID_placeholder)
                // TODO : I think this gets overridden to (*Func, Args...)
                Instruction *newHookInst = CallInst::Create((Function *)hookInst, {CSInst, CS->getArgument(0), IDG.getDummyID(M)});
                
                // Insert hook call after call site instruction
                BasicBlock::iterator bbIter((Instruction *)CSInst);
                bbIter++;
                BB->getInstList().insert(bbIter, (Instruction *)newHookInst);
            }

            /// Iterate all Functions of Module M, remove NoInline attribute from Functions with RustAllocator attribute.
            void removeInlineAttr(Module &M) {
                for (Function &F : M) {
                    if (F.hasFnAttribute(Attribute::RustAllocator)) {
                        F.removeFnAttr(Attribute::NoInline);
                    }
                }
            }

            ////// From Below is Post Inline Functionality //////

            void assignUniqueIDs(Module &M) {
                CallGraph &CG = getAnalysis<CallGraphWrapperPass>().getCallGraph();

                std::string hookFuncNames[3] = { "allocHook", "mallocHook",
                                         "deallocHook" };

                SmallVector<Function *, 3> hookFns;
                for (auto hookName : hookFuncNames) {
                    Function *F = M.getFunction(hookName);
                    if (!F)
                        continue;
                    
                    hookFns.push_back(F);
                }
                
                // SCC Iterator traverses the graph in reverse Topological order.
                // We want to traverse in Topological order, so we gather all the nodes,
                // then reverse the vector.
                std::vector<Function *> WorkList;
                for (scc_iterator<CallGraph *> scc_iter = scc_begin(&CG); !scc_iter.isAtEnd(); ++scc_iter) {
                    // Ideally none of our components should be in an SCC, thus each node 
                    // we are interested in should have no more than 1 item in them.
                    if (scc_iter->size() != 1) {
                        continue;
                    }

                    Function *F = scc_iter->front()->getFunction();
                    WorkList.push_back(F);
                }

                for (auto *F : llvm::reverse(WorkList)) {
                    ReversePostOrderTraversal<Function *> RPOT(F);
                    
                    for (BasicBlock *BB : RPOT) {
                        for (Instruction &I : *BB) {
                            CallSite CS(&I);
                            if (!CS) {
                                continue;
                            }

                            Function *hook = CS.getCalledFunction();
			    if (hook == hookFns[0]) {
				// allocHook
				CS.setArgument(2, IDG.getConstID(M));
			    } else if (hook == hookFns[1]) {
				// mallocHook
				CS.setArgument(4, IDG.getConstID(M));
			    } else if (hook == hookFns[2]) {
				// deallocHook
				CS.setArgument(2, IDG.getConstID(M));
			    }
			}
                    }
                }
            }

        private:
        Function *allocHook;
        Function *mallocHook;
        Function *deallocHook;
    };

    char DynUntrustedAlloc::ID = 0;
}
