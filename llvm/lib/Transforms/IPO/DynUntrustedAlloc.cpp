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
    bool isRustAlloc(Function *F) {
        auto name = F->getName().data();
        return 0 == std::strncmp(name, TrustedAllocatorName, strlen(TrustedAllocatorName));
    }

    class IDGenerator {
        unsigned int id;

        public:
            IDGenerator() : id(0) {}

            unsigned long int getID() {
                return id++;
            }
    };

    static IDGenerator IDG;

    class UniqueID {
        public:
            unsigned int ID;

            // Provide an int for specific or dummy UniqueIDs. Otherwise Constructor should assign incrementing IDs based on request.
            UniqueID(unsigned int ID = IDG.getID()) : ID(ID) {}
        private:
    };

    class DynUntrustedAlloc : public ModulePass {
        public:
            static char ID;

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
                    StructType::create(M.getContext(), {IntegerType::get(M.getContext(), 32)}));
                allocHook = cast<Function>(allocHookFunc);

                Constant *mallocHookFunc = M.getOrInsertFunction("mallocHook", 
                    Type::getVoidTy(M.getContext()), 
                    Type::getInt8PtrTy(M.getContext()), 
                    IntegerType::get(M.getContext(), 32), 
                    Type::getInt8PtrTy(M.getContext()), 
                    IntegerType::get(M.getContext(), 32), 
                    StructType::create(M.getContext(), {IntegerType::get(M.getContext(), 32)}));
                mallocHook = cast<Function>(mallocHookFunc);

                Constant *deallocHookFunc = M.getOrInsertFunction("deallocHook", 
                    Type::getVoidTy(M.getContext()), 
                    Type::getInt8PtrTy(M.getContext()), 
                    IntegerType::get(M.getContext(), 32), 
                    StructType::create(M.getContext(), {IntegerType::get(M.getContext(), 32)}),
                    NULL);
                deallocHook = cast<Function>(deallocHookFunc);

                hookAllocFunctions(M);
                removeInlineAttr(M);
                return true;
            }

            /// Iterate over all functions we are looking for, and instrument them with hooks accordingly
            void hookAllocFunctions(Module &M) {
                std::string allocFuncs[4] = { "__rust_alloc", "__rust_untrusted_alloc",
                                         "__rust_alloc_zeroed", "__rust_untrusted_alloc_zeroed" };
                for (auto allocName : allocFuncs ) {
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
                ConstantInt *UUID_dummy = llvm::ConstantInt::get(IntegerType::getInt64Ty(M.getContext()), 0);

                // Create hook call instruction (hookInst, return_ptr, ptr_size, UUID_placeholder)
                // TODO : I think this gets overridden to (*Func, Args...)
                Instruction *newHookInst = CallInst::Create((Function *)hookInst, {CSInst, CS->getArgument(0), UUID_dummy});
                
                // Insert hook call after call site instruction
                BB->getInstList().insertAfter((Instruction *)CSInst, (Instruction *)newHookInst);
            }

            /// Iterate all Functions of Module M, remove NoInline attribute from Functions with RustAllocator attribute.
            void removeInlineAttr(Module &M) {
                for (Function &F : M) {
                    if (F.hasFnAttribute(Attribute::RustAllocator)) {
                        F.removeFnAttribute(Attribute::NoInline);
                    }
                }
            }

            ////// From Below is Post Inline Functionality //////

            void scanPOGraph(Module &M) {
                CallGraph &CG = getAnalysis<CallGraphWrapperPass>().getCallGraph();
                ReversePostOrderTraversal<Function *> RPOT(CG);

                for (rpo_iterator BB = RPOT.begin(); BB != RPOT.end(); ++BB) {
                    for (BasicBlock::reverse_iterator inst = BB->rbgein(), end = BB->rend(); inst != end; ++inst) {

                    }
                }
            }


            // void loadCallGraph(Module &M) {
            //     // Lazy Call Graph should contain functions for me to directly get reverse post order traversal from.
            //     &LCG = getAnalysis<LazyCallGraphAnalysis>().getGraph();
            //     &CG = getAnalysis<CallGraphWrapperPass>().getCallGraph();
            // }

            // void mapCSID() {
            //     ReversePostOrderTraversal<Function *> RPOT(CG);
            //     for (rpo_iterator I = RPOT.begin(); I != RPOT.end(); ++I) {
            //         for (auto inst : *I) {
            //             // TODO : Figure out what I should be doing here. What data type is inst?? or I for that matter.
            //         }
            //     }
            // }

            

            // void scanPostOrderGraph() {
            //     for (auto GraphNode : post_order(&CG)) {
            //         Function *F = GraphNode->getFunction();
            //         if (!VisitedFunctions.insert(F).second) {
            //             continue;
            //         }
                    
            //         if (F->hasFnAttribute(Attribute::RustAllocator)) {
            //             // Function has RustAllocator attribute, instrument call stack.
            //             traverseFunctionCallStack(F);
            //         }
            //     }
            // }

            // void traverseFunctionCallStack(Function *F) {
            //     std::vector<Function*> WorkingSet {F};

            //     // Loop over functions until last RustAllocator function is found.
            //     while (!WorkingSet.empty()) {
            //         // Get Current Function, pop from WorkingSet
            //         Function *CF = WorkingSet.back();
            //         VisitedFunctions.insert(CF);
            //         WorkingSet.pop_back();

            //         auto FuncNode = CG[CF];
            //         for (auto CR : *FuncNode) {
            //             auto ParentNode = CR.second;
            //             if (!ParentNode) {
            //                 continue;
            //             }

            //             // Get Parent Function of Current Function, check to see if it has the Rust Allocator Attribute
            //             Function *PF = ParentNode->getFunction();
            //             if PF->hasFnAttribute(Attribute::RustAllocator) {
            //                 // PF has attribute, inline CF into parent and add PF to WorkingSet
            //                 CallSite CS = CR.first;
            //                 InlineFunctionInfo IFI(nullptr);

            //                 if (!CS) {
            //                     errs() << "Expected callsite for valid Parent Node Allocator.\n";
            //                 }

            //                 if (InlineFunction(CS, IFI).isSuccess()) {
            //                     errs() << "Successfully inlined: " << CS.getCaller()->getName() << "\n";
            //                 }


            //                 WorkingSet.push_back(PF);
            //             } else {
            //                 // Parent Function does not have RustAllocator attribute,
            //                 // instrument call site 
            //             }
            //         }
            //     }
            // }

        private:
        // CallGraph &CG = getAnalysis<CallGraphWrapperPass>().getCallGraph();
        // LazyCallGraph &LCG = getAnalysis<LazyCallGraphAnalysis>().getGraph();
        // std::set<Function *> VisitedFunctions;
        // std::vector<Function *> GraphNodeVisitor;
        // std::set<Function *> InstrumentFunctions;
        // DenseMap<CallSite *, UniqueID> CSMap;
        Function *allocHook;
        Function *mallocHook;
        Function *deallocHook;
    };

    char DynUntrustedAlloc::ID = 0;
};