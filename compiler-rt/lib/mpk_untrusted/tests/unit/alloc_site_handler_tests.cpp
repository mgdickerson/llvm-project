// TODO: This should not need a relative path, either use an include dir or
// relocate in lib
#include "../util/mpk_untrusted_test_config.h"
#include "alloc_site_handler.h"
#include "mpk.h"
#include "mpk_fault_handler.h"
#include "gtest/gtest.h"
#include <limits>
#include <memory>
#include <pthread.h>

namespace __mpk_untrusted {

// For this test to work properly, we have to ensure all other tests
// remove all allocations that they have added to the map.
TEST(getAllocSite, EmptyMap) {
  auto handle = AllocSiteHandler::getOrInit();
  auto allocSite = handle->getAllocSite(nullptr);
  EXPECT_EQ(allocSite.get(), AllocSite::error().get());
}

TEST(getAllocSite, InvalidPreAddress) {
  auto handle = AllocSiteHandler::getOrInit();
  auto ptr = (rust_ptr)malloc(sizeof(uint64_t));
  handle->insertAllocSite(
      ptr, std::make_shared<AllocSite>(ptr, sizeof(uint64_t), 1));
  auto decPtr = (rust_ptr)((uintptr_t)ptr - 1);
  auto allocSite = handle->getAllocSite(decPtr);
  EXPECT_EQ(allocSite.get(), AllocSite::error().get());
  handle->removeAllocSite(ptr);
}

TEST(getAllocSite, InvalidPostAddress) {
  auto handle = AllocSiteHandler::getOrInit();
  auto ptr = (rust_ptr)malloc(sizeof(uint64_t));
  handle->insertAllocSite(
      ptr, std::make_shared<AllocSite>(ptr, sizeof(uint64_t), 1));
  auto incPtr = (rust_ptr)((uintptr_t)ptr + sizeof(uint64_t));
  auto allocSite = handle->getAllocSite(incPtr);
  EXPECT_EQ(allocSite.get(), AllocSite::error().get());
  handle->removeAllocSite(ptr);
}

TEST(getAllocSite, InvalidBetweenAddress) {
  auto handle = AllocSiteHandler::getOrInit();
  auto ptr = (rust_ptr)malloc(sizeof(uint64_t));
  auto ptr2 = (rust_ptr)((uintptr_t)ptr + (sizeof(uint64_t) * 2));
  handle->insertAllocSite(
      ptr, std::make_shared<AllocSite>(ptr, sizeof(uint64_t), 1));
  handle->insertAllocSite(
      ptr2, std::make_shared<AllocSite>(ptr, sizeof(uint64_t), 1));
  auto decPtr = (rust_ptr)((uintptr_t)ptr + (sizeof(uint64_t) * 1));
  auto allocSite = handle->getAllocSite(decPtr);
  EXPECT_EQ(allocSite.get(), AllocSite::error().get());
  handle->removeAllocSite(ptr);
  handle->removeAllocSite(ptr2);
}

TEST(getAllocSite, ValidBetweenAddress) {
  auto handle = AllocSiteHandler::getOrInit();
  auto ptr = (rust_ptr)malloc(sizeof(uint64_t));
  auto ptr2 = (rust_ptr)((uintptr_t)ptr + (sizeof(uint64_t) * 4));
  auto newAllocSite = std::make_shared<AllocSite>(ptr, sizeof(uint64_t) * 2, 1);
  handle->insertAllocSite(ptr, newAllocSite);
  handle->insertAllocSite(
      ptr2, std::make_shared<AllocSite>(ptr, sizeof(uint64_t), 1));
  auto decPtr = (rust_ptr)((uintptr_t)ptr + (sizeof(uint64_t) * 1));
  auto getAllocSite = handle->getAllocSite(decPtr);
  EXPECT_EQ(getAllocSite.get(), newAllocSite.get());
  handle->removeAllocSite(ptr);
  handle->removeAllocSite(ptr2);
}

TEST(getAllocSite, PointerArithmeticOverflowWraps) {
  auto ptr = (rust_ptr)(-1); // max pointer size
  auto newAllocSite = std::make_shared<AllocSite>(ptr, sizeof(uint64_t), 1);
  EXPECT_FALSE(newAllocSite->containsPtr(++ptr));
}

TEST(faultingAllocs, addFaultAlloc) {
  auto handle = AllocSiteHandler::getOrInit();
  auto ptr = (rust_ptr)malloc(sizeof(uint64_t));
  auto newAllocSite = std::make_shared<AllocSite>(ptr, sizeof(uint64_t), 1);
  handle->insertAllocSite(ptr, newAllocSite);
  handle->addFaultAlloc(ptr, 1);
  auto fault_set = handle->faultingAllocs();
  if (fault_set.empty())
    FAIL() << "Error Adding AllocSite to error set!\n";

  AllocSite ac = *fault_set.begin();
  EXPECT_EQ(ac.getPtr(), newAllocSite->getPtr());
  EXPECT_EQ(ac.id(), newAllocSite->id());
  handle->removeAllocSite(ptr);
}

void *ThreadedGettid(void *tid) {
  *(pid_t *)tid = gettid();
  pthread_exit(NULL);
}

// Test gettid() macro:
// 1) PID and TID are the same on single thread
// 2) PID and TID are different in multi-thread
TEST(gettid, MacroTest) {
  EXPECT_EQ(getpid(), gettid());

  pthread_t thread_id;
  pid_t tid;
  auto rc = pthread_create(&thread_id, NULL, ThreadedGettid, (void *)&tid);
  if (rc) {
    FAIL() << "Error: Unable to create thread.\n";
  }

  void *status;
  rc = pthread_join(thread_id, &status);
  if (rc) {
    FAIL() << "Error: Unable to join thread.\n";
  }

  EXPECT_NE(getpid(), tid);
}

#define NUM_THREADS 10

void *setAndGetPKeyInfo(void *__unused) {
  auto handle = AllocSiteHandler::getOrInit();
  PKeyInfo pkinf(1, PKEY_DISABLE_ACCESS);
  handle->storePKeyInfo(gettid(), pkinf);
  EXPECT_EQ(pkinf.access_rights,
            handle->popPendingPKeyInfo(gettid()).getValue().access_rights);
  pthread_exit(NULL);
}

TEST(pkeyMap, insertAndRetrievePKeyInfo) {
  pthread_t threads[NUM_THREADS];
  int rc;
  void *status;

  for (pthread_t &thread_id : threads) {
    rc = pthread_create(&thread_id, NULL, setAndGetPKeyInfo, NULL);
    if (rc)
      FAIL() << "Error: Unable to create thread.\n";
  }

  for (auto thread_id : threads) {
    rc = pthread_join(thread_id, &status);
    if (rc)
      FAIL() << "Error: Unable to join thread.\n";
  }
}

} // namespace __mpk_untrusted
