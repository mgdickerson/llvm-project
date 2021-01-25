// TODO: This should not need a relative path, either use an include dir or
// relocate in lib
#include "../util/mpk_untrusted_test_config.h"
#include "alloc_site_handler.h"
#include "gtest/gtest.h"
#include <limits>
#include <memory>

namespace __mpk_untrusted {

// For this test to work properly, we have to ensure all other tests
// remove all allocations that they have added to the map.
TEST(getAllocSite, EmptyMap) {
  auto handle = AllocSiteHandler::get();
  auto allocSite = handle->getAllocSite(nullptr);
  EXPECT_EQ(allocSite.get(), AllocSite::error().get());
}

TEST(getAllocSite, InvalidPreAddress) {
  auto handle = AllocSiteHandler::get();
  auto ptr = (rust_ptr)malloc(sizeof(uint64_t));
  handle->insertAllocSite(
      ptr, std::make_shared<AllocSite>(ptr, sizeof(uint64_t), 1));
  auto decPtr = (rust_ptr)((uintptr_t)ptr - 1);
  auto allocSite = handle->getAllocSite(decPtr);
  EXPECT_EQ(allocSite.get(), AllocSite::error().get());
  handle->removeAllocSite(ptr);
}

TEST(getAllocSite, InvalidPostAddress) {
  auto handle = AllocSiteHandler::get();
  auto ptr = (rust_ptr)malloc(sizeof(uint64_t));
  handle->insertAllocSite(
      ptr, std::make_shared<AllocSite>(ptr, sizeof(uint64_t), 1));
  auto incPtr = (rust_ptr)((uintptr_t)ptr + sizeof(uint64_t));
  auto allocSite = handle->getAllocSite(incPtr);
  EXPECT_EQ(allocSite.get(), AllocSite::error().get());
  handle->removeAllocSite(ptr);
}

TEST(getAllocSite, InvalidBetweenAddress) {
  auto handle = AllocSiteHandler::get();
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
  auto handle = AllocSiteHandler::get();
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
  auto ptr = (rust_ptr)(-1); // 0xffffffffffffffff
  auto newAllocSite = std::make_shared<AllocSite>(ptr, sizeof(uint64_t), 1);
  EXPECT_FALSE(newAllocSite->containsPtr(++ptr));
}

} // namespace __mpk_untrusted
