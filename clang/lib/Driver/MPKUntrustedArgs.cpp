//===--- MPKUntrustedArgs.cpp - Arguments for MPKUntrusted ----------------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
#include "clang/Driver/MPKUntrustedArgs.h"
#include "ToolChains/CommonArgs.h"
#include "clang/Driver/Driver.h"
#include "clang/Driver/DriverDiagnostic.h"
#include "clang/Driver/Options.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Support/Path.h"
#include <clang/Driver/ToolChain.h>

using namespace clang;
using namespace clang::driver;
using namespace llvm::opt;

namespace {
constexpr char MPKUntrustedInstrumentOption[] = "-fmpk_untrusted";
} // namespace

MPKUntrustedArgs::MPKUntrustedArgs(const ToolChain &TC, const ArgList &Args) {
  const Driver &D = TC.getDriver();
  const llvm::Triple &Triple = TC.getTriple();
  if (Args.hasFlag(options::OPT_fmpk_untrusted, options::OPT_fnompk_untrusted,
                   false)) {
    if (Triple.getOS() == llvm::Triple::Linux ||
        Triple.getOS() == llvm::Triple::Fuchsia) {
      switch (Triple.getArch()) {
      case llvm::Triple::x86_64:
      case llvm::Triple::arm:
      case llvm::Triple::aarch64:
      case llvm::Triple::ppc64le:
      case llvm::Triple::mips:
      case llvm::Triple::mipsel:
      case llvm::Triple::mips64:
      case llvm::Triple::mips64el:
        break;
      default:
        D.Diag(diag::err_drv_clang_unsupported)
            << (std::string(MPKUntrustedInstrumentOption) + " on " +
                Triple.str());
      }
    } else if (Triple.getOS() == llvm::Triple::FreeBSD ||
               Triple.getOS() == llvm::Triple::OpenBSD ||
               Triple.getOS() == llvm::Triple::Darwin ||
               Triple.getOS() == llvm::Triple::NetBSD) {
      if (Triple.getArch() != llvm::Triple::x86_64) {
        D.Diag(diag::err_drv_clang_unsupported)
            << (std::string(MPKUntrustedInstrumentOption) + " on " +
                Triple.str());
      }
    } else {
      D.Diag(diag::err_drv_clang_unsupported)
          << (std::string(MPKUntrustedInstrumentOption) + " on " +
              Triple.str());
    }

    MPKUntrusted = true;
    MPKUntrustedRT = true;

    // if (!Args.hasFlag(options::OPT_fmpk_untrusted_link_deps,
    //                  options::OPT_fnompk_untrusted_link_deps, true))
    //    MPKUntrustedRT = false;
  }
}

void MPKUntrustedArgs::addArgs(const ToolChain &TC, const ArgList &Args,
                               ArgStringList &CmdArgs,
                               types::ID InputType) const {
  if (!MPKUntrusted)
    return;

  CmdArgs.push_back(MPKUntrustedInstrumentOption);
}
