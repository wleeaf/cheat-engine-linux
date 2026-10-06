// Actual stopped ARM/Thumb applications; compare opaque images independently.
using VfpBank = std::array<uint8_t,260>;
static bool rawRegset(pid_t tid, unsigned note, std::vector<uint8_t>& bytes) {
    bytes.resize(4096);
    iovec io{bytes.data(),bytes.size()};
    if (ptrace(PTRACE_GETREGSET,tid,reinterpret_cast<void*>(uintptr_t(note)),&io)<0 ||
        !io.iov_len || io.iov_len>=bytes.size()) { bytes.clear(); return false; }
    bytes.resize(io.iov_len); return true;
}

static bool rawSetRegset(pid_t tid,unsigned note,const std::vector<uint8_t>& bytes) {
    iovec io{const_cast<uint8_t*>(bytes.data()),bytes.size()};
    return ptrace(PTRACE_SETREGSET,tid,reinterpret_cast<void*>(uintptr_t(note)),&io)==0;
}
static const ce::os::NativeExtendedContext::Regset* bankFor(
    const ce::os::NativeExtendedContext& context,unsigned note) {
    for (const auto& bank:context.regsets) if (bank.note==note) return &bank;
    return nullptr;
}
static void arm32Extended(pid_t tid,Checks& check) {
    std::vector<uint8_t> original,observed,legacy,tls;
    const bool raw=rawRegset(tid,0x400,original);
    uint64_t d8=0,d31=0; uint32_t fpscr=0;
    if (original.size()==260) {
        std::memcpy(&d8,original.data()+8*8,8); std::memcpy(&d31,original.data()+31*8,8);
        std::memcpy(&fpscr,original.data()+256,4);
    }
    check(raw && original.size()==260 && d8==UINT64_C(0x9abcdef012345678) &&
          d31==UINT64_C(0xfedcba9876543210) && fpscr==0x00400000,
          "the real kernel exposes seeded D8 D31 and FPSCR in the 260-byte ARM VFP bank");
    auto captured=ce::os::captureNativeExtendedContext(tid);
    const auto* vfp=captured ? bankFor(*captured,0x400) : nullptr;
    check(vfp && vfp->bytes==original && std::all_of(captured->regsets.begin(),captured->regsets.end(),
          [](const auto& bank) { return bank.note==NT_PRFPREG || bank.note==0x400 || bank.note==0x401; }),
          "product capture uses the actual ARM32 VFP ABI without fabricated ARM64 extensions");
    const bool hasTls=rawRegset(tid,0x401,tls),hasLegacy=rawRegset(tid,NT_PRFPREG,legacy);
    const auto* savedTls=captured ? bankFor(*captured,0x401) : nullptr;
    const auto* savedLegacy=captured ? bankFor(*captured,NT_PRFPREG) : nullptr;
    check(captured && (hasTls ? savedTls && tls.size()==4 && savedTls->bytes==tls : !savedTls) &&
          (hasLegacy ? savedLegacy && savedLegacy->bytes==legacy : !savedLegacy),
          "capture preserves independently probed native FPA or compat TLS images");
    check(captured && ce::os::verifyNativeExtendedContext(tid,*captured).has_value(),
          "the untouched opaque register image verifies without mutation");
    Bank gpBefore{},gpAfter{}; const bool gp=rawBank(tid,gpBefore);
    auto changed=original; if (changed.size()==260) { changed[64]^=0x55; changed[255]^=0x11; changed[258]^=0xc0; }
    const bool mutation=raw && rawSetRegset(tid,0x400,changed) && rawRegset(tid,0x400,observed) && observed==changed;
    check(mutation && gp && rawBank(tid,gpAfter) && gpAfter==gpBefore,
          "actual kernel VFP edits change D8 D31 and FPSCR while preserving all GP registers");
    auto mismatch=captured ? ce::os::verifyNativeExtendedContext(tid,*captured) : ce::Result<void>(std::unexpected(std::make_error_code(std::errc::not_supported)));
    check(!mismatch && mismatch.error()==std::errc::state_not_recoverable && vfp && vfp->bytes==original,
          "verification detects changed floating-point state without replacing the original saved image");
    const bool restored=captured && ce::os::restoreNativeExtendedContext(tid,*captured).has_value();
    check(restored && rawRegset(tid,0x400,observed) && observed==original && rawBank(tid,gpAfter) && gpAfter==gpBefore,
          "opaque recovery restores every VFP byte and leaves the original GP stop intact");
    extendedTarget=tid; extendedWrites=0;
    const bool again=captured && ce::os::restoreNativeExtendedContext(tid,*captured).has_value();
    extendedTarget=0;
    check(again && extendedWrites==0,"idempotent restoration does not rewrite already exact kernel banks");
    if (hasTls) {
        auto secondaryChanged=tls; secondaryChanged[0]^=1;
        const bool secondaryMutation=rawSetRegset(tid,0x401,secondaryChanged) &&
            rawRegset(tid,0x401,observed) && observed==secondaryChanged;
        mismatch=captured ? ce::os::verifyNativeExtendedContext(tid,*captured) : ce::Result<void>(std::unexpected(std::make_error_code(std::errc::not_supported)));
        check(secondaryMutation && !mismatch && mismatch.error()==std::errc::state_not_recoverable,
              "actual compat TLS edits are detected by the complete saved image");
        check(captured && ce::os::restoreNativeExtendedContext(tid,*captured).has_value() &&
              rawRegset(tid,0x401,observed) && observed==tls && rawRegset(tid,0x400,observed) && observed==original,
              "restoration includes the actual compat TLS bank without changing VFP state");
    } else {
        extendedTarget=tid; extendedWrites=0; spoofLegacyRead=true;
        mismatch=captured ? ce::os::verifyNativeExtendedContext(tid,*captured) : ce::Result<void>(std::unexpected(std::make_error_code(std::errc::not_supported)));
        auto refusal=captured ? ce::os::restoreNativeExtendedContext(tid,*captured) : ce::Result<void>(std::unexpected(std::make_error_code(std::errc::not_supported)));
        spoofLegacyRead=false; extendedTarget=0;
        check(hasLegacy && !mismatch && mismatch.error()==std::errc::state_not_recoverable &&
              !refusal && refusal.error()==std::errc::state_not_recoverable && extendedWrites==0,
              "a simulated changed legacy FPA read retains recovery without invoking the unsafe kernel write");
        check(captured && ce::os::restoreNativeExtendedContext(tid,*captured).has_value() &&
              rawRegset(tid,NT_PRFPREG,observed) && observed==legacy && rawRegset(tid,0x400,observed) && observed==original,
              "original legacy FPA bytes remain intact and unchanged recovery finishes without writing them");
    }
    const bool beforeFault=mutation && rawSetRegset(tid,0x400,changed);
    armFault(tid,false,0x400);
    auto ambiguous=captured ? ce::os::restoreNativeExtendedContext(tid,*captured) : ce::Result<void>(std::unexpected(std::make_error_code(std::errc::not_supported)));
    clearArmFault();
    check(beforeFault && !ambiguous && ambiguous.error()==std::errc::state_not_recoverable && forwardedMutation &&
          rawRegset(tid,0x400,observed) && observed==original && captured &&
          ce::os::restoreNativeExtendedContext(tid,*captured).has_value(),
          "an injected error after a real VFP restore retains its image and permits verified retry");
    const bool beforeReject=mutation && rawSetRegset(tid,0x400,changed);
    extendedTarget=tid; rejectExtendedWrite=true;
    auto rejected=captured ? ce::os::restoreNativeExtendedContext(tid,*captured) : ce::Result<void>(std::unexpected(std::make_error_code(std::errc::not_supported)));
    extendedTarget=0; rejectExtendedWrite=false;
    const bool retained=beforeReject && !rejected && rejected.error()==std::errc::state_not_recoverable &&
        rawRegset(tid,0x400,observed) && observed==changed && rawBank(tid,gpAfter) && gpAfter==gpBefore;
    const bool recovered=captured && ce::os::restoreNativeExtendedContext(tid,*captured).has_value() &&
        rawRegset(tid,0x400,observed) && observed==original && ce::os::verifyNativeExtendedContext(tid,*captured).has_value();
    check(retained && recovered,"a refused VFP restoration keeps the real stopped task recoverable by the original owner");
    // Baseline cleanup may use raw kernel restoration, but the product asserts
    // above cannot pass through this fallback. The application can still finish.
    if (!recovered && raw) rawSetRegset(tid,0x400,original);
    if (hasTls) rawSetRegset(tid,0x401,tls);
    captureFaultTarget=tid; captureFaultHits=0;
    auto unavailable=ce::os::captureNativeExtendedContext(tid);
    captureFaultTarget=0;
    check(!unavailable && captureFaultHits>0 && unavailable.error()==std::errc::io_error && rawRegset(tid,0x400,observed) && observed==original,
          "a failed required VFP capture cannot be silently omitted from a successful saved image");
}
#if defined(__aarch64__)
static void native64Extended(pid_t tid,Checks& check) {
    std::vector<uint8_t> original,observed;
    const bool raw=rawRegset(tid,NT_PRFPREG,original);
    check(raw && original.size()==528,"native ARM64 retains its independent 528-byte FPSIMD ABI");
    auto captured=ce::os::captureNativeExtendedContext(tid);
    const auto* fp=captured ? bankFor(*captured,NT_PRFPREG) : nullptr;
    check(fp && fp->bytes==original && !bankFor(*captured,0x400),
          "native ARM64 capture preserves FPSIMD and retains its extended-state backend");
    check(captured && ce::os::verifyNativeExtendedContext(tid,*captured).has_value(),
          "the complete native ARM64 extension snapshot initially verifies");
    std::array<uint64_t,34> before{},after{};
    const auto gp=[&](auto& bank) {
        iovec io{bank.data(),sizeof(bank)};
        return ptrace(PTRACE_GETREGSET,tid,reinterpret_cast<void*>(NT_PRSTATUS),&io)==0 && io.iov_len==sizeof(bank);
    };
    const bool originalGp=gp(before);
    auto changed=original; if (!changed.empty()) changed[1]^=0x5a;
    const bool mutation=raw && rawSetRegset(tid,NT_PRFPREG,changed) && rawRegset(tid,NT_PRFPREG,observed) && observed==changed;
    check(mutation && originalGp && gp(after) && after==before,
          "actual native ARM64 vector mutation preserves the original general-register stop");
    auto mismatch=captured ? ce::os::verifyNativeExtendedContext(tid,*captured) : ce::Result<void>(std::unexpected(std::make_error_code(std::errc::not_supported)));
    check(!mismatch && mismatch.error()==std::errc::state_not_recoverable && fp && fp->bytes==original,
          "native ARM64 extension verification retains its original changed vector image");
    check(captured && ce::os::restoreNativeExtendedContext(tid,*captured).has_value() &&
          ce::os::verifyNativeExtendedContext(tid,*captured).has_value() && rawRegset(tid,NT_PRFPREG,observed) && observed==original && gp(after) && after==before,
          "native ARM64 restores FPSIMD and every captured extension without changing GP state");
    extendedTarget=tid; extendedWrites=0;
    const bool repeated=captured && ce::os::restoreNativeExtendedContext(tid,*captured).has_value();
    extendedTarget=0;
    check(repeated && extendedWrites==0,"exact native ARM64 recovery avoids redundant extension writes");
    const bool beforeFault=mutation && rawSetRegset(tid,NT_PRFPREG,changed);
    armFault(tid,false,NT_PRFPREG);
    auto ambiguous=captured ? ce::os::restoreNativeExtendedContext(tid,*captured) : ce::Result<void>(std::unexpected(std::make_error_code(std::errc::not_supported)));
    clearArmFault();
    check(beforeFault && !ambiguous && ambiguous.error()==std::errc::state_not_recoverable && forwardedMutation && captured &&
          ce::os::restoreNativeExtendedContext(tid,*captured).has_value() && ce::os::verifyNativeExtendedContext(tid,*captured).has_value(),
          "an error after actual native ARM64 restoration remains recoverable by its stopped owner");
}
#endif
