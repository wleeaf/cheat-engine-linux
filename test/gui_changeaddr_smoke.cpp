// Headless (offscreen Qt) smoke test for the "Change address" dialog (CE
// formAddressChangeUnit). Cheat Engine has no separate "Unicode String" type: a
// Unicode string is the String type with the Unicode box ticked. This verifies that
// folding (String + Unicode -> UnicodeString), the reverse round-trip (a UnicodeString
// entry opens as String + ticked box), the Length round-trip, and that Unicode is only
// offered for the String type. Exit 0 on success.

#include "gui/changeaddressdialog.hpp"
#include "platform/linux/linux_process.hpp"

#include <QApplication>
#include <cstdio>
#include <cstdint>
#include <unistd.h>

using ce::gui::ChangeAddressDialog;

// A one-level pointer in this process: g_ptrslot holds &g_val, so the chain
// [g_ptrslot]+0 resolves to &g_val for the live-resolution preview test.
static int g_val = 4321;
static uintptr_t g_ptrslot;

int main(int argc, char** argv) {
    qputenv("QT_QPA_PLATFORM", "offscreen");
    QApplication app(argc, argv);

    // Start as a String entry, length 8.
    ChangeAddressDialog d("0x1000", ce::ValueType::String, false, 8);
    bool lenOk = (d.length() == 8);                       // length round-trips in

    // Ticking Unicode turns the String type into UnicodeString; unticking reverts.
    d.setUnicodeForTest(true);
    bool foldUnicode = (d.valueType() == ce::ValueType::UnicodeString);
    d.setUnicodeForTest(false);
    bool plainString = (d.valueType() == ce::ValueType::String);

    // A UnicodeString entry opens as String + a ticked Unicode box, length preserved.
    ChangeAddressDialog d2("0x2000", ce::ValueType::UnicodeString, false, 16);
    bool roundTrip = d2.unicodeCheckedForTest()
                  && d2.valueType() == ce::ValueType::UnicodeString
                  && d2.length() == 16;

    // Unicode is only offered for String: disabled for a numeric type, enabled once
    // the type is switched to String (kTypes order: index 6 == "String").
    ChangeAddressDialog d3("0x3000", ce::ValueType::Int32, false, 1);
    bool disabledForInt = !d3.unicodeEnabledForTest();
    d3.setTypeIndexForTest(6);
    bool enabledForString = d3.unicodeEnabledForTest();

    // Pointer editor: ticking Pointer composes [[base]+..] from base + offset chain.
    ChangeAddressDialog dp("0x1000", ce::ValueType::Int32, false, 1);
    dp.setPointerModeForTest(true);
    dp.setPointerBaseForTest("game.exe+1C");
    dp.addOffsetForTest(0x10);   // first-added offset is the outermost (final)
    dp.addOffsetForTest(0x8);
    bool composeOk = dp.isPointer() && dp.offsetRowCountForTest() == 2
                  && dp.address() == "[[game.exe+1C]+8]+10";

    // A pointer entry opens in pointer mode with its rows populated, and round-trips.
    ChangeAddressDialog dr("[[game.exe+1C]+8]+10", ce::ValueType::Int32, false, 1);
    bool rtOk = dr.isPointer() && dr.offsetRowCountForTest() == 2
             && dr.address() == "[[game.exe+1C]+8]+10";

    // A plain address stays a non-pointer entry.
    ChangeAddressDialog dpl("00400000", ce::ValueType::Int32, false, 1);
    bool plainOk = !dpl.isPointer() && dpl.address() == "00400000";
    bool ptrOk = composeOk && rtOk && plainOk;

    // Signed (CE cbSigned / ShowAsSigned): the incoming flag round-trips, and the box is
    // offered only for integer types (enabled for 4 Bytes, disabled for Float).
    ChangeAddressDialog ds("0x1000", ce::ValueType::Int32, false, 1, nullptr, /*showSigned=*/false);
    bool signedRoundTripOff = (ds.isSigned() == false) && ds.signedEnabledForTest();
    ChangeAddressDialog ds2("0x1000", ce::ValueType::Int32, false, 1, nullptr, /*showSigned=*/true);
    bool signedRoundTripOn = (ds2.isSigned() == true);
    ds2.setTypeIndexForTest(4);   // Float: signed is not applicable, so the box disables
    bool signedDisabledForFloat = !ds2.signedEnabledForTest();
    bool signedOk = signedRoundTripOff && signedRoundTripOn && signedDisabledForFloat;

    // Live pointer resolution preview (CE resolves the chain as you build it): with a
    // process, the composed chain resolves and the preview shows the target address.
    g_ptrslot = reinterpret_cast<uintptr_t>(&g_val);
    ce::os::LinuxProcessHandle proc(getpid());
    ChangeAddressDialog dprev("0x0", ce::ValueType::Int32, false, 1, nullptr, /*showSigned=*/true, &proc);
    dprev.setPointerModeForTest(true);
    dprev.setPointerBaseForTest(QString("0x%1").arg(reinterpret_cast<uintptr_t>(&g_ptrslot), 0, 16));
    dprev.addOffsetForTest(0);   // [g_ptrslot]+0 -> &g_val
    // The preview shows the resolved address and the Int32 value there (g_val == 4321).
    QString want = QStringLiteral("→ 0x%1 = 4321").arg(reinterpret_cast<uintptr_t>(&g_val), 0, 16);
    bool previewOk = (dprev.previewTextForTest() == want);
    // Without a process, no preview is shown (nothing to resolve against).
    ChangeAddressDialog dnop("0x0", ce::ValueType::Int32, false, 1);
    dnop.setPointerModeForTest(true);
    dnop.setPointerBaseForTest("0x1000");
    dnop.addOffsetForTest(0);
    bool noPreviewOk = dnop.previewTextForTest().isEmpty();
    bool livePreviewOk = previewOk && noPreviewOk;

    bool ok = lenOk && foldUnicode && plainString && roundTrip && disabledForInt
           && enabledForString && ptrOk && signedOk && livePreviewOk;
    printf("gui changeaddr smoke: %s (len=%d fold=%d plain=%d roundTrip=%d intDisabled=%d "
           "strEnabled=%d compose=%d ptrRoundTrip=%d plainAddr=%d signed=%d livePreview=%d)\n",
           ok ? "OK" : "FAILED", (int)lenOk, (int)foldUnicode, (int)plainString, (int)roundTrip,
           (int)disabledForInt, (int)enabledForString, (int)composeOk, (int)rtOk, (int)plainOk,
           (int)signedOk, (int)livePreviewOk);
    return ok ? 0 : 1;
}
