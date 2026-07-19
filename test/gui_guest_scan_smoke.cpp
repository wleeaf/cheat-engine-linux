// Headless (offscreen Qt) end-to-end smoke test for the emulator GuestScanDialog.
// Forks a child that poses as Dolphin (prctl comm) with a 16 MB guest-RAM buffer
// holding a known value, constructs the real dialog against it, drives an exact First
// Scan and a Next Scan by clicking the actual buttons, and checks the results table.
// This exercises the whole GUI path: probeTarget emulator detection -> guest-RAM
// candidate -> GuestView scan/narrow -> table population.

#include "gui/guest_scan_dialog.hpp"
#include "platform/linux/linux_process.hpp"
#include "core/target_profile.hpp"

#include <QApplication>
#include <QLineEdit>
#include <QPushButton>
#include <QTableWidget>

#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <signal.h>
#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <cstring>

static QPushButton* buttonByText(QObject* parent, const QString& text) {
    for (auto* b : parent->findChildren<QPushButton*>())
        if (b->text() == text) return b;
    return nullptr;
}

int main(int argc, char** argv) {
    // Child: name itself "dolphin-emu" and hold a 16 MB guest-RAM buffer whose only
    // occurrence of 12345 (i32) is at guest offset 0x1000.
    pid_t child = fork();
    if (child == 0) {
        prctl(PR_SET_NAME, "dolphin-emu", 0, 0, 0);
        const size_t sz = 16u << 20;
        void* g = mmap(nullptr, sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (g == MAP_FAILED) _exit(1);
        std::memset(g, 0, sz);
        int32_t needle = 12345;
        std::memcpy(static_cast<char*>(g) + 0x1000, &needle, sizeof(needle));
        for (;;) pause();
    }
    usleep(250000);   // let the child map and settle

    QApplication app(argc, argv);
    ce::os::LinuxProcessHandle proc(child);
    ce::gui::GuestScanDialog dlg(&proc);

    auto* valueEdit = dlg.findChild<QLineEdit*>();
    auto* table = dlg.findChild<QTableWidget*>();
    auto* firstBtn = buttonByText(&dlg, "First Scan");
    auto* nextBtn = buttonByText(&dlg, "Next Scan");
    const bool wired = valueEdit && table && firstBtn && nextBtn;

    auto* newBtn = buttonByText(&dlg, "New Scan");
    auto* unknownBtn = buttonByText(&dlg, "Unknown Scan");
    auto* increasedBtn = buttonByText(&dlg, "Increased");
    const bool wired2 = wired && newBtn && unknownBtn && increasedBtn;

    int firstRows = -1, nextRows = -1, incRows = -1;
    if (wired2) {
        // 1) exact First Scan for the known value, then an exact Next Scan (unchanged).
        valueEdit->setText("12345");
        firstBtn->click();
        app.processEvents();
        firstRows = table->rowCount();
        nextBtn->click();
        app.processEvents();
        nextRows = table->rowCount();

        // 2) unknown-value scan + comparison narrowing: snapshot, raise the value in the
        //    target, then "Increased" must narrow to the one offset that grew.
        newBtn->click();
        unknownBtn->click();       // snapshots the region (value still 12345)
        app.processEvents();

        ce::TargetProfile prof = ce::probeTarget(child);
        if (!prof.guestCandidates.empty()) {
            uintptr_t hostAddr = prof.guestCandidates.front().base + 0x1000;
            int32_t bigger = 99999;
            proc.write(hostAddr, &bigger, sizeof(bigger));   // raise it above the snapshot
        }
        increasedBtn->click();
        app.processEvents();
        incRows = table->rowCount();
    }

    kill(child, SIGKILL);
    int status = 0;
    waitpid(child, &status, 0);

    const bool ok = wired2 && firstRows >= 1 && nextRows >= 1 && nextRows <= firstRows &&
                    incRows >= 1;
    printf("gui guest-scan smoke: %s (wired=%d firstRows=%d nextRows=%d incRows=%d)\n",
           ok ? "OK" : "FAILED", wired2, firstRows, nextRows, incRows);
    return ok ? 0 : 1;
}
