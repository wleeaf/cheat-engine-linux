// The graphical tutorial without a window: the same game, ticking 60 times a
// second, with typed commands that hold keys. The tests drive it this way.

#include "tutorial/graphical/text_mode.hpp"

#include "tutorial/graphical/game.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unistd.h>

namespace {

std::mutex gameLock;

void print(const std::string& text) {
    std::fputs(text.c_str(), stdout);
    std::fflush(stdout);
}

std::string bar(float fraction) {
    // A NaN or infinity converted to int is undefined.
    if (!(fraction > 0.0f)) fraction = 0.0f;
    if (fraction > 1.0f) fraction = 1.0f;
    const int filled = static_cast<int>(fraction * 20.0f + 0.5f);
    return "[" + std::string(filled, '#') + std::string(20 - filled, '.') + "]";
}

std::string status() {
    if (gt_finished()) return "Finished\n";
    GtView view;
    gt_view(&view);
    std::string out = "Level " + std::to_string(gt_level()) + " of " + std::to_string(GT_LEVELS) + ": " + gt_title(gt_level()) + "\n";
    if (view.show_target) out += "  Target: " + bar(view.target_health) + "\n";
    if (view.show_heat) out += "  Heat: " + bar(view.heat) + (view.jammed ? " jammed" : "") + "\n";
    if (view.show_door) {
        char power[32];
        std::snprintf(power, sizeof power, "%.0f", static_cast<double>(view.jump_power));
        out += std::string("  Jump power: ") + power + "\n";
        out += std::string("  Player: ") + (view.player.y + view.player.h >= 319.5f ? "on the floor"
                                         : view.player.y + view.player.h <= 180.5f && view.player.x + view.player.w > 420 ? "on the ledge"
                                         : "in the air") + "\n";
    }
    return out;
}

std::string screen() {
    if (gt_finished()) return "\nFinished\n\n" + std::string(gt_finished_text()) + "\n";
    return "\n" + status() + "\n" + gt_text(gt_level()) + "\n\n"
           "Commands: press <keys> <ms> (keys: left, right, fire, jump, joined with +), "
           "wait <ms>, status, next, quit\n";
}

int parseKeys(const std::string& text) {
    int keys = 0;
    std::istringstream parts(text);
    std::string key;
    while (std::getline(parts, key, '+')) {
        if (key == "left") keys |= GT_LEFT;
        else if (key == "right") keys |= GT_RIGHT;
        else if (key == "fire") keys |= GT_FIRE;
        else if (key == "jump") keys |= GT_JUMP;
        else return -1;
    }
    return keys;
}

} // namespace

int runGraphicalTextMode(unsigned seed, int level) {
    {
        std::lock_guard lock(gameLock);
        gt_init(seed);
        if (level > 1) gt_goto(level);
        print("Cheat Engine graphical tutorial (text mode), process id " + std::to_string(getpid()) + "\n" + screen());
    }
    std::atomic<bool> stop{false};
    std::thread ticker([&] {
        using clock = std::chrono::steady_clock;
        auto last = clock::now();
        char message[160];
        while (!stop) {
            std::this_thread::sleep_for(std::chrono::milliseconds(16));
            const auto now = clock::now();
            const float dt = std::chrono::duration<float>(now - last).count();
            last = now;
            std::lock_guard lock(gameLock);
            const bool wasDone = gt_done();
            if (gt_tick(dt > 0.05f ? 0.05f : dt, message, sizeof message)) print(std::string(message) + "\n");
            if (!wasDone && gt_done())
                print("Level " + std::to_string(gt_level()) + " complete. Type next to continue.\n");
        }
    });

    std::string line;
    while (std::getline(std::cin, line)) {
        std::istringstream in(line);
        std::string command, first, second;
        in >> command >> first >> second;
        if (command == "quit" || command == "exit") break;
        if (command == "press" || command == "wait") {
            const int keys = command == "wait" ? 0 : parseKeys(first);
            const std::string duration = command == "wait" ? first : second;
            int ms = 0;
            try { ms = std::stoi(duration); } catch (...) { ms = -1; }
            if (keys < 0 || ms < 0 || ms > 60000) { print("Usage: press <keys> <ms> or wait <ms>\n"); continue; }
            { std::lock_guard lock(gameLock); gt_keys(keys); }
            std::this_thread::sleep_for(std::chrono::milliseconds(ms));
            std::lock_guard lock(gameLock);
            gt_keys(0);
            print(status());
            continue;
        }
        std::lock_guard lock(gameLock);
        if (command == "status") print(status());
        else if (command == "help" || command == "show") print(screen());
        else if (command == "next") print(gt_next() ? screen() : "Finish this level first.\n");
        else if (!command.empty()) print("Unknown command. Type help.\n");
    }
    stop = true;
    ticker.join();
    return 0;
}
