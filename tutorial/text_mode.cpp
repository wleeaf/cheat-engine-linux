// The tutorial in a terminal: the same game as the window, driven by typed
// commands. It also serves the automated tests, so every line it prints has a
// stable shape ("Health: 93", "Step 2 complete.").

#include "tutorial/text_mode.hpp"

#include "tutorial/game.h"

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

std::mutex gameLock;   // held around every game call and every print

long long nowMs() {
    using namespace std::chrono;
    static const auto start = steady_clock::now();
    return duration_cast<milliseconds>(steady_clock::now() - start).count();
}

void print(const std::string& text) {
    std::fputs(text.c_str(), stdout);
    std::fflush(stdout);
}

std::string wrap(const std::string& text, size_t width = 78) {
    std::string out, line;
    std::string paragraph;
    auto flush = [&] { if (!line.empty()) { out += line + "\n"; line.clear(); } };
    size_t start = 0;
    while (start <= text.size()) {
        const size_t end = text.find("\n\n", start);
        paragraph = text.substr(start, end == std::string::npos ? std::string::npos : end - start);
        std::istringstream words(paragraph);
        std::string word;
        while (words >> word) {
            if (!line.empty() && line.size() + 1 + word.size() > width) flush();
            line += (line.empty() ? "" : " ") + word;
        }
        flush();
        if (end == std::string::npos) break;
        out += "\n";
        start = end + 2;
    }
    return out;
}

std::string fields() {
    std::string out;
    char value[64];
    for (int i = 0; i < tut_field_count(); ++i) {
        tut_field_value(i, value, sizeof value);
        out += std::string("  ") + tut_field_label(i) + ": " + value + "\n";
    }
    return out;
}

std::string commands() {
    std::string out = "Commands:";
    for (int i = 0; i < tut_action_count(); ++i)
        out += std::string(" ") + tut_action_command(i) + " (" + tut_action_label(i) + "),";
    if (tut_step() == 1) out += " password <code>,";
    if (!tut_finished()) out += " next,";
    out += " show, values, quit\n";
    return out;
}

std::string screen() {
    if (tut_finished()) return "\nFinished\n\n" + wrap(tut_finished_text()) + "\nType quit to leave.\n";
    const int step = tut_step();
    std::string out = "\nStep " + std::to_string(step) + " of " + std::to_string(TUT_STEPS) + ": " + tut_title(step) + "\n\n";
    out += wrap(tut_text(step)) + "\n";
    if (step > 1) out += std::string("Password for this step: ") + tut_password(step) + "\n";
    out += fields();
    out += commands();
    return out;
}

std::string completion() {
    return "Step " + std::to_string(tut_step()) + " complete. Type next to continue.\n";
}

void prompt() {
    if (isatty(STDIN_FILENO)) print("> ");
}

} // namespace

int runTutorialTextMode(unsigned seed) {
    {
        std::lock_guard lock(gameLock);
        tut_init(seed);
        print("Cheat Engine tutorial (text mode), process id " + std::to_string(getpid()) + "\n" + screen());
        prompt();
    }

    std::atomic<bool> stop{false};
    std::thread ticker([&] {
        char message[256];
        while (!stop) {
            {
                std::lock_guard lock(gameLock);
                const int step = tut_step();
                const bool wasDone = tut_done();
                const int shown = tut_tick(nowMs(), message, sizeof message);
                std::string out;
                if (shown) out += std::string(message) + "\n";
                if (!wasDone && tut_done() && tut_step() == step) out += completion();
                if (!out.empty()) print(out);
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
    });

    std::string line;
    while (std::getline(std::cin, line)) {
        std::istringstream in(line);
        std::string command, argument;
        in >> command >> argument;
        if (command.empty()) { std::lock_guard lock(gameLock); prompt(); continue; }
        if (command == "quit" || command == "exit") break;
        std::lock_guard lock(gameLock);
        std::string out;
        if (command == "help" || command == "show") {
            out = screen();
        } else if (command == "values") {
            out = fields();
        } else if (command == "next") {
            out = tut_next() ? screen() : "Finish this step first.\n";
        } else if (command == "password") {
            const int step = tut_unlock(argument.c_str());
            out = step ? screen() : (tut_step() == 1 ? "That password does not open a step.\n"
                                                      : "Passwords work on step 1.\n");
        } else {
            int action = -1;
            for (int i = 0; i < tut_action_count(); ++i)
                if (command == tut_action_command(i)) action = i;
            if (action < 0) {
                out = "Unknown command. " + commands();
            } else {
                const bool wasDone = tut_done();
                char message[256];
                tut_action(action, message, sizeof message);
                out = std::string(message) + "\n" + fields();
                if (!wasDone && tut_done()) out += completion();
            }
        }
        print(out);
        prompt();
    }
    stop = true;
    ticker.join();
    return 0;
}
