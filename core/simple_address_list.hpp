#pragma once
/// Headless in-memory IAddressList — a non-GUI cheat table, so the Lua address
/// list / memory-record API (createMemoryRecord, addressList_*, getTableEntry,
/// setTableEntry, ...) works from the CLI and tests without pulling in Qt.
///
/// Live value reads / freezing are the GUI model's job; this keeps the record
/// metadata (address, type, description, value string, active flag, ...) so scripts
/// can build and inspect a table headlessly.

#include "core/address_list.hpp"

#include <algorithm>

namespace ce {

class SimpleAddressList : public IAddressList {
public:
    int count() const override { return static_cast<int>(entries_.size()); }

    std::optional<AddressEntrySnapshot> at(int index) const override {
        if (index < 0 || index >= static_cast<int>(entries_.size())) return std::nullopt;
        return entries_[index];
    }
    std::optional<AddressEntrySnapshot> byId(int id) const override {
        int i = indexOf(id);
        return i >= 0 ? std::optional<AddressEntrySnapshot>(entries_[i]) : std::nullopt;
    }
    int findIdByDescription(const std::string& desc) const override {
        for (const auto& e : entries_)
            if (e.description == desc) return e.id;
        return -1;
    }
    std::vector<int> ids() const override {
        std::vector<int> out;
        out.reserve(entries_.size());
        for (const auto& e : entries_) out.push_back(e.id);
        return out;
    }

    int createEntry(uintptr_t addr, ValueType type, const std::string& description) override {
        AddressEntrySnapshot e;
        e.id = nextId_++;
        e.address = addr;
        e.type = type;
        e.description = description;
        entries_.push_back(std::move(e));
        return entries_.back().id;
    }
    int createGroup(const std::string& description) override {
        AddressEntrySnapshot e;
        e.id = nextId_++;
        e.description = description;
        e.isGroup = true;
        entries_.push_back(std::move(e));
        return entries_.back().id;
    }
    bool deleteById(int id) override {
        int i = indexOf(id);
        if (i < 0) return false;
        entries_.erase(entries_.begin() + i);
        return true;
    }
    bool disableAllWithoutExecute() override {
        for (auto& e : entries_) e.active = false;
        return true;
    }

    bool setDescription(int id, const std::string& desc) override { return set(id, [&](auto& e){ e.description = desc; }); }
    bool setAddress(int id, uintptr_t addr) override { return set(id, [&](auto& e){ e.address = addr; }); }
    bool setType(int id, ValueType t) override { return set(id, [&](auto& e){ e.type = t; }); }
    bool setValue(int id, const std::string& v) override { return set(id, [&](auto& e){ e.value = v; }); }
    bool setActive(int id, bool a) override {
        return set(id, [&](auto& e){ e.active = a; if (activationCb_) activationCb_(e.id, a); });
    }
    bool setColor(int id, const std::string& c) override { return set(id, [&](auto& e){ e.color = c; }); }
    bool setScript(int id, const std::string& s) override { return set(id, [&](auto& e){ e.script = s; }); }
    bool setHexView(int id, bool hex) override { return set(id, [&](auto& e){ e.showAsHex = hex; }); }
    std::string liveValue(int id) override { auto s = byId(id); return s ? s->value : std::string{}; }

    void setActivationCallback(ActivationCallback cb) override { activationCb_ = std::move(cb); }

    const std::vector<AddressEntrySnapshot>& entries() const { return entries_; }

private:
    int indexOf(int id) const {
        for (int i = 0; i < static_cast<int>(entries_.size()); ++i)
            if (entries_[i].id == id) return i;
        return -1;
    }
    template <typename F>
    bool set(int id, F&& fn) {
        int i = indexOf(id);
        if (i < 0) return false;
        fn(entries_[i]);
        return true;
    }

    std::vector<AddressEntrySnapshot> entries_;
    int nextId_ = 1;
    ActivationCallback activationCb_;
};

} // namespace ce
