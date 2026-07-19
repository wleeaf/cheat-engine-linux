#pragma once
/// Abstract live cheat-table address list.
/// Implemented by the Qt AddressListModel in the GUI. Consumed by Lua bindings without
/// pulling Qt into libcecore. Identifies entries by a stable monotonic int id so script
/// references survive row reordering.

#include "core/types.hpp"
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace ce {

/// Given each cheat-table row's indent depth and which rows are collapsed groups,
/// return whether each row should be hidden because an ancestor group is collapsed.
/// A collapsed group at indent d hides the following contiguous rows with indent > d
/// (its descendants), until a row at indent <= d ends its scope. Nested collapse is
/// handled. Pure and unit-tested; the GUI feeds the result to setRowHidden.
inline std::vector<bool> hiddenByCollapse(const std::vector<int>& indents,
                                          const std::vector<bool>& collapsed) {
    std::vector<bool> hidden(indents.size(), false);
    std::vector<int> activeCollapsedIndents;   // stack of collapsed groups still in scope
    for (std::size_t i = 0; i < indents.size(); ++i) {
        const int d = indents[i];
        while (!activeCollapsedIndents.empty() && activeCollapsedIndents.back() >= d)
            activeCollapsedIndents.pop_back();
        hidden[i] = !activeCollapsedIndents.empty();
        if (i < collapsed.size() && collapsed[i])
            activeCollapsedIndents.push_back(d);
    }
    return hidden;
}

struct AddressEntrySnapshot {
    int id = 0;
    std::string description;
    uintptr_t address = 0;
    ValueType type = ValueType::Int32;
    std::string value;
    std::string color;
    std::string script;
    std::string hotkeyKeys;
    bool active = false;
    bool isGroup = false;
    bool showAsHex = false;
    int indent = 0;
};

class IAddressList {
public:
    virtual ~IAddressList() = default;

    virtual int count() const = 0;
    virtual std::optional<AddressEntrySnapshot> at(int index) const = 0;
    virtual std::optional<AddressEntrySnapshot> byId(int id) const = 0;
    virtual int findIdByDescription(const std::string& desc) const = 0;
    virtual std::vector<int> ids() const = 0;

    virtual int createEntry(uintptr_t addr, ValueType type, const std::string& description) = 0;
    virtual int createGroup(const std::string& description) = 0;
    virtual bool deleteById(int id) = 0;
    virtual bool disableAllWithoutExecute() = 0;

    virtual bool setDescription(int id, const std::string& desc) = 0;
    virtual bool setAddress(int id, uintptr_t addr) = 0;
    /// Set the address as a re-evaluated expression (pointer records):
    /// "[base+off]+off2", "module+offset", etc. Resolved live on each refresh.
    /// Default no-op keeps non-GUI IAddressList implementations compiling.
    virtual bool setAddressExpression(int /*id*/, const std::string& /*expr*/) { return false; }
    virtual bool setType(int id, ValueType t) = 0;
    virtual bool setValue(int id, const std::string& valStr) = 0;
    virtual bool setActive(int id, bool active) = 0;
    virtual bool setColor(int id, const std::string& color) = 0;
    virtual bool setScript(int id, const std::string& script) = 0;
    /// Live-read the record's current value (re-resolve pointer + read process).
    /// Empty string if unavailable. Default no-op for non-GUI lists.
    virtual std::string liveValue(int /*id*/) { return {}; }
    /// Freeze direction: 0=Normal(locked) 1=IncreaseOnly 2=DecreaseOnly
    /// 3=NeverIncrease 4=NeverDecrease. Default no-op for non-GUI lists.
    virtual bool setFreezeMode(int /*id*/, int /*mode*/) { return false; }
    /// Display/edit the record's value in hexadecimal (by id). Default no-op.
    virtual bool setHexView(int /*id*/, bool /*hex*/) { return false; }
    /// Element length for String / Array-of-byte records (bytes). Default no-op.
    virtual bool setByteCount(int /*id*/, std::size_t /*count*/) { return false; }
    /// Display integer values signed vs unsigned (CE ShowAsSigned). Default no-op.
    virtual bool setSigned(int /*id*/, bool /*isSigned*/) { return false; }
    /// Nesting depth under group headers (0 = root). The current level is exposed
    /// read-side via AddressEntrySnapshot::indent. Default no-op for non-GUI lists.
    virtual bool setIndent(int /*id*/, int /*indent*/) { return false; }

    using ActivationCallback = std::function<void(int id, bool active)>;
    virtual void setActivationCallback(ActivationCallback cb) = 0;
};

} // namespace ce
