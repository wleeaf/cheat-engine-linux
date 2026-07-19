#pragma once
/// Abstract live cheat-table address list.
/// Implemented by the Qt AddressListModel in the GUI. Consumed by Lua bindings without
/// pulling Qt into libcecore. Identifies entries by a stable monotonic int id so script
/// references survive row reordering.

#include "core/types.hpp"
#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace ce {

/// [begin, end) of the rows nested under the group/parent at `row`: the contiguous
/// following rows with a deeper indent. end == row+1 when it has no children. Used to
/// apply a group operation (set value, activate) to its whole subtree.
inline std::pair<std::size_t, std::size_t> descendantRange(const std::vector<int>& indents,
                                                           std::size_t row) {
    std::size_t begin = row + 1, end = begin;
    if (row >= indents.size()) return {begin, begin};
    const int parent = indents[row];
    while (end < indents.size() && indents[end] > parent) ++end;
    return {begin, end};
}

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

/// Permutation (old index for each new position) after moving the contiguous block
/// [start, start+len) so it is inserted before the item originally at `dest` (Qt's
/// drop-row convention). Dragging a group header carries its descendants: pass the
/// group's descendantRange length as `len`. A drop inside or immediately around the
/// block, or any out-of-range argument, yields the identity (no move). Pure + unit
/// tested; the GUI applies the result to reorder its entries on a drag-drop.
inline std::vector<int> moveRangePermutation(int count, int start, int len, int dest) {
    std::vector<int> perm;
    perm.reserve(count > 0 ? count : 0);
    if (count <= 0 || len <= 0 || start < 0 || start + len > count) {
        for (int i = 0; i < count; ++i) perm.push_back(i);   // invalid -> identity
        return perm;
    }
    std::vector<int> rest;                                    // indices outside the block, in order
    rest.reserve(count - len);
    for (int i = 0; i < count; ++i)
        if (i < start || i >= start + len) rest.push_back(i);
    int insertPos = 0;                                        // where the block lands within `rest`
    for (int r : rest) { if (r < dest) ++insertPos; else break; }
    for (int k = 0; k < insertPos; ++k) perm.push_back(rest[k]);
    for (int i = start; i < start + len; ++i) perm.push_back(i);
    for (int k = insertPos; k < (int)rest.size(); ++k) perm.push_back(rest[k]);
    return perm;
}

/// Plan for wrapping a set of selected rows under a NEW group header (CE's "add the
/// selected records to a new group"). `order[i]` is the original row index that belongs
/// at new position i, or -1 where the freshly-created group header goes; `indent[i]` is
/// that position's resulting nesting depth. The header is inserted at the earliest
/// selected row and takes the shallowest indent in the selection; the selected rows are
/// gathered contiguously right after it (original order preserved, relative nesting
/// kept) one level deeper. Non-selected rows keep their order and indent, so any row that
/// sat between two non-adjacent selected rows falls out below the new group. `ok` is
/// false (and the vectors empty) for an empty or fully out-of-range selection. Pure +
/// unit-tested; the GUI applies it, creating a real group entry at each -1.
struct GroupSelectionPlan {
    std::vector<int> order;    // original index per new position, or -1 for the group header
    std::vector<int> indent;   // resulting indent per new position
    bool ok = false;
};

inline GroupSelectionPlan groupSelection(const std::vector<int>& indents,
                                         std::vector<std::size_t> selected) {
    GroupSelectionPlan plan;
    const std::size_t n = indents.size();
    std::sort(selected.begin(), selected.end());
    selected.erase(std::unique(selected.begin(), selected.end()), selected.end());
    while (!selected.empty() && selected.back() >= n) selected.pop_back();
    if (selected.empty()) return plan;

    const std::size_t insertAt = selected.front();   // earliest selected row: where the header lands
    int minSel = indents[selected.front()];
    for (std::size_t s : selected) minSel = std::min(minSel, indents[s]);

    std::vector<char> isSel(n, 0);
    for (std::size_t s : selected) isSel[s] = 1;

    plan.order.reserve(n + 1);
    plan.indent.reserve(n + 1);
    for (std::size_t i = 0; i < n; ++i) {
        if (i == insertAt) {
            plan.order.push_back(-1);        // the new group header
            plan.indent.push_back(minSel);
            for (std::size_t s : selected) { // members, in original order, one level deeper
                plan.order.push_back(static_cast<int>(s));
                plan.indent.push_back(indents[s] + 1);
            }
        }
        if (isSel[i]) continue;              // members already emitted under the header
        plan.order.push_back(static_cast<int>(i));
        plan.indent.push_back(indents[i]);
    }
    plan.ok = true;
    return plan;
}

/// Expand a delete selection so that removing a group header also removes its whole
/// subtree (CE: a group carries its descendants; deleting the header deletes the
/// children too). Given each row's indent and the initially selected rows, return the
/// full ascending, deduplicated set of rows to remove: every selected row plus, for any
/// selected row that heads a subtree, its descendantRange. A leaf's descendantRange is
/// empty, so leaves delete alone; overlapping selections (a group and a row already
/// inside it) collapse cleanly. Pure + unit-tested; removeEntries applies it so no
/// orphaned, wrongly-indented children are left behind.
inline std::vector<std::size_t> expandGroupDeletion(const std::vector<int>& indents,
                                                    const std::vector<std::size_t>& selected) {
    std::vector<char> mark(indents.size(), 0);
    for (std::size_t r : selected) {
        if (r >= indents.size()) continue;
        mark[r] = 1;
        auto sub = descendantRange(indents, r);   // [begin,end) subtree; empty for a leaf
        for (std::size_t i = sub.first; i < sub.second; ++i) mark[i] = 1;
    }
    std::vector<std::size_t> out;
    for (std::size_t i = 0; i < mark.size(); ++i)
        if (mark[i]) out.push_back(i);
    return out;   // ascending
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
