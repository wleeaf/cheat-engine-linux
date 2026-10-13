#pragma once
/// Small JSON value, parser and writer shared by the table loader and the agent
/// tools. The parser treats its input as untrusted: nesting is bounded, strings
/// are validated (escapes, surrogate pairs, control characters) and numbers are
/// kept as their exact text, so 64-bit addresses never pass through a double.

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace ce::json {

struct Value {
    enum class Type { Null, Bool, Number, String, Array, Object };

    Type type = Type::Null;
    bool boolValue = false;
    // String contents, or the exact source text of a number.
    std::string stringValue;
    std::vector<Value> arrayValue;
    std::unordered_map<std::string, Value> objectValue;
    // Key order of an object, so written JSON keeps the order it was built in.
    std::vector<std::string> objectOrder;

    static Value object() { Value v; v.type = Type::Object; return v; }
    static Value array() { Value v; v.type = Type::Array; return v; }
    static Value string(std::string s) { Value v; v.type = Type::String; v.stringValue = std::move(s); return v; }
    static Value boolean(bool b) { Value v; v.type = Type::Bool; v.boolValue = b; return v; }
    static Value number(int64_t n) { Value v; v.type = Type::Number; v.stringValue = std::to_string(n); return v; }
    static Value number(uint64_t n) { Value v; v.type = Type::Number; v.stringValue = std::to_string(n); return v; }
    static Value number(int n) { return number(static_cast<int64_t>(n)); }
    static Value number(double n);

    bool isNull() const { return type == Type::Null; }
    bool isObject() const { return type == Type::Object; }
    bool isArray() const { return type == Type::Array; }
    bool isString() const { return type == Type::String; }
    bool isNumber() const { return type == Type::Number; }
    bool isBool() const { return type == Type::Bool; }

    /// Object member, or nullptr when absent or this is not an object.
    const Value* get(const std::string& key) const;
    /// Set an object member (keeps first-insertion order). Returns *this.
    Value& set(const std::string& key, Value value);
    /// Append an array element. Returns *this.
    Value& push(Value value);

    /// Typed accessors for object members; nullopt when missing or mistyped.
    std::optional<std::string> getString(const std::string& key) const;
    std::optional<int64_t> getInt(const std::string& key) const;
    std::optional<bool> getBool(const std::string& key) const;
};

/// Parse a complete JSON document (an optional UTF-8 BOM is skipped).
bool parse(const std::string& input, Value& out);

/// Write compact JSON.
std::string dump(const Value& value);

/// Escape a string for a JSON string literal (without the quotes).
std::string escape(const std::string& s);

} // namespace ce::json
