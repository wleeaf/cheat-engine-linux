#include "core/json.hpp"

#include <charconv>
#include <cctype>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cerrno>

namespace ce::json {
namespace {

class Parser {
public:
    explicit Parser(const std::string& input) : input_(input) {
        if (input_.compare(0,3,"\xef\xbb\xbf")==0) pos_=3;
    }

    bool parse(Value& out) {
        skipWs();
        if (!parseValue(out)) return false;
        skipWs();
        return pos_ == input_.size();
    }

private:
    void skipWs() {
        while (pos_<input_.size() && (input_[pos_]==' ' || input_[pos_]=='\t' || input_[pos_]=='\r' || input_[pos_]=='\n'))
            ++pos_;
    }

    bool consume(char expected) {
        skipWs();
        if (pos_ >= input_.size() || input_[pos_] != expected) return false;
        ++pos_;
        return true;
    }

    bool parseValue(Value& out) {
        // Bound nesting so a hostile table (e.g. "[[[[[...]]]]]") can't exhaust
        // the stack through the parseValue/parseArray/parseObject recursion.
        struct DepthGuard {
            int& d;
            explicit DepthGuard(int& v) : d(v) { ++d; }
            ~DepthGuard() { --d; }
        } guard(depth_);
        if (depth_ > kMaxDepth) return false;
        skipWs();
        if (pos_ >= input_.size()) return false;
        char c = input_[pos_];
        if (c == '"') return parseString(out);
        if (c == '{') return parseObject(out);
        if (c == '[') return parseArray(out);
        if (c == '-' || std::isdigit(static_cast<unsigned char>(c))) return parseNumber(out);
        if (input_.compare(pos_, 4, "true") == 0) {
            pos_ += 4;
            out.type = Value::Type::Bool;
            out.boolValue = true;
            return true;
        }
        if (input_.compare(pos_, 5, "false") == 0) {
            pos_ += 5;
            out.type = Value::Type::Bool;
            out.boolValue = false;
            return true;
        }
        if (input_.compare(pos_, 4, "null") == 0) {
            pos_ += 4;
            out.type = Value::Type::Null;
            return true;
        }
        return false;
    }

    bool parseString(Value& out) {
        if (pos_ >= input_.size() || input_[pos_] != '"') return false;
        ++pos_;
        std::string value;
        while (pos_ < input_.size()) {
            char c = input_[pos_++];
            if (c == '"') {
                out.type = Value::Type::String;
                out.stringValue = std::move(value);
                return true;
            }
            if (c != '\\') {
                if (static_cast<unsigned char>(c)<0x20) return false;
                value += c;
                continue;
            }
            if (pos_ >= input_.size()) return false;
            char esc = input_[pos_++];
            switch (esc) {
                case '"': value += '"'; break;
                case '\\': value += '\\'; break;
                case '/': value += '/'; break;
                case 'b': value += '\b'; break;
                case 'f': value += '\f'; break;
                case 'n': value += '\n'; break;
                case 'r': value += '\r'; break;
                case 't': value += '\t'; break;
                case 'u': {
                    auto unit=[&](uint32_t& code) {
                        if (input_.size()-pos_<4) return false;
                        code=0;
                        for (int i=0;i<4;++i) {
                            const char h=input_[pos_++];
                            const int digit=h>='0' && h<='9' ? h-'0' : h>='a' && h<='f' ? h-'a'+10 : h>='A' && h<='F' ? h-'A'+10 : -1;
                            if (digit<0) return false;
                            code=(code<<4)|static_cast<unsigned>(digit);
                        }
                        return true;
                    };
                    uint32_t code=0;
                    if (!unit(code)) return false;
                    if (code>=0xd800 && code<=0xdbff) {
                        if (input_.size()-pos_<2 || input_[pos_]!='\\' || input_[pos_+1]!='u') return false;
                        pos_+=2;uint32_t low=0;
                        if (!unit(low) || low<0xdc00 || low>0xdfff) return false;
                        code=0x10000+((code-0xd800)<<10)+(low-0xdc00);
                    } else if (code>=0xdc00 && code<=0xdfff) return false;
                    if (code<=0x7f) value+=static_cast<char>(code);
                    else {
                        if (code<=0x7ff) value+=static_cast<char>(0xc0|(code>>6));
                        else {
                            if (code<=0xffff) value+=static_cast<char>(0xe0|(code>>12));
                            else {
                                value+=static_cast<char>(0xf0|(code>>18));
                                value+=static_cast<char>(0x80|((code>>12)&63));
                            }
                            value+=static_cast<char>(0x80|((code>>6)&63));
                        }
                        value+=static_cast<char>(0x80|(code&63));
                    }
                    break;
                }
                default:
                    return false;
            }
        }
        return false;
    }

    bool parseNumber(Value& out) {
        const size_t start=pos_;
        auto digit=[&] {return pos_<input_.size() && input_[pos_]>='0' && input_[pos_]<='9';};
        if (input_[pos_]=='-') ++pos_;
        if (!digit()) return false;
        if (input_[pos_]=='0') {++pos_;if (digit()) return false;}
        else while (digit()) ++pos_;
        if (pos_<input_.size() && input_[pos_]=='.') {
            ++pos_;if (!digit()) return false;
            while (digit()) ++pos_;
        }
        if (pos_<input_.size() && (input_[pos_]=='e' || input_[pos_]=='E')) {
            ++pos_;
            if (pos_<input_.size() && (input_[pos_]=='+' || input_[pos_]=='-')) ++pos_;
            if (!digit()) return false;
            while (digit()) ++pos_;
        }
        out.type = Value::Type::Number;
        out.stringValue=input_.substr(start,pos_-start);
        return true;
    }

    bool parseArray(Value& out) {
        if (!consume('[')) return false;
        out.type = Value::Type::Array;
        skipWs();
        if (pos_ < input_.size() && input_[pos_] == ']') {
            ++pos_;
            return true;
        }
        while (true) {
            Value item;
            if (!parseValue(item)) return false;
            out.arrayValue.push_back(std::move(item));
            skipWs();
            if (pos_ < input_.size() && input_[pos_] == ']') {
                ++pos_;
                return true;
            }
            if (!consume(',')) return false;
        }
    }

    bool parseObject(Value& out) {
        if (!consume('{')) return false;
        out.type = Value::Type::Object;
        skipWs();
        if (pos_ < input_.size() && input_[pos_] == '}') {
            ++pos_;
            return true;
        }
        while (true) {
            skipWs();
            Value key;
            if (!parseString(key)) return false;
            if (!consume(':')) return false;
            Value value;
            if (!parseValue(value)) return false;
            if (!out.objectValue.count(key.stringValue)) out.objectOrder.push_back(key.stringValue);
            out.objectValue.insert_or_assign(std::move(key.stringValue), std::move(value));
            skipWs();
            if (pos_ < input_.size() && input_[pos_] == '}') {
                ++pos_;
                return true;
            }
            if (!consume(',')) return false;
        }
    }

    const std::string& input_;
    size_t pos_ = 0;
    int depth_ = 0;
    static constexpr int kMaxDepth = 128;
};


void write(const Value& value, std::string& out) {
    switch (value.type) {
        case Value::Type::Null: out += "null"; break;
        case Value::Type::Bool: out += value.boolValue ? "true" : "false"; break;
        case Value::Type::Number: out += value.stringValue.empty() ? "0" : value.stringValue; break;
        case Value::Type::String: out += '"'; out += escape(value.stringValue); out += '"'; break;
        case Value::Type::Array: {
            out += '[';
            for (size_t i = 0; i < value.arrayValue.size(); ++i) {
                if (i) out += ',';
                write(value.arrayValue[i], out);
            }
            out += ']';
            break;
        }
        case Value::Type::Object: {
            out += '{';
            bool first = true;
            auto member = [&](const std::string& key, const Value& v) {
                if (!first) out += ',';
                first = false;
                out += '"'; out += escape(key); out += "\":";
                write(v, out);
            };
            // Ordered keys first, then any added without order (direct map edits).
            for (const auto& key : value.objectOrder)
                if (auto it = value.objectValue.find(key); it != value.objectValue.end()) member(key, it->second);
            if (value.objectOrder.size() != value.objectValue.size())
                for (const auto& [key, v] : value.objectValue) {
                    bool listed = false;
                    for (const auto& k : value.objectOrder) if (k == key) { listed = true; break; }
                    if (!listed) member(key, v);
                }
            out += '}';
            break;
        }
    }
}

} // namespace

Value Value::number(double n) {
    Value v;
    v.type = Type::Number;
    if (!std::isfinite(n)) { v.type = Type::Null; return v; }   // JSON has no NaN/Inf
    // to_chars is locale-independent (the GUI may run with a "1,5" locale)
    // and gives the shortest text that reads back as the same double.
    char buffer[40];
    auto written = std::to_chars(buffer, buffer + sizeof buffer, n);
    v.stringValue.assign(buffer, written.ptr);
    return v;
}

const Value* Value::get(const std::string& key) const {
    if (type != Type::Object) return nullptr;
    auto it = objectValue.find(key);
    return it == objectValue.end() ? nullptr : &it->second;
}

Value& Value::set(const std::string& key, Value value) {
    type = Type::Object;
    if (!objectValue.count(key)) objectOrder.push_back(key);
    objectValue.insert_or_assign(key, std::move(value));
    return *this;
}

Value& Value::push(Value value) {
    type = Type::Array;
    arrayValue.push_back(std::move(value));
    return *this;
}

std::optional<std::string> Value::getString(const std::string& key) const {
    const Value* v = get(key);
    if (!v || v->type != Type::String) return std::nullopt;
    return v->stringValue;
}

std::optional<int64_t> Value::getInt(const std::string& key) const {
    const Value* v = get(key);
    if (!v || v->type != Type::Number) return std::nullopt;
    char* end = nullptr;
    errno = 0;
    const long long n = std::strtoll(v->stringValue.c_str(), &end, 10);
    if (errno || !end || *end) return std::nullopt;   // fractions and out-of-range are not integers
    return static_cast<int64_t>(n);
}

std::optional<bool> Value::getBool(const std::string& key) const {
    const Value* v = get(key);
    if (!v || v->type != Type::Bool) return std::nullopt;
    return v->boolValue;
}

bool parse(const std::string& input, Value& out) {
    return Parser(input).parse(out);
}

std::string dump(const Value& value) {
    std::string out;
    write(value, out);
    return out;
}

namespace {

// Length of the well-formed UTF-8 sequence at s[i], or 0 if it is not one
// (stray continuation byte, truncated, overlong, surrogate, above U+10FFFF).
size_t utf8Sequence(const std::string& s, size_t i) {
    const auto byte = [&](size_t k) { return static_cast<unsigned char>(s[k]); };
    const unsigned char lead = byte(i);
    size_t length;
    unsigned char low = 0x80, high = 0xBF;   // allowed range of the second byte
    if (lead >= 0xC2 && lead <= 0xDF) length = 2;
    else if (lead >= 0xE0 && lead <= 0xEF) { length = 3; if (lead == 0xE0) low = 0xA0; if (lead == 0xED) high = 0x9F; }
    else if (lead >= 0xF0 && lead <= 0xF4) { length = 4; if (lead == 0xF0) low = 0x90; if (lead == 0xF4) high = 0x8F; }
    else return 0;
    if (i + length > s.size()) return 0;
    if (byte(i + 1) < low || byte(i + 1) > high) return 0;
    for (size_t k = 2; k < length; ++k)
        if ((byte(i + k) & 0xC0) != 0x80) return 0;
    return length;
}

} // namespace

std::string escape(const std::string& s) {
    std::string out;
    for (size_t i = 0; i < s.size(); ++i) {
        const char c = s[i];
        // JSON text is UTF-8: bytes that are not (raw game memory, odd file
        // names) become U+FFFD instead of making the whole message invalid.
        if (static_cast<unsigned char>(c) >= 0x80) {
            if (const size_t length = utf8Sequence(s, i)) {
                out.append(s, i, length);
                i += length - 1;
            } else {
                out += "\\ufffd";
            }
            continue;
        }
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '"':  out += "\\\""; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            case '\b': out += "\\b"; break;
            case '\f': out += "\\f"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    constexpr char hex[] = "0123456789abcdef";
                    out += "\\u00";
                    out += hex[static_cast<unsigned char>(c) >> 4];
                    out += hex[static_cast<unsigned char>(c) & 15];
                } else out += c;
                break;
        }
    }
    return out;
}

} // namespace ce::json
