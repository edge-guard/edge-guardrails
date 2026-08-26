#include "guardrails_bridge.h"
#include <regex>
#include <chrono>
#include <iostream>
#include <string_view>

namespace {

const std::regex& sensitive_pattern() {
    static const std::regex pattern(
        "(\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\\b|"
        "\\b\\d{3}-\\d{2}-\\d{4}\\b|"
        "(?:API_SECRET_KEY|sk_live_[0-9a-zA-Z]{16,}))",
        std::regex::optimize
    );
    return pattern;
}

} // namespace

extern "C" {

int edge_guardrail_check(const char* text, size_t len) {
    if (!text || len == 0) return 0;

    auto start = std::chrono::high_resolution_clock::now();

    std::string_view sv(text, len);
    std::string s(sv);
    bool is_suspicious = std::regex_search(s, sensitive_pattern());

    auto end = std::chrono::high_resolution_clock::now();
    auto elapsed_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

    std::cout << "  [C++ Guardrail Engine] Scanned " << len << " bytes in " 
              << elapsed_us << " us | Verdict: " 
              << (is_suspicious ? "BLOCKED" : "PASSED") << std::endl;

    return is_suspicious ? 1 : 0;
}

}
