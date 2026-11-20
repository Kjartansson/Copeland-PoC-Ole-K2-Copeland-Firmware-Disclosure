#include <algorithm>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <limits>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

using Block = std::uint64_t;
using Blocks = std::vector<Block>;
using Prev = std::vector<std::int64_t>;

static std::vector<std::uint8_t> read_file(const std::string &path) {
    std::ifstream input(path, std::ios::binary | std::ios::ate);
    if (!input) throw std::runtime_error("cannot open " + path);
    auto size = input.tellg();
    if (size < 0) throw std::runtime_error("cannot size " + path);
    std::vector<std::uint8_t> data(static_cast<std::size_t>(size));
    input.seekg(0);
    if (size && !input.read(reinterpret_cast<char *>(data.data()), size))
        throw std::runtime_error("cannot read " + path);
    return data;
}

static Blocks to_blocks(const std::vector<std::uint8_t> &data, std::size_t begin,
                        std::size_t end, std::size_t shift = 0) {
    if (begin > end || end > data.size() || begin + shift >= end)
        throw std::runtime_error("invalid block range");
    Blocks blocks;
    blocks.reserve((end - begin - shift) / 8);
    for (std::size_t i = begin + shift; i + 8 <= end; i += 8) {
        Block value;
        std::memcpy(&value, data.data() + i, 8);
        blocks.push_back(value);
    }
    return blocks;
}

static Blocks read_candidate(const std::string &path, std::size_t shift,
                             std::size_t offset, std::size_t length) {
    auto data = read_file(path);
    if (offset > data.size()) throw std::runtime_error("candidate offset past end");
    std::size_t end = length ? std::min(data.size(), offset + length) : data.size();
    if (end < offset) throw std::runtime_error("candidate range overflow");
    return to_blocks(data, offset, end, shift);
}

static Blocks read_sfub(const std::string &path) {
    auto data = read_file(path);
    const std::size_t header = 0x210;
    if (data.size() < header || std::memcmp(data.data(), "SFUB_update", 11) != 0)
        throw std::runtime_error("target must be a raw SFUB container");
    std::uint32_t declared;
    std::memcpy(&declared, data.data() + 0x34, 4);
    if (declared > data.size() - header) throw std::runtime_error("truncated SFUB");
    return to_blocks(data, header, header + declared);
}

static Prev previous_occurrences(const Blocks &blocks) {
    Prev previous(blocks.size(), -1);
    std::unordered_map<Block, std::int64_t> last;
    last.reserve(blocks.size() * 1.2 + 1);
    for (std::size_t i = 0; i < blocks.size(); ++i) {
        auto it = last.find(blocks[i]);
        if (it != last.end()) previous[i] = it->second;
        last[blocks[i]] = static_cast<std::int64_t>(i);
    }
    return previous;
}

static std::uint64_t signature(const Prev &previous, std::size_t start,
                               std::size_t width, unsigned &repeats) {
    std::uint64_t hash = 1469598103934665603ULL;
    repeats = 0;
    for (std::size_t i = start; i < start + width; ++i) {
        unsigned distance = 0;
        if (previous[i] >= 0 && previous[i] >= static_cast<std::int64_t>(start)) {
            distance = static_cast<unsigned>(i - previous[i]);
            ++repeats;
        }
        hash ^= distance + 1;
        hash *= 1099511628211ULL;
    }
    return hash;
}

static bool same_signature(const Prev &a, std::size_t apos,
                           const Prev &b, std::size_t bpos, std::size_t width) {
    for (std::size_t i = 0; i < width; ++i) {
        std::int64_t ad = 0, bd = 0;
        if (a[apos + i] >= static_cast<std::int64_t>(apos))
            ad = static_cast<std::int64_t>(apos + i) - a[apos + i];
        if (b[bpos + i] >= static_cast<std::int64_t>(bpos))
            bd = static_cast<std::int64_t>(bpos + i) - b[bpos + i];
        if (ad != bd) return false;
    }
    return true;
}

struct Alignment {
    std::uint64_t votes = 0;
    std::size_t candidate_position = 0;
    std::size_t target_position = 0;
};

struct Score {
    std::int64_t start = 0;
    std::uint64_t votes = 0;
    std::uint64_t matching_repeats = 0;
    std::uint64_t mismatches = 0;
    std::uint64_t candidate_repeats = 0;
    bool exact = false;
};

static Score score_alignment(const Prev &candidate, const Prev &target,
                             std::int64_t start, std::uint64_t votes) {
    Score score;
    score.start = start;
    score.votes = votes;
    if (start < 0 || static_cast<std::size_t>(start) + candidate.size() > target.size()) {
        score.mismatches = candidate.size();
        return score;
    }
    const std::size_t offset = static_cast<std::size_t>(start);
    for (std::size_t i = 0; i < candidate.size(); ++i) {
        std::int64_t cd = candidate[i] >= 0 ? static_cast<std::int64_t>(i) - candidate[i] : 0;
        std::int64_t td = 0;
        if (target[offset + i] >= start)
            td = static_cast<std::int64_t>(offset + i) - target[offset + i];
        if (cd) ++score.candidate_repeats;
        if (cd && cd == td) ++score.matching_repeats;
        if (cd != td) ++score.mismatches;
    }
    score.exact = score.mismatches == 0 && score.candidate_repeats >= 4;
    return score;
}

static std::vector<Score> match(const Blocks &candidate, const Blocks &target,
                                std::size_t width, unsigned min_repeats) {
    if (candidate.size() < width || target.size() < width) return {};
    Prev cp = previous_occurrences(candidate);
    Prev tp = previous_occurrences(target);
    std::unordered_map<std::uint64_t, std::vector<std::size_t>> index;
    for (std::size_t i = 0; i + width <= candidate.size(); ++i) {
        unsigned repeats;
        auto hash = signature(cp, i, width, repeats);
        if (repeats >= min_repeats) index[hash].push_back(i);
    }
    std::unordered_map<std::int64_t, Alignment> alignments;
    for (std::size_t i = 0; i + width <= target.size(); ++i) {
        unsigned repeats;
        auto hash = signature(tp, i, width, repeats);
        if (repeats < min_repeats) continue;
        auto found = index.find(hash);
        if (found == index.end()) continue;
        for (auto position : found->second) {
            if (!same_signature(cp, position, tp, i, width)) continue;
            std::int64_t start = static_cast<std::int64_t>(i) - static_cast<std::int64_t>(position);
            if (start < 0 || static_cast<std::size_t>(start) + candidate.size() > target.size()) continue;
            auto &alignment = alignments[start];
            if (!alignment.votes) {
                alignment.candidate_position = position;
                alignment.target_position = i;
            }
            ++alignment.votes;
        }
    }
    std::vector<std::pair<std::int64_t, std::uint64_t>> ordered;
    ordered.reserve(alignments.size());
    for (const auto &entry : alignments) ordered.emplace_back(entry.first, entry.second.votes);
    std::sort(ordered.begin(), ordered.end(), [](const auto &a, const auto &b) {
        return a.second > b.second;
    });
    if (ordered.size() > 4096) ordered.resize(4096);
    std::vector<Score> scores;
    for (const auto &entry : ordered)
        scores.push_back(score_alignment(cp, tp, entry.first, entry.second));
    std::sort(scores.begin(), scores.end(), [](const Score &a, const Score &b) {
        if (a.exact != b.exact) return a.exact > b.exact;
        if (a.matching_repeats != b.matching_repeats)
            return a.matching_repeats > b.matching_repeats;
        if (a.mismatches != b.mismatches) return a.mismatches < b.mismatches;
        return a.votes > b.votes;
    });
    if (scores.size() > 20) scores.resize(20);
    return scores;
}

static void self_test() {
    Blocks candidate(400), target(3000);
    for (std::size_t i = 0; i < candidate.size(); ++i)
        candidate[i] = i % 11 == 0 ? 7 : (i % 7 == 0 ? 11 : (i % 5 == 0 ? 13 :
                       (i % 3 == 0 ? 17 : 1000 + i * 13)));
    for (std::size_t i = 0; i < target.size(); ++i) target[i] = 9000000 + i * 17;
    std::unordered_map<Block, Block> permutation;
    Block next = 5000000;
    const std::size_t embedded = 777;
    for (std::size_t i = 0; i < candidate.size(); ++i) {
        auto [it, inserted] = permutation.emplace(candidate[i], next);
        if (inserted) next += 101;
        target[embedded + i] = it->second;
    }
    auto scores = match(candidate, target, 32, 4);
    if (scores.empty() || !scores.front().exact || scores.front().start != embedded) {
        std::cerr << "self-test scores: " << scores.size() << '\n';
        for (const auto &s : scores)
            std::cerr << "start=" << s.start << " votes=" << s.votes
                      << " matching=" << s.matching_repeats << " mismatches=" << s.mismatches
                      << " repeats=" << s.candidate_repeats << " exact=" << s.exact << '\n';
        throw std::runtime_error("ECB pattern self-test failed");
    }
    std::cout << "PASS synthetic ECB pattern match at block 777\n";

    Blocks sparse_candidate(128), sparse_target(2048);
    for (std::size_t i = 0; i < sparse_candidate.size(); ++i) sparse_candidate[i] = 2000 + i;
    for (std::size_t i = 0; i < sparse_target.size(); ++i) sparse_target[i] = 8000000 + i * 19;
    for (std::size_t i = 5; i < 9; ++i) sparse_candidate[i + 20] = sparse_candidate[i];
    permutation.clear();
    next = 6000000;
    const std::size_t sparse_embedded = 123;
    for (std::size_t i = 0; i < sparse_candidate.size(); ++i) {
        auto [it, inserted] = permutation.emplace(sparse_candidate[i], next);
        if (inserted) next += 103;
        sparse_target[sparse_embedded + i] = it->second;
    }
    auto sparse_scores = match(sparse_candidate, sparse_target, 32, 4);
    if (sparse_scores.empty() || !sparse_scores.front().exact ||
        sparse_scores.front().start != sparse_embedded) {
        std::cerr << "sparse self-test scores: " << sparse_scores.size() << '\n';
        for (const auto &s : sparse_scores)
            std::cerr << "start=" << s.start << " votes=" << s.votes
                      << " matching=" << s.matching_repeats << " mismatches=" << s.mismatches
                      << " repeats=" << s.candidate_repeats << " exact=" << s.exact << '\n';
        throw std::runtime_error("sparse ECB pattern self-test failed");
    }
    std::cout << "PASS sparse ECB pattern match at block 123\n";
}

int main(int argc, char **argv) {
    try {
        if (argc == 2 && std::string(argv[1]) == "--self-test") {
            self_test();
            return 0;
        }
        if (argc < 3 || argc > 8) {
            std::cerr << "usage: sfub_ecb_pattern_match CANDIDATE RAW_SFUB [SHIFT] [WIDTH] [MIN_REPEATS] [OFFSET] [LENGTH]\n";
            return 2;
        }
        std::size_t shift = argc > 3 ? std::stoul(argv[3]) : 0;
        std::size_t width = argc > 4 ? std::stoul(argv[4]) : 32;
        unsigned min_repeats = argc > 5 ? std::stoul(argv[5]) : 4;
        std::size_t offset = argc > 6 ? std::stoul(argv[6]) : 0;
        std::size_t length = argc > 7 ? std::stoul(argv[7]) : 0;
        if (!width || width > 255 || !min_repeats || min_repeats >= width)
            throw std::runtime_error("invalid width/repeat parameters");
        auto candidate = read_candidate(argv[1], shift, offset, length);
        auto target = read_sfub(argv[2]);
        auto scores = match(candidate, target, width, min_repeats);
        std::cout << "{\"candidate_blocks\":" << candidate.size()
                  << ",\"target_blocks\":" << target.size()
                  << ",\"shift\":" << shift << ",\"width\":" << width
                  << ",\"min_repeats\":" << min_repeats
                  << ",\"candidate_offset\":" << offset
                  << ",\"candidate_length\":" << length << ",\"scores\":[";
        for (std::size_t i = 0; i < scores.size(); ++i) {
            const auto &s = scores[i];
            if (i) std::cout << ',';
            std::cout << "{\"start\":" << s.start << ",\"votes\":" << s.votes
                      << ",\"matching_repeats\":" << s.matching_repeats
                      << ",\"mismatches\":" << s.mismatches
                      << ",\"candidate_repeats\":" << s.candidate_repeats
                      << ",\"exact\":" << (s.exact ? "true" : "false") << '}';
        }
        std::cout << "]}\n";
        return 0;
    } catch (const std::exception &error) {
        std::cerr << "error: " << error.what() << '\n';
        return 1;
    }
}
