# PathTraversalTool
Bray Traversal Automator
Overview
The Bray Traversal Automator is a C++ tool designed for penetration testing professionals to identify path traversal vulnerabilities in web applications. It automates the process of fuzzing payloads, supports multiple encoding methods, and includes AI-enhanced features for payload prioritization and adaptation based on detected operating systems and servers. This tool is an improved version of a Python-based path traversal tester, rewritten in C++ for better performance, efficiency, and concurrency.

Key Features:

Multithreaded and asynchronous HTTP requests for faster scanning.
OS and server detection to prioritize payloads intelligently.
Support for various encoding methods (e.g., URL encoding, Unicode, Base64).
Adaptive payload mutation when a successful vulnerability is detected.
Stealth mode to reduce detection by adding random delays.
Command-line interface with customizable options.
Logging and output saving for easy result analysis.
This tool is intended for authorized penetration testing only. Ensure you have explicit permission before use.

Prerequisites
Before compiling and running the tool, ensure you have the following dependencies installed. These libraries are required for handling HTTP requests, argument parsing, logging, and progress bars.

Dependencies
C++ Compiler: Use a C++14-compatible compiler such as g++ (part of GCC).
libcurl: For asynchronous HTTP requests. Install it using your package manager:
On Ubuntu/Debian: sudo apt install libcurl4-openssl-dev
On Fedora: sudo dnf install libcurl-devel
On macOS (using Homebrew): brew install curl
On Windows: Use MSYS2 or install via Chocolatey (choco install curl).
cxxopts: A header-only library for command-line argument parsing. Download it from GitHub and include the header in your project.
Installation: Clone the repository and copy cxxopts.hpp to your include directory, or use CMake to build it.
spdlog: A fast C++ logging library. Install it via your package manager or build from source.
On Ubuntu/Debian: sudo apt install libspdlog-dev
On Fedora: sudo dnf install spdlog-devel
On macOS: brew install spdlog
On Windows: Build from source or use vcpkg.
Alternatively, you can replace it with standard C++ logging if you modify the code.
progressbar: A simple progress bar library for C++. You can use cpp-progressbar or a similar alternative.
Installation: Clone the repository and include the header, or install via package manager if available.
Other Requirements:
make or a build system (optional but recommended for automation).
C++ standard library (usually included with your compiler).
Installation and Compilation
Follow these steps to compile the Bray Traversal Automator from source.

Step 1: Clone the Repository
Clone this repository to your local machine:


Copy
git clone https://github.com/your-username/bray-traversal-automata.git
cd bray-traversal-automata
Step 2: Install Dependencies
Ensure all dependencies are installed as per the "Prerequisites" section above. If you're using a package manager, install them system-wide.

Step 3: Compile the Code
The code is provided in bray_traversal.cpp. Use the following command to compile it:


Copy
g++ -std=c++14 -o bray_traversal bray_traversal.cpp -lcurl -lpthread -lspdlog -I/path/to/cxxopts/include -I/path/to/progressbar/include
Explanation of Flags:
-std=c++14: Ensures C++14 standard is used (required for some features).
-o bray_traversal: Outputs the executable as bray_traversal.
-lcurl: Links the libcurl library.
-lpthread: Links the POSIX threads library for multithreading.
-lspdlog: Links the spdlog library.
-I/path/to/cxxopts/include: Specify the include path for cxxopts. Replace /path/to/ with the actual directory where cxxopts.hpp is located (e.g., -I./include if you have a local include folder).
-I/path/to/progressbar/include: Specify the include path for the progressbar library.
Tips for Compilation:

If you encounter linking errors, ensure all libraries are installed and their development headers are available.
On Windows, you may need to use MinGW or MSYS2 for compilation. Adjust the command accordingly (e.g., add -lws2_32 for Winsock).
For easier builds, create a Makefile in your repository root with the following content:

Copy
CXX = g++
CXXFLAGS = -std=c++14
LDLIBS = -lcurl -lpthread -lspdlog
INCLUDES = -I/path/to/cxxopts/include -I/path/to/progressbar/include

all:
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o bray_traversal bray_traversal.cpp $(LDLIBS)

clean:
	rm -f bray_traversal
Then, compile with make.
Step 4: Verify the Build
After compilation, you should have an executable named bray_traversal. Run it with the --help flag to verify:


Copy
./bray_traversal --help
This should display the available command-line options.

Usage
The tool is run from the command line. It requires a target URL and supports various options for customization.

Basic Usage

Copy
./bray_traversal --url <target_url>
Example: ./bray_traversal --url http://example.com
Command-Line Options
Use the --help flag for a full list, but here's a summary:

--url or -u: Required. The base URL to test (e.g., http://example.com).
--threads or -T: Number of threads for concurrent requests (default: 10).
--payloads or -p: File containing payloads to test (default: payloads.txt).
--user-agents or -a: File containing user agents (default: user_agents.txt).
--depth or -d: Traversal depth for recursive testing (default: 10).
--success-criteria or -sc: Space-separated list of success criteria (e.g., --success-criteria "root:" "Administrator").
--encoding or -e: Space-separated list of encoding methods (default: includes URL, Unicode, etc.).
--stealth or -s: Enable stealth mode to add random delays (default: false).
--verbose or -v: Enable detailed logging (default: false).
--output or -o: File to save results (e.g., --output results.txt).
--request-type or -r: HTTP method (GET or POST, default: GET).
Examples
Basic Scan with Default Settings:


Copy
./bray_traversal --url http://example.com --output scan_results.txt
This performs a standard path traversal test and saves the results to scan_results.txt.

Scan with Stealth and Verbose Logging:


Copy
./bray_traversal --url http://example.com --stealth --verbose --threads 5
Adds random delays to avoid detection and provides detailed logs.

Custom Payloads and Success Criteria:


Copy
./bray_traversal --url http://example.com --payloads custom_payloads.txt --success-criteria "uid=" "password"
Uses a custom payload file and checks for specific success strings.

Payload and User Agent Files
Payloads File: A text file with one payload per line (e.g., ../, ....//, etc.). Default is payloads.txt.
User Agents File: A text file with one user agent string per line (e.g., Mozilla/5.0...). Default is user_agents.txt.
Features and Enhancements
AI-Prioritized Payloads: Automatically detects the target OS and server, then prioritizes payloads for efficiency.
Adaptive Mutation: If a payload succeeds, the tool generates and tests mutations using various encoding methods.
Performance Optimizations: Uses multithreading and libcurl's multi-interface for fast, non-blocking HTTP requests.
Cross-Platform Support: Works on Linux, macOS, and Windows with minimal adjustments.
Contributing
Contributions are welcome! If you'd like to improve the code, add features, or fix bugs, please:

Fork the repository.
Create a new branch for your feature.
Submit a pull request with a description of your changes.
License
This project is licensed under the MIT License - see the LICENSE file for details. (Note: If you haven't created a LICENSE file, add one to your repository.)

Contact
For questions or issues, open an issue on GitHub or contact the maintainer. Remember, this tool is for educational and authorized testing purposes only.
