# 🛡️ GoBfuscator - Advanced Go Code Obfuscation Tool

![Go Version](https://img.shields.io/badge/go-%3E%3D1.18-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![GitHub Stars](https://img.shields.io/github/stars/luftwaffe66/GoBfuscator)
![GitHub Forks](https://img.shields.io/github/forks/luftwaffe66/GoBfuscator)

## 🔍 Overview

GoBfuscator is a professional-grade obfuscation tool specifically designed for Go (Golang) source code. It provides multiple layers of protection to make reverse engineering difficult while maintaining 100% runtime functionality.

**Key Features:**
- ✨ AES-256 encrypted strings with runtime decryption
- 🔀 Comprehensive identifier renaming (functions, variables, types)
- 🧹 Code cleanup and comment removal
- 🛡️ Protection against common reverse engineering techniques
- ⚡ Zero runtime performance overhead after initial decryption

## 🚀 Quick Start

### Installation

```bash
git clone https://github.com/luftwaffe66/GoBfuscator.git
cd GoBfuscator
pip install -r requirements.txt
```

### Basic Usage

```bash
python3 obfuscator.py yourfile.go
```

This will generate `yourfile_obfuscated.go` with all protections applied.

## 🛠️ Technical Implementation

### Multi-Layer Obfuscation

1. **Identifier Renaming**:
   - All non-reserved identifiers are replaced with random 6-character names
   - Preserves Go reserved words and standard library imports
   - Handles method receivers and package-level declarations

2. **String Encryption**:
   - Uses AES-256-CBC with random IV for each string
   - Base64 encoded for embedding in source
   - Runtime decryption with automatic PKCS7 padding removal

3. **Code Cleanup**:
   - Removal of all comments
   - Compression of whitespace
   - Normalization of formatting

### Security Features

- 🔑 Unique encryption key generated per run
- 🛡️ Protection against simple string extraction tools
- 🔄 Randomized naming prevents pattern recognition
- ⚠️ Preserves important escape sequences (\n, \t, etc.)

## 📊 Benchmark Results

| Operation         | Original | Obfuscated | Overhead |
|------------------|----------|------------|----------|
| Startup Time     | 12ms     | 15ms       | +25%     |
| Memory Usage     | 8.2MB    | 8.5MB      | +3.6%    |
| Runtime Performance | 1.0x  | 1.0x       | 0%       |

*Tests performed on Go 1.19, Intel i7-1185G7, 16GB RAM*

## 🧩 Integration

### CI/CD Pipeline

```yaml
steps:
  - name: Obfuscate Go Code
    run: |
      git clone https://github.com/luftwaffe66/GoBfuscator.git
      cd GoBfuscator
      python3 obfuscator.py $GITHUB_WORKSPACE/main.go
      mv main_obfuscated.go $GITHUB_WORKSPACE/main.go
```

### Advanced Options

```bash
# Preserve specific identifiers
python3 obfuscator.py --preserve "Config,DBConn" main.go

# Custom encryption key (base64)
python3 obfuscator.py --key "dGhpcyBpcyBhIHNlY3JldCBrZXkh" main.go
```

## 📚 Documentation

### How It Works

1. **Parsing Phase**:
   - Extracts all renameable identifiers
   - Identifies strings for encryption
   - Preserves code structure

2. **Transformation Phase**:
   - Generates random names for identifiers
   - Encrypts strings with AES-256
   - Builds decryption infrastructure

3. **Output Phase**:
   - Generates clean, functional Go code
   - Adds required decryption functions
   - Maintains original functionality

### Limitations

- ❌ Doesn't handle reflection-based code analysis
- ❌ Can't obfuscate exported package names
- ❌ May break some debugger functionality

## 🤝 Contributing

We welcome contributions! Please follow these steps:

1. Fork the repository  
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)  
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)  
4. Push to the branch (`git push origin feature/AmazingFeature`)  
5. Open a Pull Request  

## 📜 License

Distributed under the MIT License. See `LICENSE` for more information.

## 📬 Contact

Project Maintainer - [@luftwaffe66](https://github.com/luftwaffe66)

## 🌟 Acknowledgments

- Inspired by various open-source obfuscation tools  
- Uses PyCryptodome for AES implementation  
- Thanks to all contributors and users

---

**🔐 Protect Your Go Code Today!** [Star this repo](https://github.com/luftwaffe66/GoBfuscator) to support the project.
