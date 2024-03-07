#include <iostream>
#include <fstream>
#include <string>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <windows.h>
#include <cxxopts.hpp>
#include <random>
#include <filesystem>

void handleErrors() {
    DWORD errorCode = GetLastError();
    LPSTR errorMsg;
    FormatMessageA(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            nullptr,
            errorCode,
            0,
            (LPSTR) &errorMsg,
            0,
            nullptr
    );
    wprintf(L"Error code: %lu\n", errorCode);
    wprintf(L"Error message: %hs\n", errorMsg);

    LocalFree(errorMsg);
    abort();
}

bool is_directory(const std::string &path) {
    return std::filesystem::is_directory(path);
}

bool is_regular_file(const std::string &path) {
    return std::filesystem::is_regular_file(path);
}

bool has_file_extension(const std::filesystem::directory_entry &entry, const std::string &extension) {
    return entry.path().extension() == extension;
}

void generate_random_salt(unsigned char salt[], size_t size) {
    if (RAND_bytes(salt, size) != 1) {
        handleErrors();
    }
}

std::string generate_random_string(size_t size) {
    const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::string result;
    result.resize(size);

    // Use C++11 random library to generate random indices
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, sizeof(charset) - 2);

    for (size_t i = 0; i < size; ++i) {
        result[i] = charset[dis(gen)];
    }

    return result;
}

void encrypt_file(const std::string &inputFilePath, const std::string &outputFilePath, const std::string &password,
                  const unsigned char salt[], size_t saltSize) {
    // Generate a random IV (Initialization Vector)
    unsigned char iv[16];
    PKCS5_PBKDF2_HMAC_SHA1(password.c_str(), password.size(), salt, saltSize, 1000, sizeof(iv), iv);

    // Derive the encryption key from the password and salt
    unsigned char key[32]; // 256-bit key
    PKCS5_PBKDF2_HMAC_SHA1(password.c_str(), password.size(), salt, saltSize, 1000, sizeof(key), key);

    // Open input and output files
    std::ifstream inputFile(inputFilePath, std::ios::binary);
    std::ofstream outputFile(outputFilePath, std::ios::binary);

    // Initialize the AES context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv);

    // Encrypt the input file
    unsigned char buffer[1024];
    int bytesRead;
    while ((bytesRead = inputFile.read(reinterpret_cast<char *>(buffer), sizeof(buffer)).gcount()) > 0) {
        int outLen;
        EVP_EncryptUpdate(ctx, buffer, &outLen, buffer, bytesRead);
        outputFile.write(reinterpret_cast<const char *>(buffer), outLen);
    }

    // Finalize encryption
    int finalLen;
    EVP_EncryptFinal_ex(ctx, buffer, &finalLen);
    outputFile.write(reinterpret_cast<const char *>(buffer), finalLen);

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    inputFile.close();
    outputFile.close();

    std::cout << inputFilePath << " has been encrypted and stored in: " << outputFilePath << std::endl;
}

void decrypt_file(const std::string &inputFilePath, const std::string &outputFilePath, const std::string &password,
                  const unsigned char salt[], size_t saltSize) {
    // Generate a random IV (Initialization Vector)
    unsigned char iv[16];
    PKCS5_PBKDF2_HMAC_SHA1(password.c_str(), password.size(), salt, saltSize, 1000, sizeof(iv), iv);

    // Derive the decryption key from the password and salt
    unsigned char key[32]; // 256-bit key
    PKCS5_PBKDF2_HMAC_SHA1(password.c_str(), password.size(), salt, saltSize, 1000, sizeof(key), key);

    // Open input and output files
    std::ifstream inputFile(inputFilePath, std::ios::binary);
    std::ofstream outputFile(outputFilePath, std::ios::binary);

    // Initialize the AES context
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX_set_padding(ctx, EVP_PADDING_PKCS7);
    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, key, iv);

    // Decrypt the input file
    unsigned char buffer[1024];
    unsigned char decryptedBuffer[1024];
    int bytesRead;
    bool finalBlock = false;

    while (!finalBlock && (bytesRead = inputFile.read(reinterpret_cast<char *>(buffer), sizeof(buffer)).gcount()) > 0) {
        int outLen;
        EVP_DecryptUpdate(ctx, decryptedBuffer, &outLen, buffer, bytesRead);

        if (bytesRead < sizeof(buffer)) {
            finalBlock = true;
        }
        outputFile.write(reinterpret_cast<const char *>(decryptedBuffer), outLen);
    }

    // Finalize decryption
    int finalLen;
    EVP_DecryptFinal_ex(ctx, decryptedBuffer, &finalLen);
    outputFile.write(reinterpret_cast<const char *>(decryptedBuffer), finalLen);

    // Clean up
    EVP_CIPHER_CTX_free(ctx);
    inputFile.close();
    outputFile.close();

    std::cout << inputFilePath << " has been decrypted and stored in: " << outputFilePath << std::endl;
}

void encrypt_folder(const std::string &inputFolderPath, const std::string &outputFolderPath, const std::string &fileType,
               const std::string &password, const unsigned char salt[], size_t saltSize) {

    try {
        std::filesystem::path pathOutputFolder = outputFolderPath;
        // Iterate over files in the folder
        for (const auto &entry: std::filesystem::directory_iterator(inputFolderPath)) {
            // Check if the entry is a regular file and has the desired file extension
            if (is_regular_file(entry) && has_file_extension(entry, fileType)) {
                encrypt_file(entry.path().string(), (pathOutputFolder / entry.path().filename()).string(), password,salt, saltSize);
            }
        }

    } catch (const std::filesystem::filesystem_error &e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return;
    }
}

void decrypt_folder(const std::string &inputFolderPath, const std::string &outputFolderPath, const std::string &fileType,
               const std::string &password, const unsigned char salt[], size_t saltSize) {
    try {
        std::filesystem::path pathOutputFolder = outputFolderPath;
        // Iterate over files in the folder
        for (const auto &entry: std::filesystem::directory_iterator(inputFolderPath)) {
            // Check if the entry is a regular file and has the desired file extension
            if (is_regular_file(entry) && has_file_extension(entry, fileType)) {
                decrypt_file(entry.path().string(), (pathOutputFolder / entry.path().filename()).string(), password,salt, saltSize);
            }
        }

    } catch (const std::filesystem::filesystem_error &e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return;
    }
}


int main(int argc, char *argv[]) {
    std::string defaultFileType = ".txt";
    bool defaultRandomSalt = true;

    cxxopts::Options options{"PBKDF2Security", "A security tool to encrypt and decrypt file"};
    options.add_options()
            ("e,encrypt", "Encrypt a file or a folder", cxxopts::value<std::string>())
            ("d,decrypt", "Decrypt a file or a folder", cxxopts::value<std::string>())
            ("o,output", "Output filepath", cxxopts::value<std::string>())
            ("s,salt", "Salt value, max size: 16", cxxopts::value<std::string>())
            ("p,password", "Password", cxxopts::value<std::string>())
            ("r,random-salt",
             "Use random salt, if a salt is specified, random-salt will be set to false automatically",
             cxxopts::value<bool>()->default_value(std::to_string(defaultRandomSalt)))
            ("f,file-type", "File type to handle when input is a folder. The default type is .txt",
             cxxopts::value<std::string>()->default_value(defaultFileType));

    options.add_options("General")
            ("h,help", "Print help");

    auto result = options.parse(argc, argv);

    // Help
    if (result.count("help")) {
        std::cout << options.help() << std::endl;
        return 0;
    }

    // Check parameters
    std::string operation, inputPath, outputPath, password, saltString, fileType;
    unsigned char salt[16];
    size_t saltSize = sizeof(salt);
    bool useRandomSalt = false;
    bool isInputPathFolder = false;
    bool isOutputPathFolder = false;

    // Check necessary parameters
    if (result.count("encrypt")) {
        operation = "encrypt";
        inputPath = result["encrypt"].as<std::string>();
    } else if (result.count("decrypt")) {
        operation = "decrypt";
        inputPath = result["decrypt"].as<std::string>();
    }

    if (result.count("output")) {
        outputPath = result["output"].as<std::string>();
    }

    if (result.count("password")) {
        password = result["password"].as<std::string>();
    }

    if (operation.empty() || inputPath.empty() || outputPath.empty() || password.empty()) {
        std::cerr << "Usage: " << argv[0]
                  << " [--encrypt <inputPath> || --decrypt <inputPath>] --output <outputPath> --password <password> [--salt <salt>] [--random-salt]"
                  << std::endl;
        return 1;
    }

    // Check input path relevant parameters
    if (is_regular_file(inputPath)) {
        isInputPathFolder = false;
    } else if (is_directory(inputPath)) {
        isInputPathFolder = true;
    } else {
        std::cerr << "Invalid inputPath: " << inputPath << std::endl;
        return 1;
    }

    if (is_regular_file(outputPath)) {
        isOutputPathFolder = false;
    } else {
        std::filesystem::path outputFolderPath = outputPath;
        std::filesystem::create_directories(outputFolderPath);
    }

    if (is_directory(outputPath)) {
        isOutputPathFolder = true;
    } else {
        std::cerr << "Invalid outputPath: " << outputPath << std::endl;
        return 1;
    }

    if (isInputPathFolder != isOutputPathFolder) {
        std::cerr << "InputPath type doesn't match OutputPath type!!!" << std::endl;
        return 1;
    }

    fileType = result["file-type"].as<std::string>();

    // Check and init salt value
    useRandomSalt = result.count("random-salt") > 0;
    if (!useRandomSalt && result["salt"].count() == 0) {
        useRandomSalt = true;
    }
    if (useRandomSalt && result["salt"].count() != 0) {
        useRandomSalt = false;
    }

    if (useRandomSalt) {
        saltString = generate_random_string(saltSize);
        // Convert salt string to binary salt
        std::copy(saltString.begin(), saltString.end(), salt);
        std::cout << "Generated random salt: " << saltString << std::endl;
    }

    if (result.count("salt")) {
        saltString = result["salt"].as<std::string>();
        // Convert salt string to binary salt
        std::copy(saltString.begin(), saltString.end(), salt);
    }

    // Call functions
    if (operation == "encrypt") {
        if (isInputPathFolder) {
            encrypt_folder(inputPath, outputPath, fileType, password, salt, saltSize);
        } else {
            encrypt_file(inputPath, outputPath, password, salt, saltSize);
        }

    } else if (operation == "decrypt") {
        if (result["salt"].count() == 0) {
            std::cerr << "Decryption need a specified salt. Use '--salt <salt>'." << std::endl;
            return 1;
        }

        if (isInputPathFolder) {
            decrypt_folder(inputPath, outputPath, fileType, password, salt, saltSize);
        } else {
            decrypt_file(inputPath, outputPath, password, salt, saltSize);
        }

    } else {
        std::cerr << "Invalid operation. Use '--encrypt' or '--decrypt'." << std::endl;
        return 1;
    }

    return 0;
}

// Test
//int main(int argc, char* argv[]) {
//
//    const std::string inputfilepath = "input.txt";
//    const std::string outputfilepath = "encrypted.txt";
//    const std::string password = "fancyface";
//    const unsigned char salt[] = { "n(6n5n$HRJxxVfrG" };
//    size_t saltSize = sizeof(salt) - 1;
////
//    encrypt_file(inputfilepath, outputfilepath, password, salt, saltSize);
//
//    const std::string encryptedFilePath = "encrypted.txt";
//    const std::string decryptedFilePath = "decrypted.txt";
//
//    decrypt_file(encryptedFilePath, decryptedFilePath, password, salt, saltSize);
//
//    return 0;
//}
