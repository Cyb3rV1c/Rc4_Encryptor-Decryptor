/*
 * Author: Cyb3rV1c
 * Created: October 2024
 * Description: RC4 Encryptor
 * License: MIT License 
 *
 * This code was written by Cyb3rV1c and is a work in progress for cybersecurity
 * educational purposes.
 */


#include <iostream>
#include <fstream>
#include <vector>
#include <iomanip>

// RC4 Encryption/Decryption function
void RC4(unsigned char* data, size_t dataLen, unsigned char* key, size_t keyLen) {
    unsigned char S[256];
    unsigned char i = 0, j = 0;

    // KSA (Key-Scheduling Algorithm)
    for (int i = 0; i < 256; i++) {
        S[i] = i;
    }

    int k = 0;
    for (int i = 0; i < 256; i++) {
        k = (k + S[i] + key[i % keyLen]) % 256;
        std::swap(S[i], S[k]);
    }

    // PRGA (Pseudo-Random Generation Algorithm)
    i = j = 0;
    for (size_t n = 0; n < dataLen; n++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        std::swap(S[i], S[j]);
        unsigned char keyStreamByte = S[(S[i] + S[j]) % 256];
        data[n] ^= keyStreamByte;  // XOR the data with the key stream
    }
}

// Function to read binary file
std::vector<unsigned char> ReadFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Error opening file for reading.");
    }
    return std::vector<unsigned char>((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

// Function to write the encrypted shellcode as a C-style hex string
void WriteHexFile(const std::string& filename, const std::vector<unsigned char>& data) {
    std::ofstream file(filename);
    if (!file) {
        throw std::runtime_error("Error opening file for writing.");
    }

    // Write data in C-style hex format
    file << "[+] unsigned char encryptedShellcode[] = {";
    for (size_t i = 0; i < data.size(); ++i) {
        if (i % 16 == 0) file << "\n    ";  // Line break for readability
        file << "0x" << std::hex << std::setw(2) << std::setfill('0') << (int)data[i];
        if (i != data.size() - 1) file << ", ";
    }
    file << "\n};\n";
}

int main() {
    try {
        // Input and output filenames
        std::string inputFilename = "";     // Replace with your shellcode file
        std::string outputFilename = "";    // Replace with your output desired name & path

        // RC4 encryption key (example key, replace with your actual key)
        unsigned char rc4Key[] = { 0x01, 0x02, 0x03, 0x04 }; // Example key
        size_t keyLen = sizeof(rc4Key);

        // Read the shellcode from the input file
        std::vector<unsigned char> shellcode = ReadFile(inputFilename);

        // Encrypt the shellcode using RC4
        RC4(shellcode.data(), shellcode.size(), rc4Key, keyLen);

        // Write the encrypted shellcode to a header file in C-style hex format
        WriteHexFile(outputFilename, shellcode);

        std::cout << "Shellcode encrypted successfully and saved to " << outputFilename << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
