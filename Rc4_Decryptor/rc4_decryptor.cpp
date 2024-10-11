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

class RC4 {
public:
    RC4(const std::string& key) {
        initialize(key);
    }

    void decrypt(unsigned char* data, size_t length) {
        for (size_t i = 0; i < length; ++i) {
            data[i] ^= getNextKeyByte();
        }
    }

private:
    unsigned char S[256];
    int i, j;

    void initialize(const std::string& key) {
        i = j = 0;
        for (int k = 0; k < 256; ++k) {
            S[k] = static_cast<unsigned char>(k);
        }

        int keyLength = key.size();
        int j = 0;
        for (int i = 0; i < 256; ++i) {
            j = (j + S[i] + key[i % keyLength]) % 256;
            std::swap(S[i], S[j]);
        }
    }

    unsigned char getNextKeyByte() {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        std::swap(S[i], S[j]);
        return S[(S[i] + S[j]) % 256];
    }
};

std::vector<unsigned char> readShellcodeFromFile(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file) {
        throw std::runtime_error("Could not open file!");
    }
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<unsigned char> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        throw std::runtime_error("Failed to read the file!");
    }

    return buffer;
}

void writeDecryptedShellcodeToFile(const std::string& filename, const std::vector<unsigned char>& shellcode) {
    std::ofstream file(filename, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Could not open file to write decrypted shellcode!");
    }
    file.write(reinterpret_cast<const char*>(shellcode.data()), shellcode.size());
}

int main() {
    try {
        std::string inputFilename = "encrypted_shellcode.bin";  // Replace with your input file name
        std::string outputFilename = "decrypted_shellcode.bin"; // Replace with your output file name
        std::string key = "my_secret_key";  // Replace with your decryption key

        // Read the encrypted shellcode from the file
        std::vector<unsigned char> shellcode = readShellcodeFromFile(inputFilename);

        // Decrypt the shellcode using RC4
        RC4 rc4(key);
        rc4.decrypt(shellcode.data(), shellcode.size());

        std::cout << "Shellcode decrypted successfully!" << std::endl;

        // Write the decrypted shellcode to a file
        writeDecryptedShellcodeToFile(outputFilename, shellcode);

        std::cout << "Decrypted shellcode saved to " << outputFilename << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
