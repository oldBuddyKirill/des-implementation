#include <iostream>

#include "utils.h"

int main()
{
    // Пример использования
    std::string plainText = "ABCDabcd";
    std::string keyStr = "1234!@#$";

    // Преобразуем входные данные в битовые последовательности
    std::bitset<64> plainBlock = utils::strToBitset(plainText);
    std::bitset<64> key = utils::strToBitset(keyStr);

    // Генерируем раундовые ключи
    std::vector<std::bitset<48>> roundKeys = utils::generateKeys(key);

    // Шифрование
    std::bitset<64> encryptedBlock = utils::desEncrypt(plainBlock, roundKeys);

    // Дешифрование
    std::bitset<64> decryptedBlock = utils::desDecrypt(encryptedBlock, roundKeys);

    // Вывод результатов
    std::cout << "Plaintext:        " << plainText << std::endl;
    std::cout << "Key:              " << keyStr << std::endl;
    std::cout << "Encrypted text:   " << utils::bitsetToStr(encryptedBlock) << std::endl;
    std::cout << "Decrypted:        " << utils::bitsetToStr(decryptedBlock) << std::endl;

    return 0;
}
