#pragma once

#include <bitset>
#include <string>
#include <vector>

#include "tables.h"

namespace utils {

std::bitset<64> strToBitset(const std::string &str)
{
    std::bitset<64> bits;
    for (int i = 0; i < 8; ++i) {
        char c = i < str.size() ? str[i] : 0;
        // Записываем в битсет символ по битам
        for (int j = 0; j < 8; ++j)
            bits[i * 8 + j] = (c >> (7 - j)) & 1;
    }
    return bits;
}

std::string bitsetToStr(const std::bitset<64> bits)
{
    std::string res;
    for (int i = 0; i < 8; ++i) {
        char c = 0;
        for (int j = 0; j < 8; ++j)
            c |= bits[i * 8 + j] << (7 - j);
        res += c;
    }
    return res;
}

// Выполнение перестановки
template<size_t Nout, size_t Nin>
constexpr std::bitset<Nout> permute(const std::bitset<Nin> data, const std::array<int, Nout> table)
{
    std::bitset<Nout> result;
    for (int i = 0; i < table.size(); ++i)
        result[i] = data[table[i] - 1]; // не забываем, что индексы в таблицах начинаются с 1
    return result;
}

// Циклический сдвиг влево
constexpr std::bitset<28> leftShift(const std::bitset<28> key, int shift) {
    return (key << shift) | (key >> (key.size() - shift));
    // Проблемы в варианте выше возникнут, если shift будет больше key.size(),
    // но в DES циклический сдвиг выполняется только на 1-2 бита
    //std::bitset<28> result;
    //for (int i = 0; i < 28; ++i) {
    //    result[i] = key[(i + shift) % 28];
    //}
    //return result;
}

// Генерация раундовых ключей
std::vector<std::bitset<48>> generateKeys(const std::bitset<64> key)
{
    std::vector<std::bitset<48>> res;

    // Применяем IKP к ключу (первоначальная перестановка)
    std::bitset<56> pc1Key = permute(key, tables::IKP);

    // Разделяем на две половины
    std::bitset<28> left, right;
    for (int i = 0; i < 28; ++i) {
        left[i] = pc1Key[i];
        right[i] = pc1Key[i + 28];
    }

    // Генерируем 16 раундовых ключей
    for (int i = 0; i < 16; ++i) {
        // Сдвигаем обе половины
        left = leftShift(left, tables::SHIFTS[i]);
        right = leftShift(right, tables::SHIFTS[i]);

        // Объединяем и применяем RKP
        std::bitset<56> combined;
        for (int j = 0; j < 28; ++j) {
            combined[j] = left[j];
            combined[j + 28] = right[j];
        }

        std::bitset<48> roundKey = permute(combined, tables::RKP);
        res.emplace_back(roundKey);
    }

    return res;
}

// Функция Фейстеля
std::bitset<32> feistel(const std::bitset<32> right, const std::bitset<48> roundKey)
{
    // Расширяем правую половину с помощью E-таблицы
    std::bitset<48> expanded = permute(right, tables::E);

    // XOR с раундовым ключом
    expanded ^= roundKey;

    // Применяем S-блоки
    std::bitset<32> substituted;
    for (int i = 0; i < 8; ++i) {
        // Получаем 6 бит для текущего S-блока

        // Определение номера строки по крайним битам 6-битной группы
        // Например, для группы бит 1_0101_0: row = (1 * 2) + 0 = 2 (строка в S-блоке).
        int row = (expanded[i * 6] << 1)
            + (expanded[i * 6 + 5] << 0);
        // Определяется номера столбца по средним 4 битам
        // Например, для 1_0101_0: col = (0 * 8) + (1 * 4) + (0 * 2) + (1 * 1) = 5 (столбец в S-блоке)
        int col = (expanded[i * 6 + 1] << 3)
            + (expanded[i * 6 + 2] << 2)
            + (expanded[i * 6 + 3] << 1)
            + (expanded[i * 6 + 4] << 0);

        // Получаем значение из S-блока
        int val = tables::S[i][row][col];

        // Записываем 4 бита результата
        for (int j = 0; j < 4; ++j)
            substituted[i * 4 + j] = (val >> (3 - j)) & 1;
    }

    // Применяем P-перестановку
    std::bitset<32> result = permute(substituted, tables::P);

    return result;
}

// Основная функция шифрования DES
std::bitset<64> desEncrypt(const std::bitset<64> block, const std::vector<std::bitset<48>> &roundKeys)
{
    // Начальная перестановка
    std::bitset<64> permuted = permute(block, tables::IP);

    // Разделяем на левую и правую половины
    std::bitset<32> left, right;
    for (int i = 0; i < 32; ++i) {
        left[i] = permuted[i];
        right[i] = permuted[i + 32];
    }

    // 16 раундов сети Фейстеля
    for (int i = 0; i < 16; ++i) {
        std::bitset<32> newLeft = right;
        std::bitset<32> feistelOut = feistel(right, roundKeys[i]);
        std::bitset<32> newRight = left ^ feistelOut;

        left = newLeft;
        right = newRight;
    }

    // Объединяем правую и левую половины
    std::bitset<64> combined;
    for (int i = 0; i < 32; ++i) {
        combined[i] = right[i];
        combined[i + 32] = left[i];
    }

    // Финальная перестановка
    std::bitset<64> encryptedBlock = permute(combined, tables::FP);

    return encryptedBlock;
}

// Функция дешифрования DES (аналогична шифрованию, но ключи в обратном порядке)
std::bitset<64> desDecrypt(const std::bitset<64> block, const std::vector<std::bitset<48>> &roundKeys)
{
    std::vector<std::bitset<48>> reversedKeys(roundKeys.rbegin(), roundKeys.rend());
    return desEncrypt(block, reversedKeys);
}

}
