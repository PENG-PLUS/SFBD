#ifndef ARC4_HPP
#define ARC4_HPP

#include <cstdint>
#include <string>

class ARC4
{
private:
    uint8_t sbox[256];
    size_t x, y;

public:
    explicit ARC4(const std::string &&key)
        : x(0), y(0)
    {
        for (size_t i = 0; i < 256; i++)
            sbox[i] = i;
        size_t j = 0;
        for (size_t i = 0; i < 256; i++)
        {
            j = (j + sbox[i] + key.data()[i % key.size()]) & 0xff;
            std::swap(sbox[i], sbox[j]);
        }
    }

    void encrypt(uint8_t *dst, const uint8_t *src, size_t len)
    {
        for (int i = 0; i < len; i++)
        {
            x = (x + 1) & 0xff;
            y = (y + sbox[x]) & 0xff;
            std::swap(sbox[x], sbox[y]);
            dst[i] = src[i] ^ sbox[(sbox[x] + sbox[y]) & 0xff];
        }
    }
};

#endif // ARC4_HPP
