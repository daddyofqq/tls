// SPDX-License-Identifier: GPL-3.0-only
/*
 *  secure_allocator.h
 *
 *  Copyright (C) 2019 Daniel Hu <daddy.of.qq@gmail.com>
 */

#ifndef SECURE_ALLOC_H
#define SECURE_ALLOC_H

#include <cstring>
#include <memory>
#include <string>
#include <vector>

// for now the only purpose of secure allocator is to clear senstive data
// from memory during deallocation in a hostile environment
//
// It is not necessary for a tamper-proof environment
// so define or undef USE_SECURE_ALLOCATOR to suit your own need
//
// Migrating the code into a custom allocator also allows flexiblity in
// design depending on the target memory model
//
#ifdef USE_SECURE_ALLOCATOR

template <typename T>
class default_secure_allocator : public std::allocator<T>
{
public:
    typedef size_t size_type;
    typedef T* pointer;
    typedef const T* const_pointer;

    template <typename U>
    struct rebind {
        typedef default_secure_allocator<U> other;
    };

    pointer allocate(size_type n, const void* hint = 0)
    {
        return std::allocator<T>::allocate(n, hint);
    }

    void deallocate(pointer p, size_type n)
    {
        if constexpr (std::is_trivial_v<T>) {
            std::memset(p, 0, n * sizeof(T));
        }
        return std::allocator<T>::deallocate(p, n);
    }

    default_secure_allocator() throw() : std::allocator<T>(){};
    default_secure_allocator(const default_secure_allocator& a) throw() : std::allocator<T>(a) {}
    template <typename U>
    default_secure_allocator(const default_secure_allocator<U>& a) throw() : std::allocator<T>(a) {}
    ~default_secure_allocator() throw() {}
};

class secure_vector : public std::vector<uint8_t, default_secure_allocator<uint8_t>>
{
public:
    using base = std::vector<uint8_t, default_secure_allocator<uint8_t>>;
    using base::base;

    secure_vector(std::vector<uint8_t> const& v) : base{}
    {
        for (auto x : v) {
            this->resize(v.size());
            std::copy(v.begin(), v.end(), this->begin());
        }
    }

    secure_vector& operator=(std::vector<uint8_t> const& v)
    {
        this->resize(v.size());
        std::copy(v.begin(), v.end(), this->begin());
        return *this;
    }
};

using secure_string = std::basic_string<char, std::char_traits<char>, default_secure_allocator<char>>;

namespace std
{
template <>
struct hash<secure_string> {
    size_t operator()(const secure_string& k) const
    {
        size_t h = 5381;
        for (auto& x : k) {
            h = 33 * h ^ static_cast<unsigned char>(x);
        }
        return h;
    }
};
}; // namespace std

#else

using secure_vector = std::vector<uint8_t>;
using secure_string = std::string;
template <typename T>
using default_secure_allocator = std::allocator<T>;

#endif

#endif
