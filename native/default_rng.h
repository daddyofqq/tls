// SPDX-License-Identifier: GPL-3.0-only
/*
 *  default_rng.h
 *
 *  Copyright (C) 2019 Daniel Hu <daddy.of.qq@gmail.com>
 */

#ifndef DEFAULT_RNG_H
#define DEFAULT_RNG_H
#include "mpi.h"
#include <random>

// this default random number generator is platform dependent and only intended for general testing
// user should create a secure and crypto grade generator (like something based on TRNG hardware)
// esp. if you are working with an embedded system
struct default_rng : public mpi_ns::randomizer {
    virtual void operator()(uint8_t* ptr, size_t size) const override
    {
        static std::random_device rd;
        static std::default_random_engine dre(rd());
        std::uniform_int_distribution<int> di(0, 255);
        while (size--) {
            *ptr++ = static_cast<uint8_t>(di(dre));
        }
    }
};

#endif
