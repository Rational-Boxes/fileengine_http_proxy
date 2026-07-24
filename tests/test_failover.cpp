// Copyright (C) 2026 James Hickman
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

// Unit test for the failover CircuitBreaker (REPLICATION_FAILOVER.md).
// Build: g++ -std=c++17 -I include tests/test_failover.cpp -o failover_tests
#include "circuit_breaker.h"
#include <cassert>
#include <cstdio>

using webdav::CircuitBreaker;

int main() {
    double t = 0.0;
    CircuitBreaker b(10.0);
    b.setClock([&] { return t; });

    // healthy
    assert(b.shouldTryPrimary() && !b.isDegraded());

    b.trip();                                   // primary down for the cooldown
    assert(b.isDegraded() && !b.shouldTryPrimary());

    t = 9.9;                                    // still within cooldown
    assert(b.isDegraded());
    t = 10.0;                                   // cooldown elapsed -> re-probe
    assert(b.shouldTryPrimary() && !b.isDegraded());

    b.trip();
    b.reset();                                  // explicit recovery
    assert(b.shouldTryPrimary() && !b.isDegraded());

    std::puts("circuit_breaker: OK");
    return 0;
}
