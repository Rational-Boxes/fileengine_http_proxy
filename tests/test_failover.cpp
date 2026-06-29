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
