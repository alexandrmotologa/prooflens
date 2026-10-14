pragma circom 2.1.6;

// VULNERABLE CIRCUIT EXAMPLE: Under-constrained signal & dead variable
template DivChecker() {
    signal input denom;
    signal input num;
    signal output out;

    signal ratio;
    signal dead_weight;

    // ratio <-- num / denom
    // Missing check: out === ratio
    denom * ratio === num;
}

component main = DivChecker();
