pragma circom 2.1.6;

template Pythagorean() {
    signal input a;
    signal input b;
    signal input c;

    signal a2;
    signal b2;
    signal c2;

    a2 <== a * a;
    b2 <== b * b;
    c2 <== c * c;

    c2 === a2 + b2;
}

component main = Pythagorean();
