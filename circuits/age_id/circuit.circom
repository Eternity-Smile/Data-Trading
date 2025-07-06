pragma circom 2.0.0;



include "../../node_modules/circomlib/circuits/comparators.circom";

include "../../node_modules/circomlib/circuits/poseidon.circom"; // Assuming Poseidon for cm



// Circuit to prove age > 18 and knowledge of id and r for a commitment cm

// Simplified: We will prove knowledge of age, id_hash, r such that cm = Poseidon(age, id_hash, r)

// and age > 18.

template AgeIdCheck() {

    // Private inputs

    signal input age;

    signal input id_hash; // Hash of the actual ID

    signal input r;



    // Public inputs

    signal input cm; // Commitment: Poseidon(age, id_hash, r)

    // We don't use sid directly in the proof here based on simplification.

    // It can be included if needed for uniqueness checks tied to cm.



    // Constraint: Check age > 18 (assuming age is less than say 2^10 for practical circuit size)

    // 18 = 10010 in binary. Need to compare bit by bit or use range proof.

    // Using LessThan component for simplicity: 18 < age or age - 19 >= 0

    component isGreater = LessThan(10); // Check if age fits in 10 bits, adjust as needed

    isGreater.in[0] <== 18;

    isGreater.in[1] <== age;

    isGreater.out === 1; // Ensures age > 18 (as LT checks strictly less than)



    // Constraint: Check commitment cm == Poseidon(age, id_hash, r)

    component poseidon = Poseidon(3); // 3 inputs: age, id_hash, r

    poseidon.inputs[0] <== age;

    poseidon.inputs[1] <== id_hash;

    poseidon.inputs[2] <== r;

    cm === poseidon.out;



    // Constraint: Check id_hash validity (placeholder - cannot check external DB in circuit)

    // This part usually requires linking to some on-chain registry or similar,

    // or proving knowledge of a signature on the ID from a trusted source.

    // Simplified: We just prove knowledge of id_hash used in commitment.

}



component main {public [cm]} = AgeIdCheck();