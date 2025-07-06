pragma circom 2.0.0;

include "../../node_modules/circomlib/circuits/poseidon.circom";

// Template: 证明你知道 layer_hash 和 R，使得 C = Poseidon(layer_hash, R)
// 这个模板会同时用于 Layer 1, Layer 2, Layer 3 （在各自的文件中）
template LayerKnowledge(n_inputs) {
    // 私密输入
    signal input layer_hash; // 对应层 Li 的哈希值 (通常是一个field或bits数组)
    signal input R;          // 对应层的随机数 Ri (通常是一个field)

    // 公开输入
    signal input C;          // 对应层的承诺 Ci = Poseidon(layer_hash, R) (通常是一个field)

    // 如果需要 F() 来源证明 或 M() 一致性证明，可以在这里添加其他公开输入
    // 例如: signal input D_hash; // 原始数据 D 的哈希
    // 例如: signal input prev_C; // 上一层承诺 C(i-1) （如果采用承诺链）

    // 约束: 检查承诺 C == Poseidon(layer_hash, R)
    // 假设不采用承诺链，基础情况是 2 个输入
    component poseidon = Poseidon(n_inputs);
    poseidon.inputs[0] <== layer_hash;
    poseidon.inputs[1] <== R;

    // 如果需要 F() 或 M() 检查，在这里添加相应的约束电路
    // 这部分因逻辑复杂，在此简化实现中省略

    // 最终约束：计算出的 Poseidon 哈希必须等于公开的承诺 C
    C === poseidon.out;
}


// 实例化主组件 (Main Component Instantiation)
// 对于 Layer 3 (以及 Layer 1, Layer 2)，假设不采用承诺链 C_i = Poseidon(L_i_hash, R_i)
// 因此 Poseidon 有 2 个输入 (L_i_hash, R_i)
// 公开输入只有承诺 C
// *** 确保这一行没有被 // 注释掉 ***
component main {public [C]} = LayerKnowledge(2);