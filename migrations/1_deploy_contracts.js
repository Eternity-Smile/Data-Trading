const DataTrading = artifacts.require("DataTrading");
const HashTimeLock = artifacts.require("HashTimeLock");
// const VerifierAgeId = artifacts.require("Verifier_age_id"); // 如果需要部署
// ...

module.exports = async function (deployer, network, accounts) {
    // Define V_t in seconds (e.g., 60 seconds)
    const verificationIntervalVt = 5;

    // ***** 修改: HashTimeLock 构造函数不再需要参数 *****
    await deployer.deploy(HashTimeLock);
    const htlcInstance = await HashTimeLock.deployed();
    console.log("HashTimeLock deployed at:", htlcInstance.address);
    // ***** 修改结束 *****

    // Deploy DataTrading, passing V_t
    await deployer.deploy(DataTrading, verificationIntervalVt);
    const dtInstance = await DataTrading.deployed();
    console.log("DataTrading deployed at:", dtInstance.address);

    // Optional: Link contracts if needed
    // await dtInstance.setHtlcContract(htlcInstance.address);
};
