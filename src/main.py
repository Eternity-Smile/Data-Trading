#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import time
import json
import random
import uuid
import logging
import subprocess
from decimal import Decimal, getcontext
import traceback
import argparse
import shutil
import sys
# Import components
try:
    from crypto_utils import CryptoUtils
    from web3_utils import Web3Utils
    from data_utils import DataUtils
    from seller import DataSeller
    from buyer import DataBuyer
    from issuer import Issuer
    from snarkjs_utils import verify_proof
except ImportError as e: print(f"[ERROR] Main: 导入模块时出错: {e}"); exit(1)

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)-7s] %(message)s')
getcontext().prec = 18

seller: DataSeller = None; buyer: DataBuyer = None; issuer: Issuer = None; web3_utils: Web3Utils = None

def press_enter_to_continue(prompt=">>> 按 Enter 键继续..."): input(prompt)
def confirm_action(prompt):
    while True:
        try:
            choice = input(f">>> {prompt} (y/n)? ").lower().strip()
            if choice == 'y': return True
            elif choice == 'n': return False
            logging.warning("无效输入，请输入 'y' 或 'n'.")
        except EOFError: logging.warning("输入流结束，默认选择 'n'."); return False

def setup_environment(skip_snark_setup=False):
    # ... (保持不变) ...
    logging.info("=== 正在设置环境 ===")
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../..'))
    root_data_dir = os.path.join(project_root, 'data')
    results_dir = os.path.join(project_root, 'results'); zk_setup_dir = os.path.join(project_root, 'zk_setup')
    os.makedirs(os.path.join(root_data_dir, 'seller'), exist_ok=True); os.makedirs(os.path.join(root_data_dir, 'buyer'), exist_ok=True)
    os.makedirs(os.path.join(root_data_dir, 'issuer'), exist_ok=True); os.makedirs(results_dir, exist_ok=True); os.makedirs(zk_setup_dir, exist_ok=True)
    logging.info("正在清理旧的运行数据 (./data)...")
    for entity in ['seller', 'buyer', 'issuer']:
        folder = os.path.join(root_data_dir, entity)
        if os.path.exists(folder):
            for item in os.listdir(folder):
                item_path = os.path.join(folder, item)
                try:
                    if os.path.isfile(item_path) or os.path.islink(item_path): os.unlink(item_path)
                    elif os.path.isdir(item_path):
                        if item.startswith('tx_') or item.startswith('credential_'):
                             if os.path.isdir(item_path): shutil.rmtree(item_path)
                             else: os.unlink(item_path)
                             logging.debug(f"Removed: {item_path}")
                except Exception as e: logging.warning(f'无法删除 {item_path}. 原因: {e}')
    if not skip_snark_setup:
        logging.info("检查/运行 ZK-SNARK 设置 (run_snark_setup.sh)...")
        setup_script_path = os.path.join(project_root, 'run_snark_setup.sh')
        if not os.path.exists(setup_script_path): logging.error(f"run_snark_setup.sh 未找到: {setup_script_path}"); return
        git_bash_executable = r'C:\Program Files\Git\bin\bash.exe' # !!! 确认路径 !!!
        if not os.path.exists(git_bash_executable): logging.error(f"Git Bash 无效: {git_bash_executable}"); exit(1)
        logging.info(f"使用 Git Bash: {git_bash_executable}")
        logging.info("脚本将检查 .ptau 文件并按需执行 circom / snarkjs setup。")
        try:
             process = subprocess.run( [git_bash_executable, setup_script_path], check=True, capture_output=True, text=True, encoding='utf-8', errors='ignore', cwd=project_root )
             logging.info("ZK-SNARK setup script STDOUT:\n" + (process.stdout or "[No stdout captured]"))
             if process.stderr: logging.warning("ZK-SNARK setup script STDERR:\n" + process.stderr)
             logging.info("ZK-SNARK setup 脚本执行成功完成 (Exit Code 0)。")
        except FileNotFoundError: logging.error(f"错误: 无法执行命令 '{git_bash_executable}' 或找不到脚本。"); exit(1)
        except subprocess.CalledProcessError as e: logging.error("ZK-SNARK setup 脚本执行失败!"); stdout_msg = e.stdout if e.stdout else "[No stdout/Decode Error]"; stderr_msg = e.stderr if e.stderr else "[No stderr/Decode Error]"; logging.error(f"Exit Code: {e.returncode}"); logging.error("Stdout:\n" + stdout_msg); logging.error("Stderr:\n" + stderr_msg); exit(1)
        except Exception as e: logging.error(f"运行 ZK setup 脚本时意外错误: {e}"); traceback.print_exc(); exit(1)
    else: logging.info("跳过 ZK-SNARK setup 脚本。")

def interactive_identity_registration(participant_name, participant_obj):
    # ... (保持不变) ...
    global issuer
    logging.info(f"\n--- {participant_name} 身份注册 ---"); max_retries = 3
    for attempt in range(max_retries):
        logging.info(f"Attempt {attempt + 1} of {max_retries}")
        identity_package = None
        try:
            age_input = input(f"请输入 {participant_name} 的年龄 (19-149): "); age = int(age_input)
            id_input = input(f"请输入 {participant_name} 的 ID (18位数字, 5001开头, 非00结尾): ")
            if participant_obj.set_identity(age, id_input):
                logging.info(f"{participant_name}: 基本格式有效，生成身份包 (pi_1)...")
                try:
                    identity_package = participant_obj.prepare_identity_package()
                    logging.info(f"{participant_name}: 身份包生成成功，提交 Issuer 验证 pi_1...")
                    verification_ok = issuer.verify_identity_package( identity_package['cm_pedersen'], identity_package['pi_vrf'], identity_package['vrf_output'], identity_package['hash_input'], identity_package['user_vrf_public_key'], identity_package['pi_1'], identity_package['public_signals_pi1'] )
                    if verification_ok:
                        logging.info(f"Issuer: {participant_name} 身份验证 (pi_1) 通过！开始凭证申请流程 (Alg 2 模拟)...")
                        try:
                            credential_request_ok = participant_obj.request_credential(issuer)
                            if credential_request_ok: logging.info(f"{participant_name}: 凭证申请流程成功！凭证已保存。"); return True
                            else: logging.error(f"{participant_name}: 凭证申请流程失败。")
                        except Exception as cred_e: logging.error(f"{participant_name}: 凭证申请流程中出错: {cred_e}"); traceback.print_exc()
                    else: logging.error(f"Issuer: {participant_name} 身份验证失败 (pi_1 或 VRF 验证未通过)。")
                except Exception as e: logging.error(f"{participant_name}: 生成身份包或 ZKP pi_1 时出错: {e}"); traceback.print_exc()
            else: logging.warning(f"{participant_name}: 输入的身份信息格式无效。")
        except ValueError: logging.warning("无效的年龄输入，请输入数字。")
        except KeyboardInterrupt: logging.info("用户中断注册。"); return False
        except Exception as e: logging.error(f"注册过程中发生意外错误: {e}"); traceback.print_exc()
        if attempt < max_retries - 1:
             if not confirm_action(f"{participant_name}: 注册/凭证流程失败，是否重试?"): return False
        else: logging.error(f"{participant_name}: 达到最大重试次数，注册失败。"); return False
    return False

def initialize_participants():
    global seller, buyer, issuer, web3_utils
    logging.info("=== 正在初始化参与者 ===")
    try:
        web3_utils = Web3Utils()
        accounts = web3_utils.get_accounts()
        if not accounts or len(accounts) < 2: logging.error("错误：需要至少 2 个 Ganache 账户。"); exit(1)
        seller_address = accounts[0]; buyer_address = accounts[1]
        logging.info(f"使用 Seller 地址: {seller_address}")
        logging.info(f"使用 Buyer 地址:  {buyer_address}")

        # Get private keys
        seller_pk = os.environ.get("SELLER_PRIVATE_KEY")
        buyer_pk = os.environ.get("BUYER_PRIVATE_KEY")

        if not seller_pk:
            print("\n--- 需要私钥 ---")
            # ***** 修改: 添加 .strip() *****
            seller_pk = input(f"输入 Seller ({seller_address}) 的私钥 (0x...): ").strip()
        if not buyer_pk:
            # ***** 修改: 添加 .strip() *****
            buyer_pk = input(f"输入 Buyer ({buyer_address}) 的私钥 (0x...): ").strip()
            print("----------------\n")

        # Validate keys before proceeding
        if not (seller_pk and seller_pk.startswith('0x') and len(seller_pk) == 66):
             # ***** 修改: 改进错误信息 *****
             logging.error(f"无效的 Seller 私钥格式。请确保以 0x 开头且总长度为 66。输入值: '{seller_pk}'")
             raise ValueError("无效的 Seller 私钥格式。")
             # ***** 修改结束 *****
        if not (buyer_pk and buyer_pk.startswith('0x') and len(buyer_pk) == 66):
             # ***** 修改: 改进错误信息 *****
             logging.error(f"无效的 Buyer 私钥格式。请确保以 0x 开头且总长度为 66。输入值: '{buyer_pk}'")
             raise ValueError("无效的 Buyer 私钥格式。")
             # ***** 修改结束 *****

        issuer = Issuer()
        seller = DataSeller(seller_address, seller_pk)
        buyer = DataBuyer(buyer_address, buyer_pk)
        logging.info("参与者初始化完成。")
    except ConnectionError as e: logging.error(f"无法连接到以太坊节点: {e}"); exit(1)
    # ***** 修改: 捕获 ValueError 并退出 *****
    except ValueError as e: logging.error(f"🚫 初始化参与者时出错: {e}"); exit(1) # 直接退出
    # ***** 修改结束 *****
    except Exception as e: logging.error(f"初始化参与者时出错: {e}"); traceback.print_exc(); exit(1)


# --- Main Workflow (修正了 L3 包构建逻辑) ---
# --- Main Workflow (修正了 L3 包构建逻辑 和 break 位置) ---
def run_interactive_workflow(dataset_name, dataset):
    global seller, buyer, issuer, web3_utils
    logging.info(f"\n=== 开始交互式工作流 ({dataset_name} 数据集) ===")
    tx_id = None; start_total_time = time.time()
    layer_aborted = False # 在循环外初始化，用于标记是否需要提前结束
    try:
        # === 阶段 0: 交互式身份注册与交易确认 ===
        if not interactive_identity_registration("Seller", seller): logging.error("Seller 注册未完成，中止。"); return
        if not interactive_identity_registration("Buyer", buyer): logging.error("Buyer 注册未完成，中止。"); return
        logging.info("\n--- 阶段 0c: 交易确认 ---")
        if not confirm_action("Seller: 是否同意发起数据交易?"): logging.info("Seller 不同意交易。"); return
        if not confirm_action("Buyer: 是否同意参与数据交易?"): logging.info("Buyer 不同意交易。"); return
        logging.info("双方同意交易，开始数据交易流程...")

        # === 阶段 1: 数据准备 & 交易初始化 ===
        logging.info("\n--- 阶段 1: 数据准备 & 交易初始化 ---")
        data_id = f"{dataset_name}_{uuid.uuid4().hex[:8]}"; price_per_layer = Decimal("0.01"); total_price_ether = price_per_layer * 3
        logging.info("Seller 添加数据到目录 (生成承诺/ZKP)..."); seller.add_data_to_catalog(data_id, dataset, f"{dataset_name} dataset", total_price_ether)
        logging.info("Seller 在链上创建交易..."); tx_id = seller.initiate_transaction(data_id, buyer.address)
        tx_id_bytes32 = seller.transactions[tx_id]['tx_id_bytes32']
        logging.info("\nBuyer 设置 HTLC 锁定时长 (相对于现在)..."); now_ts = int(time.time())
        duration1 = int(input(f"  L1 锁定时长 (秒, 推荐 > 120): ") or "300"); t1 = now_ts + duration1
        duration2 = int(input(f"  L2 锁定时长 (秒, 推荐 > {duration1+120}): ") or "600"); t2 = now_ts + duration2
        duration3 = int(input(f"  L3 锁定时长 (秒, 推荐 > {duration2+120}): ") or "900"); t3 = now_ts + duration3
        logging.info(f"  HTLC 到期时间戳: T1={t1}, T2={t2}, T3={t3}")
        logging.info("Seller 在链上设置 HTLC 参数 (H1-3, T1-3) 并注册层信息..."); htlc_hashes = seller.set_htlc_and_vts_params(tx_id, t1, t2, t3)
        logging.info("Buyer 确认交易参数..."); buyer.acknowledge_transaction(tx_id, tx_id_bytes32, data_id, seller.address, htlc_hashes, t1, t2, t3, total_price_ether)
        seller.update_balance(); buyer.update_balance()
        press_enter_to_continue("交易初始化完成，参数已设置。按 Enter 进行 L1 流程...")

        # === 阶段 2, 3, 4: 分层处理 ===
        for layer_index, layer_key in enumerate(['L1', 'L2', 'L3']):
            logging.info(f"\n--- 阶段 {layer_index + 2}: Layer {layer_key} ---")
            # 注意：layer_aborted 现在在循环外部定义，这里不再需要重复定义
            buyer_verified_offchain = False; seller_withdrawn = False
            # layer_aborted = False # <- 移除这行
            layer_package = None # 初始化 layer_package

            # 1. Buyer 锁款
            if not confirm_action(f"Buyer: 是否为 {layer_key} 锁定 {price_per_layer:.4f} ETH?"): logging.info(f"Buyer 跳过锁定 {layer_key}。中止。"); layer_aborted = True; # break # 不在这里 break，在循环末尾统一检查
            if layer_aborted: continue # 如果已中止，跳过本层剩余步骤

            logging.info(f"Buyer 正在为 {layer_key} 锁定资金..."); lock_id = buyer.lock_funds_for_layer(tx_id, layer_key)
            if not lock_id:
                logging.error(f"锁定 {layer_key} 资金失败。中止交易。")
                layer_aborted = True # 标记中止
                continue # 跳过本层剩余步骤

            # 将 Lock ID 保存到 Seller 状态中
            if tx_id in seller.transactions:
                 seller.transactions[tx_id].setdefault('htlc_locks', {})[layer_key] = lock_id
                 logging.info(f"Buyer 为 {layer_key} 锁定资金成功 (LockID: {lock_id.hex()[:10]}...). Seller 已记录 LockID。")
            else:
                 logging.warning(f"Seller 未找到 TxID {tx_id} 状态，无法记录 {layer_key} 的 LockID。")


            # 2. Seller 发送数据包
            if not confirm_action(f"Seller: Buyer 已锁定 {layer_key} 资金，是否发送 {layer_key} 数据包 (链下)?"): logging.info(f"Seller 选择不发送 {layer_key}。中止。"); layer_aborted = True; # break
            if layer_aborted: continue # 如果已中止，跳过本层剩余步骤

            logging.info(f"Seller 准备发送 {layer_key} 数据包...")
            # ***** L3 包裹构建逻辑修正 *****
            if layer_key == 'L3':
                # ... (L3 包裹构建代码，同上一版，保持不变) ...
                logging.info("Buyer: 提供 RSA 公钥给 Seller (用于 L3 加密)...")
                buyer_pub_key_str = buyer.rsa_public_key_str
                logging.info(f"Seller: 获取 {layer_key} 的元数据 (ZKP, VTS 等)...")
                l3_metadata_package = seller.deliver_layer_data(tx_id, layer_key)
                if not l3_metadata_package:
                    logging.error(f"无法获取 {layer_key} 的元数据包。中止。")
                    layer_aborted = True
                    continue
                logging.info(f"Seller: 使用 Buyer 公钥加密 {layer_key} 数据...")
                encrypted_l3_chunks = seller.re_encrypt_and_deliver_l3(tx_id, buyer_pub_key_str)
                if encrypted_l3_chunks is None:
                    logging.error(f"加密 {layer_key} 数据失败。中止。")
                    layer_aborted = True
                    continue
                logging.info(f"构建最终的 {layer_key} 包 (含加密数据和元数据)...")
                layer_package_for_buyer = l3_metadata_package.copy()
                layer_package_for_buyer['encrypted_data'] = encrypted_l3_chunks
                if 'data' in layer_package_for_buyer:
                    logging.debug("从发送给 Buyer 的 L3 包中移除原始 'data' 字段。")
                    del layer_package_for_buyer['data']
                layer_package = layer_package_for_buyer
            else: # L1 或 L2
                layer_package = seller.deliver_layer_data(tx_id, layer_key)
                if not layer_package:
                    logging.error(f"无法获取 {layer_key} 的数据包。中止。")
                    layer_aborted = True
                    continue
            # ***** L3 包裹构建逻辑修正结束 *****


            # ***** Seller 调用 signalDelivery *****
            logging.info(f"Seller: 在 DataTrading 合约上标记 {layer_key} 已发送 (signalDelivery)...")
            try:
                seller.web3.dt_signal_delivery(seller.address, seller.private_key, tx_id_bytes32, layer_index)
                logging.info(f"  {layer_key} 交付信号已发送。Buyer 现在有 V_t 时间进行验证。")
            except Exception as signal_e:
                logging.error(f"Seller 发送 {layer_key} 交付信号失败: {signal_e}")
                if not confirm_action("无法发送交付信号，是否仍要继续？(y=继续, n=中止)"): layer_aborted = True; # break
            if layer_aborted: continue # 如果已中止，跳过本层剩余步骤

            # 3. Buyer 链下验证
            logging.info(f"Buyer 收到 {layer_key} 包，准备进行链下验证...")
            if layer_package is None: # 再次检查，理论上不应发生
                logging.error(f"未能准备好 {layer_key} 的数据包，无法进行验证。中止。")
                layer_aborted = True
                continue

            if not confirm_action(f"Buyer: 是否进行 {layer_key} 数据包的链下验证 (ZKP, VTS)?"):
                logging.info(f"Buyer 跳过链下验证 {layer_key}。"); buyer_verified_offchain = False
                if confirm_action(f"Buyer: 跳过验证，是否中止交易并等待 {layer_key} 超时后尝试退款?"): logging.warning(f"交易中止，等待 {layer_key} HTLC 超时后 Buyer 可尝试退款。"); layer_aborted = True; # break
                else: logging.warning(f"Buyer 选择忽略 {layer_key} 验证，流程继续...")
            else:
                if layer_key == 'L3':
                    buyer_verified_offchain = buyer.decrypt_and_verify_l3(tx_id, layer_package)
                else:
                    buyer_verified_offchain = buyer.verify_layer_package_offchain(tx_id, layer_package)

                if not buyer_verified_offchain:
                    logging.error(f"{layer_key} 链下验证/处理失败。")
                    if confirm_action(f"Buyer: {layer_key} 验证/处理失败，是否中止交易并等待超时后尝试退款?"): logging.warning(f"交易中止，等待 {layer_key} HTLC 超时后 Buyer 可尝试退款。"); layer_aborted = True; # break
                    else: logging.warning(f"Buyer 选择忽略 {layer_key} 失败，流程继续...")
                else: logging.info(f"Buyer 完成 {layer_key} 包的链下验证/处理。等待 Seller 提款...")
            if layer_aborted: continue # 如果已中止，跳过本层剩余步骤

            # 4. Seller 提款尝试
            logging.info(f"Seller 准备尝试提取 {layer_key} 的 HTLC 资金...")
            logging.info(f"  (注意: 合约要求距离 signalDelivery 至少经过 V_t 秒，并且在 T{layer_index+1} 之前)")
            if confirm_action(f"Seller: 是否尝试提取 {layer_key} 的 HTLC 资金?"):
                seller_withdrawn = seller.handle_htlc_withdraw(tx_id, layer_key)
                if not seller_withdrawn: logging.warning(f"Seller 未能提取 {layer_key} 资金 (请检查是否满足 V_t 和 T{layer_index+1} 条件)。")
                else: logging.info(f"Seller 成功提取 {layer_key} 资金。")
            else: logging.info("Seller 跳过提取。")

            # 5. Buyer 链上确认
            if buyer_verified_offchain and seller_withdrawn:
                if confirm_action(f"Buyer: Seller 已提款且你已链下验证，是否在链上确认 {layer_key} 验证?"):
                    logging.info(f"Buyer 正在链上确认 {layer_key}...")
                    buyer_confirmed_onchain = buyer.confirm_verification_onchain(tx_id, layer_key)
                    if not buyer_confirmed_onchain: logging.warning(f"Buyer 未能成功在链上确认 {layer_key}。")
                    else: logging.info(f"Buyer 在链上确认 {layer_key} 成功。")
                    if layer_key == 'L3' and buyer_confirmed_onchain: logging.info("交易完成！")
                else: logging.info(f"Buyer 选择不在链上确认 {layer_key}。")
            elif buyer_verified_offchain and not seller_withdrawn: logging.warning(f"Buyer 已验证 {layer_key}，但 Seller 未提款/提款失败。无法进行链上确认。Buyer 可在超时后尝试退款。")
            elif not buyer_verified_offchain and seller_withdrawn: logging.warning(f"Seller 已提款 {layer_key}，但 Buyer 未验证通过/跳过验证。Buyer 无法确认。")
            else: # buyer_verified_offchain is False and seller_withdrawn is False (or Seller skipped withdraw)
                  # 修正日志信息
                  if seller_withdrawn: # Should not happen based on elif above, but for completeness
                      logging.warning(f"Seller 已提款 {layer_key}，但 Buyer 未验证通过/跳过验证。Buyer 无法确认。")
                  elif not buyer_verified_offchain:
                      logging.info(f"Buyer 未完成/跳过 {layer_key} 链下验证。Buyer 可在超时后尝试退款。")
                  else: # Should not happen
                      logging.info(f"未知状态，Buyer:{buyer_verified_offchain}, Seller:{seller_withdrawn}")


            seller.update_balance(); buyer.update_balance()

            # ***** 修正 break 的位置 *****
            # 在每次循环迭代结束前检查是否需要中止
            if layer_aborted:
                logging.warning(f"检测到 {layer_key} 流程中止，跳出循环。")
                break # <--- 正确位置：在 for 循环内部

            # 提示进入下一层或结束
            if layer_key != 'L3':
                 press_enter_to_continue(f"{layer_key} 流程结束。按 Enter 进行下一层...")
            # L3 结束后循环会自动结束，不需要这个 press_enter
            # elif layer_key == 'L3':
            #     press_enter_to_continue(f"{layer_key} 流程结束。按 Enter 查看最终结果...")
        # ----- for 循环结束 -----

        # 现在这个检查在循环外面是多余的，因为 break 已经在内部处理了
        # if layer_aborted: logging.warning("交易流程因用户选择或错误而中止。"); # break # 移除这里的 break

        logging.info("\n--- 交易流程结束 ---")
        final_data = buyer.get_final_data(tx_id)
        if final_data:
            highest_layer = 'N/A'
            # 修正 .get() 的使用方式，提供默认值
            if tx_id in buyer.transactions and buyer.transactions[tx_id].get('received_layers', set()):
                 # 使用集合推导式更安全
                 layers_num = {int(k[1]) for k in buyer.transactions[tx_id]['received_layers'] if len(k)>1 and k[1].isdigit()}
                 if layers_num: highest_layer = f"L{max(layers_num)}"
            logging.info(f"Buyer 已获得最终数据 (来自 {highest_layer}).")
            if isinstance(final_data, (list, dict)):
                try: final_data_str = json.dumps(final_data, indent=2, ensure_ascii=False); logging.info(f"Final Data Sample: {final_data_str[:1000]}...")
                except TypeError: logging.info(f"Final Data Sample (Non-serializable): {str(final_data)[:1000]}...")
            else: logging.info(f"Final Data Sample: {str(final_data)[:1000]}...")
        else: logging.info("Buyer 未能获得任何数据层。")

    except KeyboardInterrupt:
        logging.warning("\n用户中断了工作流。")
        if tx_id: logging.warning(f"当前交易 TxID: {tx_id}. 可能需要手动处理链上状态或 HTLC 退款。")
    except Exception as e:
        logging.error(f"\n!!! 工作流出错: {e} !!!")
        if tx_id and seller and buyer: logging.warning("考虑手动取消交易或处理HTLC退款。")
        logging.error("详细错误信息:", exc_info=True)
    finally:
        # 确保 seller 和 buyer 对象存在再调用 update_balance
        if 'seller' in globals() and seller: seller.update_balance()
        if 'buyer' in globals() and buyer: buyer.update_balance()
        end_total_time = time.time()
        total_duration = end_total_time - start_total_time
        logging.info(f"\n总工作流时间 ({dataset_name}): {total_duration:.4f} 秒")
# --- Entry Point ---
def main():
    # ... (保持不变) ...
    parser = argparse.ArgumentParser(description='交互式安全数据交易模拟 (使用 SnarkJS)')
    parser.add_argument('--skip-setup', action='store_true', help='跳过 ZK Setup 脚本执行检查')
    parser.add_argument('--dataset', choices=['small', 'medium', 'large'], default='small', help='数据集大小')
    args = parser.parse_args()
    data_utils = DataUtils(); logging.info(f"\n准备 '{args.dataset}' 数据集...")
    dataset_path = os.path.join('data', f'{args.dataset}_dataset.json')
    if not os.path.exists(dataset_path):
         logging.info(f"数据集文件 {dataset_path} 未找到。正在创建...")
         try:
             size_map = {'small': 10, 'medium': 100, 'large': 1000}
             if hasattr(data_utils, 'create_test_data') and callable(data_utils.create_test_data):
                 dataset = data_utils.create_test_data(size_kb=size_map[args.dataset], seed=random.randint(1, 10000))
                 data_utils.save_data(dataset, dataset_path); logging.info(f"数据集 '{args.dataset}' 已创建并保存。")
             else: logging.error("错误: DataUtils 类中缺少 create_test_data 方法。"); exit(1)
         except Exception as e: logging.error(f"创建或保存数据集时出错: {e}"); exit(1)
    else:
         try: dataset = data_utils.load_data(dataset_path); logging.info(f"数据集 '{args.dataset}' 加载成功.")
         except Exception as e: logging.error(f"加载数据集 {dataset_path} 时出错: {e}"); exit(1)
    setup_environment(skip_snark_setup=args.skip_setup)
    initialize_participants()
    run_interactive_workflow(args.dataset, dataset)
    logging.info("\n=== 模拟结束 ===")

if __name__ == "__main__":
    # ... (保持不变) ...
    import logging; from decimal import Decimal, getcontext; import time; import uuid; import json; import os; import argparse; import traceback; import subprocess; import shutil
    try: from crypto_utils import CryptoUtils; from web3_utils import Web3Utils; from data_utils import DataUtils; from seller import DataSeller; from buyer import DataBuyer; from issuer import Issuer; from snarkjs_utils import verify_proof
    except ImportError as e: print(f"[ERROR] Main: 导入模块时出错: {e}"); exit(1)
    main()

