# backend/src/data_utils.py
import json
import random
import string
# pandas 和 numpy 在这个版本里不是必需的
# import pandas as pd
# import numpy as np
from datetime import datetime, timedelta
import os
import logging # 添加 logging

class DataUtils:

    @staticmethod
    def create_test_data(size_kb, data_type='structured', seed=None):
        """
        创建指定大小的测试数据。
        对于 structured 类型，返回一个包含字典的列表 (list of dicts)。
        对于 unstructured 类型，返回一个字符串 (str)。
        """
        logging.info(f"Creating test data: size={size_kb}KB, type={data_type}, seed={seed}")
        if seed is not None:
            random.seed(seed)
            # np.random.seed(seed) # 如果后续添加 numpy 依赖

        target_bytes = size_kb * 1024
        data = []

        if data_type == 'structured':
            # 估算一个包含1000字符'extra_data'的记录大约 1.5KB
            estimated_record_size_bytes = 1500
            num_records = max(1, int(target_bytes / estimated_record_size_bytes))
            logging.debug(f"Target bytes: {target_bytes}, Estimated records: {num_records}")

            for i in range(num_records):
                record = {
                    'id': i,
                    'name': ''.join(random.choices(string.ascii_letters, k=10)),
                    'age': random.randint(18, 80),
                    'email': ''.join(random.choices(string.ascii_lowercase, k=8)) + '@example.com',
                    'address': ''.join(random.choices(string.ascii_letters + ' ', k=50)),
                    'phone': ''.join(random.choices(string.digits, k=10)),
                    'registration_date': (datetime.now() - timedelta(days=random.randint(1, 1000))).isoformat(),
                    'preferences': {
                        'color': random.choice(['red', 'blue', 'green', 'yellow', 'purple']),
                        'food': random.choice(['pizza', 'burger', 'sushi', 'pasta', 'salad']),
                        'activity': random.choice(['reading', 'sports', 'music', 'movies', 'travel'])
                    },
                    'credit_score': random.randint(300, 850),
                    'income': random.randint(30000, 200000),
                    'education': random.choice(['High School', 'Bachelor', 'Master', 'PhD']),
                    'occupation': random.choice(['Engineer', 'Doctor', 'Teacher', 'Artist', 'Scientist']),
                    'extra_data': ''.join(random.choices(string.ascii_letters + string.digits, k=1000)) # 固定长度
                }
                data.append(record)
            final_size_info = DataUtils.analyze_data_size(data) # 计算实际大小
            logging.debug(f"Actual generated data size: {final_size_info['kb']:.2f} KB ({final_size_info['bytes']} bytes)")
            return data # 返回列表

        elif data_type == 'unstructured':
             chars_needed = target_bytes
             # 确保 k 是整数
             return ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation + ' ', k=int(chars_needed)))
        else:
            raise ValueError("Unsupported data_type specified")


    @staticmethod
    def stratify_data(data):
        """
        将数据分成三层 L1, L2, L3.
        """
        logging.debug(f"Stratifying data of type: {type(data)}")
        if isinstance(data, list):  # 结构化数据
            if not data:
                logging.warning("Input data list is empty for stratification.")
                return {'L1': [], 'L2': [], 'L3': []}

            l1_fields = ['id', 'name', 'age', 'email']
            # 使用 .get() 获取值，如果键不存在则返回 None，避免 KeyError
            l1_data = [{k: record.get(k) for k in l1_fields} for record in data]

            l2_fields = l1_fields + ['address', 'phone', 'registration_date', 'preferences']
            l2_data = [{k: record.get(k) for k in l2_fields} for record in data]

            l3_data = data # 原始列表作为 L3

            logging.debug(f"Stratification complete: L1({len(l1_data)} records), L2({len(l2_data)} records), L3({len(l3_data)} records)")
            return {'L1': l1_data, 'L2': l2_data, 'L3': l3_data}

        elif isinstance(data, str): # 非结构化数据
            logging.warning("Stratifying unstructured data with simple ratio split (0.2, 0.3, 0.5)")
            total_length = len(data)
            if total_length == 0:
                 logging.warning("Input data string is empty for stratification.")
                 return {'L1': '', 'L2': '', 'L3': ''}
            l1_size = int(total_length * 0.2)
            l2_size = int(total_length * 0.3) # L2 的增量大小
            l2_end_index = l1_size + l2_size
            # 确保索引不越界
            l1_end_index = min(l1_size, total_length)
            l2_end_index = min(l2_end_index, total_length)

            l1_data = data[:l1_end_index]
            # L2 应该包含 L1 的内容，所以是从头开始到 L2 的结束位置
            l2_data = data[:l2_end_index]
            l3_data = data

            logging.debug(f"Stratification complete: L1({len(l1_data)} chars), L2({len(l2_data)} chars), L3({len(l3_data)} chars)")
            return {'L1': l1_data, 'L2': l2_data, 'L3': l3_data}
        else:
            raise TypeError(f"Unsupported data type for stratification: {type(data)}")


    @staticmethod
    def save_data(data, filename):
        """使用 json.dump 保存数据到文件 (或直接写入字符串)"""
        logging.debug(f"Saving data to {filename}")
        directory = os.path.dirname(filename)
        if directory and not os.path.exists(directory):
            try:
                os.makedirs(directory)
                logging.debug(f"Created directory: {directory}")
            except OSError as e:
                logging.error(f"Failed to create directory {directory}: {e}")
                raise

        try:
            with open(filename, 'w', encoding='utf-8') as f:
                if isinstance(data, (dict, list)):
                    # ensure_ascii=False 支持中文等非 ASCII 字符
                    json.dump(data, f, ensure_ascii=False, indent=2)
                elif isinstance(data, str):
                    f.write(data)
                else:
                    # 对于其他类型，尝试转换为字符串保存
                    logging.warning(f"Saving non-standard data type ({type(data)}) as string to {filename}")
                    f.write(str(data))
            logging.debug(f"Data saved successfully to {filename}")
        except Exception as e:
             logging.error(f"Failed to save data to {filename}: {e}")
             raise


    @staticmethod
    def load_data(filename):
        """使用 json.load 从文件加载数据，如果失败则尝试作为文本读取"""
        logging.debug(f"Loading data from {filename}")
        if not os.path.exists(filename):
            raise FileNotFoundError(f"Data file not found: {filename}")
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                # 尝试直接解析 JSON
                content = json.load(f)
                logging.debug(f"Successfully loaded {filename} as JSON.")
                return content # 应该返回 list 或 dict
        except json.JSONDecodeError as json_err:
             logging.warning(f"Failed to decode {filename} as JSON: {json_err}. Attempting to read as text.")
             # 如果 JSON 解析失败，尝试作为普通文本文件读取
             try:
                 with open(filename, 'r', encoding='utf-8') as f:
                     content = f.read()
                     logging.debug(f"Successfully loaded {filename} as text.")
                     return content # 返回字符串
             except Exception as read_err:
                  logging.error(f"Failed to read {filename} as text after JSON decode failed: {read_err}")
                  # 重新抛出原始的 JSON 错误可能更好，表明期望的是 JSON
                  raise ValueError(f"File {filename} is not valid JSON and failed to read as text.") from read_err
        except Exception as e:
            logging.error(f"Failed to load data from {filename}: {e}")
            raise


    @staticmethod
    def analyze_data_size(data):
        """分析数据大小"""
        logging.debug(f"Analyzing size of data type: {type(data)}")
        if isinstance(data, (dict, list)):
            try:
                # 使用紧凑格式计算大小，更接近实际存储
                data_str = json.dumps(data, ensure_ascii=False, separators=(',', ':'))
            except TypeError: # 处理包含无法序列化内容的数据
                 logging.warning("Data contains non-serializable elements, analyzing string representation size.")
                 data_str = str(data)
        else:
            data_str = str(data)

        try:
            size_bytes = len(data_str.encode('utf-8'))
        except Exception as e:
             logging.error(f"Could not encode data to analyze size: {e}")
             return {'bytes': 0, 'kb': 0, 'mb': 0}

        size_kb = size_bytes / 1024
        size_mb = size_kb / 1024
        logging.debug(f"Analyzed size: {size_bytes} bytes, {size_kb:.2f} KB, {size_mb:.4f} MB")
        return {'bytes': size_bytes, 'kb': size_kb, 'mb': size_mb}