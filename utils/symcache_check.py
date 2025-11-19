from kssymbolic import SymCache
from kssymbolic import Archive
import json
import os
import re
from datetime import datetime
from query_es import query_es
import requests
import zipfile
import time

# symcache = SymCache.open(
#     "/Users/yuencong/workplace/symbolic/symbolic-cabi/com_kwai_gif.11.2.30.setter.symcache"
# )

def symtab_symbols():
    print('start----' + str(datetime.now()))
    fat = Archive.open('/Users/yuencong/Downloads/gif-appstore.app.30.dSYM/com_kwai_gif.app.dSYM/Contents/Resources/DWARF/com_kwai_gif')
    obj = fat.get_object(arch = 'arm64')
    sym_cache = SymCache.from_object(obj, "/Users/yuencong/Downloads/gif-appstore.app.30.dSYM/com_kwai_gif.app.dSYM/Contents/Resources/DWARF/com_kwai_gif")
    sym_cache.lookup("0x43e2068")
    with open('com_kwai_gif.11.2.30.setter.symcache', 'wb') as file_obj :
        sym_cache.dump_into(file_obj)
    print('end----' + str(datetime.now()))

def count():
    # iOS 主站 11.2.30 测试数据
    # symcache functions: 1430011
    # 不做内联展开解析的 json_functions 1225790
    # 内联全部展开解析的 json_functions 3399066
    # c++ std 内联折叠: 2000488
    count = 0
    sum = 1000
    functions_sum = sum
    while functions_sum == sum:
        arr = symcache.get_functions(sum)
        functions_sum = len(arr)
        count += functions_sum;
        print("functions sum: %s" % count)

def check_normal():
    count = 0
    sum = 1000
    functions_sum = sum
    while functions_sum == sum:
        functions = symcache.get_functions(sum)
        for function in functions:
            json_function = json.loads(function)
            symbol = json_function["symbol"]
            full_file_path =json_function["full_file_path"]
            inline_len = len(json.loads(json_function["inline"]))
            if inline_len > 1:
                continue
            if full_file_path == "":
                full_file_path = None
            else:
                full_file_path = os.path.split(full_file_path)[-1]
            line_nums = json.loads(json_function["line_num"])
            for line_info in line_nums:
                addr = (list(line_info.keys())[0])
                line_num = (list(line_info.values())[0])
                rv = symcache.lookup(addr)
                if len(rv) == 0:
                    exit("%s lookup failed: \n%s \n%s" % (addr, rv, json_function))
                if len(rv) > 1:
                    continue
                diff_lookup_rv = rv[0]
                if diff_lookup_rv.full_path != None:
                    diff_lookup_rv.full_path = os.path.split(diff_lookup_rv.full_path)[-1]
                if diff_lookup_rv.symbol != symbol:
                    exit("%s 解析的符号不一致: \n%s \n%s" %(addr, diff_lookup_rv.symbol, symbol))
                if diff_lookup_rv.line != line_num:
                    exit("%s 解析的行号不一致: \n%s \n%s" % (addr, diff_lookup_rv, function))
                if diff_lookup_rv.full_path != full_file_path:
                    exit("%s 解析的路径不一致: \n%s\n%s\n" % (addr, diff_lookup_rv.full_path, full_file_path))
        functions_sum = len(functions)
        count += functions_sum
        print("functions sum: %s" % count)


def check_inline():
    count = 0
    sum = 1000
    functions_sum = sum
    while functions_sum == sum:
        functions = symcache.get_functions(sum)
        for function in functions:
            json_function = json.loads(function)
            symbol = json_function["symbol"]
            full_file_path =json_function["full_file_path"]
            inline = json.loads(json_function["inline"])
            if full_file_path == "":
                full_file_path = None
            else:
                full_file_path = os.path.split(full_file_path)[-1]
            line_nums = json.loads(json_function["line_num"])
            for line_info in line_nums:
                addr = (list(line_info.keys())[0])
                line_num = (list(line_info.values())[0])
                rv = symcache.lookup(addr)
                if len(rv) == 0:
                    exit("%s lookup failed: \n%s \n%s" % (addr, rv, json_function))
                if len(rv) == 1:
                    continue
                if len(inline) == 0:
                    # 存在内联内联都被折叠了，line num 记录的是最上层的 caller
                    diff_lookup_rv = rv[-1]
                    if diff_lookup_rv.full_path != None:
                        diff_lookup_rv.full_path = os.path.split(diff_lookup_rv.full_path)[-1]
                    if diff_lookup_rv.symbol != symbol:
                        exit("%s 解析的符号不一致: \n%s \n%s" %(addr, diff_lookup_rv.symbol, symbol))
                    if diff_lookup_rv.line != line_num:
                        exit("%s 解析的行号不一致: \n%s \n%s" % (addr, diff_lookup_rv, function))
                    if diff_lookup_rv.full_path != full_file_path:
                        exit("%s 解析的路径不一致: \n%s\n%s\n" % (addr, diff_lookup_rv.full_path, full_file_path))
                    # print("addr: %s 内联折叠，校验通过" % addr)
                else:
                    # 校验展开的内联栈
                    for index in range(len(inline) + 1):
                        index += 1
                        diff_lookup_rv = rv[-index]
                        if index == len(inline) + 1:
                            symbol = json_function["symbol"]
                            line = line_num
                            full_file_path = json_function["full_file_path"]
                            if full_file_path == "":
                                full_file_path = None
                        else:
                            inline_rv = inline[-index]
                            symbol = inline_rv["func"]
                            line = inline_rv["line"]
                            full_file_path = inline_rv["file"]
                        if symbol != diff_lookup_rv.symbol:
                            exit("%s 内联解析的符号不一致: \n%s \n%s" %(addr, rv, inline))
                        if line != diff_lookup_rv.line:
                            exit("%s 内联解析的行号不一致: \n%s \n%s" %(addr, rv, function))
                        if full_file_path != os.path.split(diff_lookup_rv.full_path)[-1]:
                            exit("%s 内联解析的文件不一致: \n%s \n%s" %(addr, rv, function))
                    # print("addr: %s 内联展开层级 %s，原始内联层级 %s 校验通过" % (addr, len(inline) + 1, len(rv)))
        functions_sum = len(functions)
        count += functions_sum
        print("functions sum: %s" % count)


def check_dwarf_line():
    with open("/Users/yuencong/workplace/symbolic/11.2.30.txt") as file:
        count = 0
        last_diff_failed = False
        last_line_components = None
        last_lookup_rv = None
        for line in file.readlines():
            line = line.strip()
            if line.startswith("0x0000000"):
                count += 1
                line_components = list(filter( lambda x: x != '', line.split(' ')))
                offset = "0x" + line_components[0][11:]
                if last_diff_failed:
                    last_offset = "0x" + last_line_components[0][11:]
                    if last_offset != offset:
                        print("校验失败 \ndwarf line: %s\n lookup rv: %s \n当前计数: %s" % (last_line_components, last_lookup_rv, count))
                        last_diff_failed = False
                        last_line_components = None
                    else:
                        last_diff_failed = False
                        last_line_components = None
                if 'end_sequence' in line_components or 'is_stmt' not in line_components:
                    continue
                dwarf_line = line_components[1]
                lookup_rv = symcache.lookup(offset)[0]
                if int(dwarf_line) != lookup_rv.line:
                    # 相同的 pc 按照后者解析，这里需要延时失败
                    last_diff_failed = True
                    last_line_components = line_components
                    last_lookup_rv = lookup_rv
        print("校验结束，校验行数: %s" % count) # 8663543


def check_dwarf_filename():
    with open("/Users/yuencong/workplace/symbolic/11.2.30.txt") as file:
        count = 0
        last_diff_failed = False
        last_line_components = None
        last_lookup_rv = None
        index = -1
        files_map = {}
        for line in file.readlines():
            line = line.strip()
            rv = re.compile("file_names\[(.*)\]\:").findall(line)
            if len(rv) > 0:
                index = rv[0]
                continue
            rv = re.compile("name: \"(.*)\"").findall(line)
            if len(rv) > 0:
                if index != -1:
                    files_map[str(index).strip()] = os.path.split(rv[0])[-1]
                    index = -1
                continue

            if line.startswith("0x0000000"):
                count += 1;
                line_components = list(filter( lambda x: x != '', line.split(' ')))
                offset = "0x" + line_components[0][11:]
                if last_diff_failed:
                    last_offset = "0x" + last_line_components[0][11:]
                    if last_offset != offset:
                        print("校验失败 \ndwarf filename: %s\n lookup rv: %s \n当前计数: %s" % (last_line_components, last_lookup_rv, count))
                        last_diff_failed = False
                        last_line_components = None
                    else:
                        last_diff_failed = False
                        last_line_components = None
                if 'end_sequence' in line_components or 'is_stmt' not in line_components:
                    continue
                file_index = line_components[3]
                filename = files_map[str(file_index)]
                lookup_rv = symcache.lookup(offset)[0]
                lookup_rv_filename = None
                if lookup_rv.full_path != None:
                    lookup_rv_filename = os.path.split(lookup_rv.full_path)[-1]
                else:
                    print(lookup_rv)
                if filename != lookup_rv_filename:
                    # 相同的 pc 按照后者解析，这里需要延时失败
                    last_diff_failed = True
                    last_line_components = line_components
                    last_lookup_rv = lookup_rv
        print("校验结束，校验行数: %s" % count) # 8663543

def check_es():
    # 11.2.30
    # print("下载 dsym")
    # response = requests.get("https://multiserver.corp.kuaishou.com/data_multiserver/test/com_kwai_gif/iOS/20230323/441059f9db90ee47fafe6bc25d9d3b82/gif-appstore.app.dSYM.zip")
    # print("下载 dsym 完成")
    # with open("gif-appstore.app.dSYM.zip", 'wb') as file:
    #     file.write(response.content)
    # print("写入本地文件完成")
    # with zipfile.ZipFile("gif-appstore.app.dSYM.zip", 'r') as file:
    #     file.extractall("gif-appstore.app.dSYM")
    # print("解压完成")
    fat = Archive.open('gif-appstore.app.dSYM/com_kwai_gif.app.dSYM/Contents/Resources/DWARF/com_kwai_gif')
    obj = fat.get_object(arch = 'arm64')
    sym_cache = SymCache.from_object(obj, "gif-appstore.app.dSYM/com_kwai_gif.app.dSYM/Contents/Resources/DWARF/com_kwai_gif")
    print("生成 symcache 完成")
    count = 0
    sum = 1000
    functions_sum = sum
    while functions_sum == sum:
        arr = sym_cache.get_functions(sum)
        for function in arr:
            json_function = json.loads(function)
            symbol = json_function["symbol"]
            full_file_path =json_function["full_file_path"]
            inline_len = len(json.loads(json_function["inline"]))
            if inline_len > 1:
                continue
            if full_file_path == "":
                full_file_path = None
            else:
                full_file_path = os.path.split(full_file_path)[-1]
            line_nums = json.loads(json_function["line_num"])
            for line_info in line_nums:
                addr = (list(line_info.keys())[0])
                line_num = (list(line_info.values())[0])
                lookup_rv = sym_cache.lookup(addr)
                if len(lookup_rv) > 1:
                    # 忽略内联
                    continue
                es_rv = query_es("d7af1ee8d7e1322daa02c02ce84d8ee3", addr)
                if es_rv != None:
                    es_symbol = es_rv["symbol"]
                    es_line = es_rv["line_num"]
                    if es_line == "":
                        es_line = "0"
                    es_filename = es_rv["file_name"]
                    if '-' in es_line:
                        # bugly 处理连续相同 pc 使用 range
                        continue
                    if int(es_line) != int(line_num):
                        print("addr: %s\n lookup: %s\n es: %s" % (addr, lookup_rv[0], es_rv));
                time.sleep(0.1)
        functions_sum = len(arr)
        count += functions_sum;
    print("functions sum: %s" % count)

print("开始校验")
# symtab_symbols()
# check_dwarf_line()
# check_dwarf_filename()
# count()
check_es()
