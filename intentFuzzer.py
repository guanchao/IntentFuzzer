#coding:utf-8
import argparse
import os
import platform
import re
import subprocess
import sys
import threading
import time
import urllib

from androguard.core.bytecodes import apk

NS_ANDROID_URI = 'http://schemas.android.com/apk/res/android'


def get_permissionname_to_protectionlevel_map( a):
    """
    获取permission对应的protectionLevel标志

    Args:
        a:APK对象

    Returns:
        dict对象，如：{"com.customed.permission", "dangerous", ...}
    """
    dic_mapping = {}
    for i in a.xml:
        for item in a.xml[i].getElementsByTagName("permission"):
            name = item.getAttributeNS(NS_ANDROID_URI, "name")
            protectionLevel = item.getAttributeNS(NS_ANDROID_URI, "protectionLevel")

            if name is not None:
                try:
                    if protectionLevel == "":
                        dic_mapping[name] = get_protectionlevel_tag(0)
                    else:
                        dic_mapping[name] = get_protectionlevel_tag(int(protectionLevel, 16))
                except Exception, e:
                    dic_mapping[name] = get_protectionlevel_tag(0)
    return dic_mapping


def get_protectionlevel_tag( level):
    """
    获取protection level 整数值对应的字符串常量

    Args:
        level: int对象，即protectionLevel值

    Returns:
        string对象
    """
    # ref: https://developer.android.com/reference/android/R.attr.html#protectionLevel
    if level == 0:
        return "normal"
    if level == 1:
        return "dangerous"
    if level == 2:
        return "signature"
    if level == 3:
        return "signatureOrSystem"
    if level == 0x20:
        return "development"
    if level == 0x40:
        return "appop"
    if level == 0x80:
        return "pre23"
    if level == 0x100:
        return "installer"
    if level == 0x200:
        return "verifier"
    if level == 0x400:
        return "preinstalled"

    return str(level)

def isNullOrEmptyString( input_string):
    """
    判断字符串是否为空位为None

    Args:
        input_string:string对象

    Returns:
        boolean值，为空或None，返回True,否则为False
    """
    if input_string is None:
        return True

    if input_string == "":
        return True
    return False

def get_exported_component(a):
    """
    获取apk的导出的组件列表

    Args:
        a:APK对象

    Returns:
        list数组
    """
    permissionname_to_protectionlevel = get_permissionname_to_protectionlevel_map(a)

    list_ready_to_check = []
    find_tags = ["activity", "activity-alias", "service", "receiver"]
    # find_tags = ["activity"]
    xml = a.get_AndroidManifest()
    # Step1:找出要检查的攻击面
    for tag in find_tags:
        for item in xml.getElementsByTagName(tag):
            name = item.getAttribute("android:name")
            exported = item.getAttribute("android:exported")
            permission = item.getAttribute("android:permission")
            has_any_actoins_in_intent_filter = False

            # exported="true"或者exported属性值未设置
            if not isNullOrEmptyString(name) and (exported.lower() != "false"):
                is_ready_to_check = False
                is_launcher = False
                has_any_non_google_actions = False

                # 遍历组件的所有intent-filter的category属性
                for sitem in item.getElementsByTagName("intent-filter"):
                    # 遍历intent-filter的所有category属性，判断是不是入口activity
                    for ssitem in sitem.getElementsByTagName("category"):
                        category_name = ssitem.getAttribute("android:name")
                        if category_name == "android.intent.category.LAUNCHER":
                            is_launcher = True

                    if len(sitem.getElementsByTagName("action")) > 0:
                        has_any_actoins_in_intent_filter = True

                if exported == "":
                    if has_any_actoins_in_intent_filter:
                        is_ready_to_check = True

                if exported.lower() == "true":
                    is_ready_to_check = True

                if is_ready_to_check and (not is_launcher):
                    list_ready_to_check.append((tag, a.format_value(name), exported, permission,
                                                has_any_non_google_actions, has_any_actoins_in_intent_filter))

    # Step2:检测android:permission，判断风险
    list_alert_exposing_components = []
    for item in list_ready_to_check:
        component = item[0]
        exported = item[2]
        permission = item[3]
        has_any_non_google_actions = item[4]
        has_any_actoins_in_intent_filter = item[5]
        is_dangerous = False

        if exported == "":
            if permission == "":
                # 未置permission
                is_dangerous = True
            else:
                # 设置了permission
                if permission in permissionname_to_protectionlevel:
                    protectionLevelTag = permissionname_to_protectionlevel[permission]
                    if (protectionLevelTag == "normal") or (protectionLevelTag == "dangerous"):
                        is_dangerous = True

        if exported.lower() == "true":
            if permission == "":
                # 未置permission
                is_dangerous = True

            else:
                # 设置了permission
                if permission in permissionname_to_protectionlevel:
                    protectionLevelTag = permissionname_to_protectionlevel[permission]
                    if (protectionLevelTag == "normal") or (protectionLevelTag == "dangerous"):
                        is_dangerous = True

        if is_dangerous:
            list_alert_exposing_components.append({"componentType":component,"componentName":item[1]})

    return list_alert_exposing_components

def adb_install(file_name):
    cmd = 'adb install "%s"' % file_name
    subprocess.Popen(cmd, stdout=subprocess.PIPE).stdout.read()

def adb_uninstall(file_name):
    cmd = 'adb uninstall "%s"' % file_name
    subprocess.Popen(cmd, stdout=subprocess.PIPE).stdout.read()

def clear(packageName):
    os.system("adb shell pm clear "+ packageName)
    os.system("adb shell pm clear com.intentfuzzer")

def fuzz(packageName, componentName, componentType, intentType):
    cmd = "adb shell am start -n com.intentfuzzer/com.intentfuzzer.MainActivity -e packageName " + packageName + " -e componentName " + componentName + " -e componentType " + componentType + " -e intentType " + intentType
    subprocess.Popen(cmd, stdout=subprocess.PIPE).stdout.read()

def main():
    if len(sys.argv) < 2:
        print u"[Error] 参数个数错误!"
        return
    file_name = sys.argv[1]
    adb_install(file_name)
    a = apk.APK(file_name)
    packageName = a.get_package()
    exported_component_list = get_exported_component(a)

    clear(packageName)

    for item in exported_component_list:
        componentName = item["componentName"]
        componentType = item["componentType"]
        print "[Info] Testing " + componentName
        fuzz(packageName, componentName, componentType, "serializable")
        time.sleep(15)
        clear(packageName)
        time.sleep(5)

    for item in exported_component_list:
        componentName = item["componentName"]
        componentType = item["componentType"]
        print "[Info] Testing " + componentName
        fuzz(packageName, componentName, componentType, "empty")
        time.sleep(15)
        clear(packageName)
        time.sleep(5)

    adb_uninstall(file_name)
    
if __name__ == '__main__':
    main()
    
