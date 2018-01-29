#Not used, not debbugged, not ran even once
#Use on your own risk, beware errors

import idaapi
import idautils
import idc
import re, itertools


def strip_all(strip_pattern):
    functionAddresses = list(idautils.Functions())
    functionNames = [idc.GetFunctionName(x) for x in functionAddresses]

    stripped_names = [re.sub(strip_pattern, "", x) for x in functionNames]
    zipped = zip(functionAddresses, functionNames, stripped_names)
    

    [MakeNameEx(x[0], x[2], idc.SN_AUTO) for x in zipped]


patterns = {
    "generalDemangle": r"\_*\d.*\_f.*"
}