import idc
import idautils
import re
import string
import sark


def get_segment_names(name):
    seg = sark.Segment(name=name)
    for ea, name in idautils.Names():
        if seg.startEA <= ea < seg.endEA:
            yield ea, name

global libcmtIndex
libcmtIndex = 0
def demangle_data_name(ea, name):
    global libcmtIndex
    if re.sub(r"\_*\d.*\_f.*","", name) is not None:
        idc.MakeNameEx(ea, re.sub( r".*LIBCMT.*", "libCMT{}".format(libcmtIndex), name), idc.SN_AUTO)
        libcmtIndex += 1

class RenameUtils:
    def __init__(self):
        self.segmentNames = [
            ".rdata",
            ".rodata",
            ".text",
            ".data",
            ".idata"
        ]

    def get_segment_names(self, name):
        rval = sark.Segment(name=name)
        for ea, name in idautils.Names():
            if rval.startEA <= ea < rval.endEA:
                yield ea, name
    
    def sub_rename(self, sub_pattern, segments = None):
        if segments is None:
            segments = self.segmentNames
        for name in segments:
            segmentData = self.get_segment_names(name)
            for address, name in segmentData:
                idc.MakeNameEx(address, re.sub(sub_pattern, "", name), idc.SN_AUTO)
    
    def delete_by_pattern(self, delete_pattern, segments = None):
        if segments is None:
            segments = self.segmentNames
        for name in segments:
            segmentData = self.get_segment_names(name)
            for address, name in segmentData:
                if re.match(delete_pattern, name):
                    idc.MakeNameEx(address, "", idc.SN_AUTO)
    
    def auto_string_naming(self):
        idaStrings = idautils.Strings()
        for cstring in idaStrings:
            stringValue = idc.GetString(cstring.ea, cstring.length, cstring.type)
            currentName = idc.GetTrueName(cstring.ea)
            if len(stringValue) > 6:
                objFileValues = re.findall(r"[a-zA-Z]+(?=\.obj)", currentName)
                objFile = ""
                idc.MakeComm(cstring.ea, currentName)
                if len(objFileValues) > 0:
                    objFile = objFileValues[0].upper()
                newName = stringValue.title()
                for repl in [x for x in string.punctuation]:
                    newName = newName.replace(repl, "")
                newName = newName.replace(" ", "")
                newName = "s{objFile}{currentName}".format(objFile=objFile, currentName=newName)
                idc.MakeNameEx(cstring.ea, newName, idc.SN_AUTO)

        
gg = r"_*[0-9a-fA-F]+_*common_"