import idc
import idautils
import sark

def get_segment_names(name):
    seg = sark.Segment(name=name)
    for ea, name in idautils.Names():
        if seg.startEA <= ea < seg.endEA:
            yield ea, name

class MapParser:
    def __init__(self):
        self.fileContents = None
        self.actualContent = []
        self.processed = []
    
    def load_map_file(self, file_name):
        self.fileContents = open(file_name).readlines()
        for line in self.fileContents:
            isActualLine = re.match(r"\s[a-fA-F0-9]{4}\:[a-fA-F0-9]{8}\s+\w+\s+[a-fA-F0-9]{8}\s+.*", line)
            if isActualLine is not None:
                self.actualContent.append(isActualLine.group(0))
        for line in self.actualContent:
            self.actualContent[self.actualContent.index(line)] = re.sub(r"[0-9]{4}\:[0-9a-fA-F]{8}\s+", "", line)
        for line in self.actualContent:
            self.actualContent[self.actualContent.index(line)] = re.sub(r"(\s|\s\w)+\w+\.\w+$", "", line)
        for line in self.actualContent:
            self.actualContent[self.actualContent.index(line)] = line.lstrip()
        
        temp = [x.split() for x in self.actualContent]
        self.processed = [(x[0], int(x[1], 16)) for x in temp]
    
    def apply_changes(self):
        for x in self.processed:
            idc.MakeNameEx(x[1], x[0], idc.SN_AUTO)
            idc.MakeFunction(x[1])



            
            
    