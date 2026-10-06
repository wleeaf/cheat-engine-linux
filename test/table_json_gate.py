#!/usr/bin/env python3
"""Independent decimal arithmetic checks against actual table load/save paths."""
import argparse
import datetime
from decimal import Decimal
import json
from pathlib import Path
import random
import re
import subprocess
import tempfile


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("build",type=Path)
    parser.add_argument("--report",type=Path,required=True)
    args=parser.parse_args()
    binary=(args.build/"table_json_integration").resolve()
    report={"suite":"table-json-exact-integers-and-unicode","utc":datetime.datetime.now(datetime.timezone.utc).isoformat(),"passed":False,"runs":[]}

    def run(command):
        try:
            result=subprocess.run([str(x) for x in command],text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=25)
        except subprocess.TimeoutExpired as error:
            output=error.stdout or ""
            if isinstance(output,bytes):output=output.decode("utf-8",errors="replace")
            report["runs"].append({"command":[str(x) for x in command],"exitCode":None,"timedOut":True,"output":output})
            raise RuntimeError("Required table JSON command exceeded its deadline") from error
        report["runs"].append({"command":[str(x) for x in command],"exitCode":result.returncode,"output":result.stdout})
        if result.returncode:raise RuntimeError(result.stdout or "table round trip failed")
        return result.stdout

    try:
        if not binary.is_file():raise RuntimeError("Required table_json_integration executable is missing")
        text=run([binary])
        if not re.search(r"^TABLE_JSON_RESULT=PASSED checks=33 failures=0$",text,re.M):raise RuntimeError("Missing or incomplete required table JSON assertions")
        limits=json.loads(run([binary,"--integer-limits"]))
        if any(type(limits[key]) is not int for key in ("pointerBits","sizeBits","offsetBits")) or limits["pointerBits"] not in (32,64) or limits["sizeBits"] not in (32,64) or limits["offsetBits"]!=64:raise RuntimeError("Unexpected executable integer profile")
        report["integerLimits"]=limits
        rng=random.Random(0xCE095)
        maximum=(1<<limits["pointerBits"])-1
        addresses=[0,1,maximum,maximum-1,*[rng.randrange(maximum+1) for _ in range(124)]]

        def token(value,style):
            negative="-" if value<0 else ""
            digits=str(abs(value))
            if value==0:return "0e12345"
            if style==0:return str(value)
            if style==1:return negative+digits+"0000e-4"
            if style==2:return negative+digits[0]+"."+(digits[1:] or "0")+"e"+str(len(digits)-1)
            if style==3:return negative+"0."+digits+"000e"+str(len(digits))
            return negative+digits+".0e0"

        fixtures=[]
        expected=[]
        for index,address in enumerate(addresses):
            offset=[-(1<<63),(1<<63)-1,0,rng.randrange(-(1<<63),1<<63)][index%4]
            size=(1<<limits["sizeBits"])-1 if index==0 else rng.randrange(1<<min(64,limits["sizeBits"]))
            address_token=token(address,index%5);offset_token=token(offset,(index+1)%5);size_token=token(size,(index+2)%5)
            # Decimal is an independent oracle; Python binary floats are not used.
            decoded=[int(Decimal(value)) for value in [address_token,offset_token,size_token]]
            if decoded!=[address,offset,size]:raise RuntimeError("Invalid independent decimal fixture")
            fixtures.append('{"id":'+str(index)+',"addr":'+address_token+',"offsets":['+offset_token+'],"type":"pointer"}')
            expected.append((address,offset,size,size_token))
        structures=["{\"size\":"+item[3]+"}" for item in expected]
        with tempfile.TemporaryDirectory(prefix="ce-table-json-oracle-") as directory:
            source=Path(directory)/"source.json";saved=Path(directory)/"saved.json"
            source.write_text('{"entries":['+','.join(fixtures)+'],"structures":['+','.join(structures)+']}')
            run([binary,"--round-trip",source,saved])
            actual=json.loads(saved.read_text())
            if len(actual["entries"])!=128 or len(actual["structures"])!=128:raise RuntimeError("Incomplete decimal oracle round trip")
            for index,(address,offset,size,_) in enumerate(expected):
                record=actual["entries"][index]
                if record["id"]!=index or int(record["addr"],0)!=address or record["offsets"]!=[offset] or actual["structures"][index]["size"]!=size:
                    raise RuntimeError("Exact integer mismatch in decimal oracle record "+str(index))
        report.update(passed=True,coreChecks=33,decimalRecords=128,decimalIntegerChecks=384)
    except (OSError,ValueError,KeyError,RuntimeError,subprocess.TimeoutExpired) as error:
        report["failure"]=str(error)
    args.report.parent.mkdir(parents=True,exist_ok=True)
    args.report.write_text(json.dumps(report,indent=2)+"\n")
    print("TABLE_JSON_GATE="+("PASSED" if report["passed"] else "FAILED"))
    if not report["passed"]:print(report.get("failure","Unknown failure"))
    return 0 if report["passed"] else 1


if __name__=="__main__":
    raise SystemExit(main())
