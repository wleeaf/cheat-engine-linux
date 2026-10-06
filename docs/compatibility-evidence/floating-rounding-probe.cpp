#include <unistd.h>
#include "scanner/memory_scanner.hpp"
#include "platform/linux/linux_process.hpp"
#include <cstdio>
#include <cmath>
int main() {
 ce::os::LinuxProcessHandle p(getpid()); ce::MemoryScanner scanner(1);
 alignas(8) float number=0.05f;
 ce::ScanConfig c;c.startAddress=reinterpret_cast<uintptr_t>(&number);c.stopAddress=c.startAddress+3;c.alignment=4;
 c.roundingType=1;c.floatDecimals=1;c.floatValue=0.1;
 for(auto type:{ce::ValueType::Float,ce::ValueType::All}) {
  c.valueType=type;auto r=scanner.firstScan(p,c);
  std::printf("rounded type=%d current=%.17g requested=%.17g inside-declared-half-place=%d found=%zu\n",int(type),double(number),c.floatValue,std::abs(double(number)-c.floatValue)<=0.05,r.count());
  std::filesystem::remove_all(r.directory().parent_path());
 }
 number=16777216.0f;c.valueType=ce::ValueType::Float;c.roundingType=2;c.floatValue=16777217;
 auto r=scanner.firstScan(p,c);std::printf("truncated current=%.17g requested=%.17g integral-values-differ=%d found=%zu\n",double(number),c.floatValue,std::trunc(double(number))!=std::trunc(c.floatValue),r.count());
 std::filesystem::remove_all(r.directory().parent_path());
}
