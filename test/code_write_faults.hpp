#pragma once
namespace code_write_test {
enum class Fault {None,ShortWrite,DropWrite,AfterMutation,RestoreBlocked,SecondShortWrite,ThirdAfterMutation};
void arm(Fault fault);
void clear();
unsigned triggered();
}
