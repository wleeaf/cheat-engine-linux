/// Stubs for ceserver.c symbols that api.c references.
/// In library mode, the TCP server is not used.
#include <stddef.h>

int recvall(int s, void *buf, int size, int flags) { (void)s; (void)buf; (void)size; (void)flags; return -1; }
int sendall(int s, void *buf, int size, int flags) { (void)s; (void)buf; (void)size; (void)flags; return -1; }
void CheckForAndDispatchCommand(int s) { (void)s; }
__thread char* threadname = NULL;
