#ifndef CE_NAMESPACE_MARKER
#define CE_NAMESPACE_MARKER 0x484f5354u
#endif

volatile unsigned ce_namespace_marker=CE_NAMESPACE_MARKER;

void* ce_namespace_entry(void* argument) {
    (void)argument;
    ce_namespace_marker=CE_NAMESPACE_MARKER+1;
    return 0;
}
