//
//  ke_csw_shim.c — definition of the ClearSword shim globals
//
#include "ke_internal.h"
#include "libjailbreak/info.h"

KEShimSystemInfo gSystemInfo = { 0 };

void keOffsetsFillClearswordShim(const KEBuildOffsets *o)
{
    if (!o) return;
    gSystemInfo.kernelStruct.inpcb.socket                    = o->inpcbSocket;
    gSystemInfo.kernelStruct.inpcb.icmp6filt                 = o->inpcbIcmp6filt;
    gSystemInfo.kernelStruct.inpcb.list_next                 = o->inpcbListNext;
    gSystemInfo.kernelStruct.inpcb.pcbinfo                   = o->inpcbPcbinfo;
    gSystemInfo.kernelStruct.inpcbinfo.ipi_zone              = o->inpcbinfoIpiZone;
    gSystemInfo.kernelStruct.kalloc_type_view.kt_zv_zv_name  = o->kallocTypeViewKtZvZvName;
    gSystemInfo.kernelStruct.socket.usecount                 = o->socketSoCount;
    gSystemInfo.kernelStruct.socket.proto                    = o->socketSoProto;
    gSystemInfo.kernelStruct.protosw.input                   = o->protoswPrInput;
    gSystemInfo.kernelConstant.staticBase                    = o->staticBase;
}

