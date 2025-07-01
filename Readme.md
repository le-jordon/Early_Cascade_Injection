Early Cascade Injection 

fork from 0xNinjaCyclone

updated for windows 11 since offset of g_ShimsEnabled address is different

- updated find_SE_DllLoadedAddress line 145 .mrdata is larger 


- update find_ShimsEnabledAddress 
// g_shimsENabled 443825 pattern is not found in .data for windows 11 and found in .text section 
//g_shimsEnabled -> ntdll.LdrGetFileNameFromLoadAsDataTable+13fd
